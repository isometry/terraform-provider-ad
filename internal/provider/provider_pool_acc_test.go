package provider_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// TestAccLDAPPool_maxConnectionsHardCap checks, at client level and read-only,
// that max_connections is a hard cap: 20 goroutines issuing paged subtree
// searches through a pool limited to 2 must all succeed without dialling more
// than 2 connections. Expect a few seconds.
func TestAccLDAPPool_maxConnectionsHardCap(t *testing.T) {
	SkipIfNotAccTest(t)
	testAccPreCheck(t)

	const (
		maxConns = 2
		workers  = 20
		searches = 3
		// Created is the cumulative dial count and the robust assertion: with
		// the old idle-only cap it equalled roughly the number of concurrent
		// goroutines. Allow one re-dial (e.g. a connection dropped by the DC).
		redialSlack = 1
	)

	ctx := context.Background()
	tc := GetTestConfig()
	cfg := newTestLDAPConfig(tc)
	cfg.MaxConnections = maxConns
	cfg.Timeout = 30 * time.Second
	client, err := ldapclient.NewClient(ctx, cfg)
	if err != nil {
		t.Fatalf("creating LDAP client: %v", err)
	}
	defer client.Close() //nolint:errcheck

	var (
		mu         sync.Mutex
		searchErrs []error
		wg         sync.WaitGroup
		done       = make(chan struct{})
		peakActive atomic.Int64
	)

	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			if a := client.Stats().Active; a > peakActive.Load() {
				peakActive.Store(a)
			}
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	}()

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range searches {
				_, err := client.SearchWithPaging(ctx, &ldapclient.SearchRequest{
					BaseDN:     tc.BaseDN,
					Scope:      ldapclient.ScopeWholeSubtree,
					Filter:     "(objectClass=*)",
					Attributes: []string{"distinguishedName"},
				})
				if err != nil {
					mu.Lock()
					searchErrs = append(searchErrs, err)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	close(done)
	<-samplerDone

	for _, err := range searchErrs {
		t.Errorf("search failed: %v", err)
	}

	stats := client.Stats()
	if stats.Created > maxConns+redialSlack {
		t.Errorf("pool dialled %d connections, want <= %d", stats.Created, maxConns+redialSlack)
	}
	// Active is incremented only after a semaphore token is taken, so it cannot
	// exceed the cap: it shows contention happened, it cannot prove a breach.
	if peak := peakActive.Load(); peak < 1 || peak > maxConns {
		t.Errorf("sampled peak Active = %d, want within [1, %d]", peak, maxConns)
	}
	if stats.Active != 0 {
		t.Errorf("Active = %d after run, want 0", stats.Active)
	}
	if stats.Idle > maxConns {
		t.Errorf("Idle = %d after run, want <= %d", stats.Idle, maxConns)
	}
}

// TestAccProvider_maxConnectionsContention applies 20 groups through a provider
// with max_connections = 1. With Terraform's default parallelism of 10 and a
// single pooled connection, ten operations contend. This proves queueing
// completes without "timed out waiting for a free connection", not that the cap
// is enforced (see TestAccLDAPPool_maxConnectionsHardCap). Expect 20-40 s.
func TestAccProvider_maxConnectionsContention(t *testing.T) {
	SkipIfNotAccTest(t)
	testAccPreCheck(t)

	base := testProviderConfig()
	providerCfg := strings.Replace(base, "provider \"ad\" {\n",
		"provider \"ad\" {\n  max_connections = 1\n  connect_timeout = 10\n", 1)
	if providerCfg == base {
		t.Fatal("provider block replacement did not change the provider configuration")
	}

	ouName := GenerateTestName("tf-test-ou-pool-")
	uniq := GenerateTestName("")
	suffix := uniq[len(uniq)-5:] // random hex, unique per run
	prefix := "tf-pool-" + suffix

	cfg := fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_ou" "parent" {
  name = %[3]q
  path = data.ad_rootdse.test.default_naming_context
}

resource "ad_group" "p" {
  count            = 20
  name             = format("%%s-%%02d", %[4]q, count.index)
  sam_account_name = format("tfp%%s%%02d", %[5]q, count.index)
  container        = ad_ou.parent.dn
}
`, providerCfg, testRootDSEDataSource(), ouName, prefix, suffix)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckGroupDestroy(context.Background(), s)
		},
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ad_group.p.0", "id"),
					resource.TestCheckResourceAttrSet("ad_group.p.19", "id"),
				),
			},
			{Config: cfg, PlanOnly: true},
		},
	})
}
