package provider_test

import (
	"context"
	"fmt"
	"log"
	"sync"
	"testing"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// setupLargeGroupFixture creates a dedicated OU holding n disabled, password-less
// users through the LDAP client, and registers best-effort cleanup. It returns
// the OU DN and the user DNs.
func setupLargeGroupFixture(t *testing.T, ouName string, n int) (string, []string) {
	t.Helper()
	// Not t.Context(): it is cancelled before t.Cleanup runs, which would fail every cleanup delete.
	ctx := context.Background()
	cfg := GetTestConfig()

	client, err := ldapclient.NewClient(ctx, newTestLDAPConfig(cfg))
	if err != nil {
		t.Fatalf("creating LDAP client: %v", err)
	}
	om := ldapclient.NewOUManager(ctx, client, cfg.BaseDN)
	um := ldapclient.NewUserManager(ctx, client, cfg.BaseDN, ldapclient.NewCacheManager())

	ou, err := om.CreateOU(&ldapclient.CreateOURequest{Name: ouName, ParentDN: cfg.BaseDN})
	if err != nil {
		_ = client.Close()
		t.Fatalf("creating OU: %v", err)
	}

	var mu sync.Mutex
	guids := make([]string, 0, n)
	dns := make([]string, 0, n)
	// Registered before user creation so partial failures are still cleaned up.
	t.Cleanup(func() {
		defer client.Close() //nolint:errcheck
		var wg sync.WaitGroup
		sem := make(chan struct{}, 10)
		for _, g := range guids {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if err := um.DeleteUser(g); err != nil {
					log.Printf("cleanup: deleting user %s: %v", g, err)
				}
			}()
		}
		wg.Wait()
		if err := om.DeleteOU(ou.ObjectGUID); err != nil {
			log.Printf("cleanup: deleting OU %s: %v", ou.DistinguishedName, err)
		}
	})

	disabled := false
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			sam := fmt.Sprintf("tflg%04d%s", i, ouName[len(ouName)-6:])
			u, err := um.CreateUser(&ldapclient.CreateUserRequest{
				Name:              sam,
				SAMAccountName:    sam,
				UserPrincipalName: sam + "@" + cfg.Domain,
				Container:         ou.DistinguishedName,
				Enabled:           &disabled,
			})
			if err != nil {
				errs <- fmt.Errorf("creating user %s: %w", sam, err)
				return
			}
			mu.Lock()
			guids = append(guids, u.ObjectGUID)
			dns = append(dns, u.DistinguishedName)
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		t.Fatalf("creating fixture users: %v", err)
	}
	return ou.DistinguishedName, dns
}

// createLargeGroupOutOfBand creates a global security group in ouDN through the
// LDAP client and adds memberDNs to it (batched by AddGroupMembers). Cleanup
// deletes the group; being registered after the fixture it runs before the
// fixture's user and OU cleanups.
func createLargeGroupOutOfBand(t *testing.T, ouDN string, memberDNs []string) (name, sam, dn, guid string) {
	t.Helper()
	ctx := context.Background() // not t.Context(): cancelled before cleanups run
	cfg := GetTestConfig()

	client, err := ldapclient.NewClient(ctx, newTestLDAPConfig(cfg))
	if err != nil {
		t.Fatalf("creating LDAP client: %v", err)
	}
	cache := ldapclient.NewCacheManager()
	gm := ldapclient.NewGroupManager(ctx, client, cfg.BaseDN, cache)

	name = GenerateTestName("tf-lg-grp-")
	sam = GenerateTestSAMName("tflgg")
	group, err := gm.CreateGroup(&ldapclient.CreateGroupRequest{
		Name:           name,
		SAMAccountName: sam,
		Container:      ouDN,
		Scope:          ldapclient.GroupScopeGlobal,
		Category:       ldapclient.GroupCategorySecurity,
	})
	if err != nil {
		_ = client.Close()
		t.Fatalf("creating group: %v", err)
	}
	t.Cleanup(func() {
		defer client.Close() //nolint:errcheck
		if err := gm.DeleteGroup(group.ObjectGUID); err != nil {
			log.Printf("cleanup: deleting group %s: %v", group.DistinguishedName, err)
		}
	})

	gmm := ldapclient.NewGroupMembershipManager(ctx, client, cfg.BaseDN, cache)
	if err := gmm.AddGroupMembers(group.ObjectGUID, memberDNs, nil); err != nil {
		t.Fatalf("adding %d members: %v", len(memberDNs), err)
	}
	return name, sam, group.DistinguishedName, group.ObjectGUID
}
