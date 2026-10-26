package ldap

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// netbiosResolver looks up (and caches) the NetBIOS name of the domain the
// provider is configured for. Successes are cached for good; a failure is
// cached for netbiosFailureTTL so an unreadable CN=Partitions does not cost
// two searches per DOMAIN\ member.
type netbiosResolver struct {
	mu    sync.Mutex
	names []string
	err   error
	errAt time.Time
}

// Package variables so tests control the clock and window.
var (
	netbiosNow        = time.Now
	netbiosFailureTTL = 60 * time.Second
)

// get returns the NetBIOS name(s) of the domain. The domain root is read from
// the rootDSE (defaultNamingContext), never the configured base_dn, which may
// be an OU.
func (r *netbiosResolver) get(ctx context.Context, client Client, _ string, timeout time.Duration) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names != nil {
		return r.names, nil
	}
	if r.err != nil && netbiosNow().Sub(r.errAt) < netbiosFailureTTL {
		return nil, r.err
	}
	names, err := r.lookup(ctx, client, timeout)
	if err != nil {
		r.err, r.errAt = err, netbiosNow()
		return nil, err
	}
	r.names, r.err = names, nil
	return names, nil
}

func (r *netbiosResolver) lookup(ctx context.Context, client Client, timeout time.Duration) ([]string, error) {

	rootDSE, err := client.Search(ctx, &SearchRequest{
		BaseDN:     "",
		Scope:      ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"configurationNamingContext", "defaultNamingContext"},
		SizeLimit:  1,
		TimeLimit:  timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read rootDSE: %w", err)
	}
	if len(rootDSE.Entries) == 0 || rootDSE.Entries[0].GetAttributeValue("configurationNamingContext") == "" {
		return nil, fmt.Errorf("rootDSE has no configurationNamingContext")
	}
	configNC := rootDSE.Entries[0].GetAttributeValue("configurationNamingContext")
	domainNC := rootDSE.Entries[0].GetAttributeValue("defaultNamingContext")
	if domainNC == "" {
		return nil, fmt.Errorf("rootDSE has no defaultNamingContext")
	}

	result, err := client.Search(ctx, &SearchRequest{
		BaseDN:     "CN=Partitions," + configNC,
		Scope:      ScopeSingleLevel,
		Filter:     fmt.Sprintf("(&(objectClass=crossRef)(nCName=%s)(nETBIOSName=*))", ldap.EscapeFilter(domainNC)),
		Attributes: []string{"nETBIOSName"},
		TimeLimit:  timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to search partitions for NetBIOS name: %w", err)
	}

	var names []string
	for _, e := range result.Entries {
		names = append(names, e.GetAttributeValues("nETBIOSName")...)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no crossRef with nETBIOSName found for %s", domainNC)
	}
	return names, nil
}

// samUsername returns the bare account name from a SAM identifier. A
// DOMAIN\ prefix must name this provider's domain (case-insensitive);
// otherwise the lookup would silently resolve the same account name in the
// wrong domain, so a mismatch is an error. If the NetBIOS name cannot be
// determined (e.g. no read access to CN=Partitions) the prefix is stripped
// as before rather than breaking restricted service accounts.
func (m *MemberNormalizer) samUsername(ctx context.Context, sam string) (string, error) {
	domain, username, found := strings.Cut(sam, "\\")
	if !found {
		return sam, nil
	}

	names, err := m.netbios.get(ctx, m.client, m.baseDN, m.timeout)
	if err != nil {
		tflog.SubsystemWarn(ctx, "ldap", "Could not determine NetBIOS domain name; not validating DOMAIN\\ prefix", map[string]any{
			"identifier": sam,
			"error":      err.Error(),
		})
		return username, nil //nolint:nilerr // deliberate fail-open
	}

	for _, n := range names {
		if strings.EqualFold(n, domain) {
			return username, nil
		}
	}

	// Validation (not not_found) so the mismatch is never read as "missing".
	ldapErr := NewLDAPError("resolve_sam_domain", fmt.Errorf(
		"SAM identifier %q names domain %q but this provider is configured for NetBIOS domain %q",
		sam, domain, strings.Join(names, ", ")))
	ldapErr.Category = ErrorCategoryValidation
	return "", ldapErr
}
