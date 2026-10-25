package ldap

import (
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGetBaseDN_ConfiguredBaseSkipsRootDSE(t *testing.T) {
	ops := &mockLDAPOps{} // any Search call panics: no expectation registered
	swapConnOps(t, ops)
	cfg := DefaultConfig()
	cfg.BaseDN = "OU=Corp,DC=example,DC=com"

	got, err := newTestClient(&mockPool{}, cfg).GetBaseDN(t.Context())

	require.NoError(t, err)
	assert.Equal(t, "OU=Corp,DC=example,DC=com", got)
	ops.AssertNotCalled(t, "Search", mock.Anything)
}

func TestGetBaseDN_ReadsRootDSEWhenUnset(t *testing.T) {
	pool := &mockPool{}
	pool.On("Get", mock.Anything).Return(&PooledConnection{healthy: true}, nil)
	ops := &mockLDAPOps{}
	ops.On("Search", mock.MatchedBy(func(r *ldap.SearchRequest) bool { return r.BaseDN == "" })).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{{
			Attributes: []*ldap.EntryAttribute{{Name: "defaultNamingContext", Values: []string{"DC=example,DC=com"}}},
		}}}, nil)
	swapConnOps(t, ops)

	got, err := newTestClient(pool, nil).GetBaseDN(t.Context())

	require.NoError(t, err)
	assert.Equal(t, "DC=example,DC=com", got)
	ops.AssertNumberOfCalls(t, "Search", 1)
}

// neverEndingPages returns pages whose paging cookie is never empty.
func neverEndingPages(t *testing.T) *mockPool {
	pool := &mockPool{}
	pool.On("Get", mock.Anything).Return(&PooledConnection{healthy: true}, nil)
	ops := &mockLDAPOps{}
	ops.On("Search", mock.Anything).Return(func() *ldap.SearchResult {
		pc := ldap.NewControlPaging(1000)
		pc.SetCookie([]byte("more"))
		return &ldap.SearchResult{
			Entries:  []*ldap.Entry{{DN: "CN=a,DC=example,DC=com"}},
			Controls: []ldap.Control{pc},
		}
	}(), nil)
	swapConnOps(t, ops)
	return pool
}

func TestSearchWithPaging_PageCapReturnsErrSearchTruncated(t *testing.T) {
	orig := maxPagesPerSearch
	maxPagesPerSearch = 3
	t.Cleanup(func() { maxPagesPerSearch = orig })
	pool := neverEndingPages(t)

	res, err := newTestClient(pool, nil).SearchWithPaging(t.Context(),
		&SearchRequest{BaseDN: "dc=example,dc=com", Filter: "(objectClass=*)", Scope: ScopeWholeSubtree})

	require.ErrorIs(t, err, ErrSearchTruncated)
	require.NotNil(t, res)
	assert.True(t, res.HasMore)
	assert.Len(t, res.Entries, 4) // pages 1..cap+1 run before the cap check trips
}

func TestSearchWithPaging_DurationCapReturnsErrSearchTruncated(t *testing.T) {
	orig := maxSearchDuration
	maxSearchDuration = -1 // already exceeded
	t.Cleanup(func() { maxSearchDuration = orig })
	pool := neverEndingPages(t)

	res, err := newTestClient(pool, nil).SearchWithPaging(t.Context(),
		&SearchRequest{BaseDN: "dc=example,dc=com", Filter: "(objectClass=*)", Scope: ScopeWholeSubtree})

	require.ErrorIs(t, err, ErrSearchTruncated)
	require.NotNil(t, res)
	assert.True(t, res.HasMore)
}

func TestWarmCache_TruncatedSearchKeepsPartialResults(t *testing.T) {
	c := &MockClient{}
	c.On("GetBaseDN", mock.Anything).Return("DC=example,DC=com", nil)
	c.On("SearchWithPaging", mock.Anything, mock.Anything).Return(
		&SearchResult{Entries: []*ldap.Entry{{
			DN:         "CN=John Doe,OU=Users,DC=example,DC=com",
			Attributes: []*ldap.EntryAttribute{{Name: "objectGUID", Values: []string{resolvedEntryGUID}}},
		}}, HasMore: true},
		fmt.Errorf("%w: exceeded maximum of 3 pages", ErrSearchTruncated))
	cm := NewCacheManager()

	err := cm.WarmCache(t.Context(), c, "")

	require.NoError(t, err)
	assert.EqualValues(t, 1, cm.GetStats().Entries)
}

func TestWarmCache_OtherSearchErrorStillFails(t *testing.T) {
	c := &MockClient{}
	c.On("SearchWithPaging", mock.Anything, mock.Anything).Return(nil, assert.AnError)

	require.Error(t, NewCacheManager().WarmCache(t.Context(), c, "DC=example,DC=com"))
}
