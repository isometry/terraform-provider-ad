package ldap

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testConfigNC = "CN=Configuration,DC=example,DC=com"

// mockNetBIOS registers the rootDSE and CN=Partitions searches that resolve
// the domain's NetBIOS name.
func mockNetBIOS(m interface {
	On(string, ...any) *mock.Call
}, name string) {
	m.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "" && req.Scope == ScopeBaseObject
	})).Return(&SearchResult{Entries: []*ldap.Entry{{
		Attributes: []*ldap.EntryAttribute{
			{Name: "configurationNamingContext", Values: []string{testConfigNC}},
			{Name: "defaultNamingContext", Values: []string{"DC=example,DC=com"}},
		},
	}}}, nil)
	m.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "CN=Partitions,"+testConfigNC &&
			strings.EqualFold(req.Filter, "(&(objectClass=crossRef)(nCName=dc=example,dc=com)(nETBIOSName=*))")
	})).Return(&SearchResult{Entries: []*ldap.Entry{{
		Attributes: []*ldap.EntryAttribute{{Name: "nETBIOSName", Values: []string{name}}},
	}}}, nil)
}

func samSearch(req *SearchRequest) bool {
	return req.BaseDN == "dc=example,dc=com" && req.Filter == "(sAMAccountName=jdoe)"
}

func countSearches(c *MockClient, match func(*SearchRequest) bool) int {
	n := 0
	for _, call := range c.Calls {
		if req, ok := call.Arguments.Get(1).(*SearchRequest); ok && call.Method == "Search" && match(req) {
			n++
		}
	}
	return n
}

func samFound(t *testing.T) *SearchResult {
	return &SearchResult{Entries: []*ldap.Entry{{
		DN: "CN=John Doe,OU=Users,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", ByteValues: [][]byte{mustGUIDBytes(t, resolvedEntryGUID)}},
		},
	}}}
}

func TestSAMDomainPrefix_MatchResolvesAnyCase(t *testing.T) {
	for _, sam := range []string{"EXAMPLE\\jdoe", "example\\jdoe", "ExAmPlE\\jdoe", "jdoe"} {
		t.Run(sam, func(t *testing.T) {
			c := &MockClient{}
			mockNetBIOS(c, "EXAMPLE")
			c.On("Search", mock.Anything, mock.MatchedBy(samSearch)).Return(samFound(t), nil)
			n := NewMemberNormalizer(c, "dc=example,dc=com", nil)

			res, err := n.Resolve(sam)

			require.NoError(t, err)
			assert.Equal(t, "CN=John Doe,OU=Users,DC=example,DC=com", res.DN)
		})
	}
}

func TestSAMDomainPrefix_MismatchErrorsWithoutUserSearch(t *testing.T) {
	c := &MockClient{}
	mockNetBIOS(c, "EXAMPLE")
	n := NewMemberNormalizer(c, "dc=example,dc=com", nil)

	_, err := n.Resolve("CHILD\\jdoe")

	require.Error(t, err)
	assert.Contains(t, err.Error(), `SAM identifier "CHILD\\jdoe" names domain "CHILD" but this provider is configured for NetBIOS domain "EXAMPLE"`)
	assert.False(t, IsNotFoundError(err), "wrong-domain prefix must not be classified as not-found")
	assert.Zero(t, countSearches(c, samSearch), "no user search may be issued")
}

func TestSAMDomainPrefix_MismatchErrorsInUserManager(t *testing.T) {
	c := &MockUserClient{}
	mockNetBIOS(c, "EXAMPLE")
	um := NewUserManager(t.Context(), c, "dc=example,dc=com", nil)

	_, err := um.GetUserBySAM("CHILD\\jdoe")

	require.Error(t, err)
	assert.False(t, IsNotFoundError(err))
	c.AssertNumberOfCalls(t, "Search", 2) // rootDSE + partitions only
}

func TestSAMDomainPrefix_LookupFailureFallsBackToStripping(t *testing.T) {
	c := &MockClient{}
	c.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == ""
	})).Return(nil, errors.New("insufficient access"))
	c.On("Search", mock.Anything, mock.MatchedBy(samSearch)).Return(samFound(t), nil)
	n := NewMemberNormalizer(c, "dc=example,dc=com", nil)

	res, err := n.Resolve("CHILD\\jdoe")

	require.NoError(t, err)
	assert.Equal(t, "CN=John Doe,OU=Users,DC=example,DC=com", res.DN)
}

func TestSAMDomainPrefix_NoPrefixNeedsNoLookup(t *testing.T) {
	c := &MockClient{}
	c.On("Search", mock.Anything, mock.MatchedBy(samSearch)).Return(samFound(t), nil)
	n := NewMemberNormalizer(c, "dc=example,dc=com", nil)

	_, err := n.Resolve("jdoe")

	require.NoError(t, err)
	c.AssertNumberOfCalls(t, "Search", 1)
}

// fakeNetBIOSClock makes netbiosNow controllable for the test's duration.
func fakeNetBIOSClock(t *testing.T) *time.Time {
	now := time.Unix(1_000_000, 0)
	orig := netbiosNow
	netbiosNow = func() time.Time { return now }
	t.Cleanup(func() { netbiosNow = orig })
	return &now
}

func TestSAMDomainPrefix_OUBaseDNStillUsesDomainRoot(t *testing.T) {
	c := &MockClient{}
	mockNetBIOS(c, "EXAMPLE")
	c.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool {
		return r.BaseDN == "OU=Corp,DC=example,DC=com" && r.Filter == "(sAMAccountName=jdoe)"
	})).Return(samFound(t), nil)
	n := NewMemberNormalizer(c, "OU=Corp,DC=example,DC=com", nil)

	_, err := n.Resolve("CHILD\\jdoe")

	// If nCName were filtered on the OU the partitions mock would not match
	// and validation would fail open.
	require.Error(t, err)
	assert.Contains(t, err.Error(), `configured for NetBIOS domain "EXAMPLE"`)
}

func TestSAMDomainPrefix_FailureCachedForWindow(t *testing.T) {
	now := fakeNetBIOSClock(t)
	c := &MockClient{}
	c.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool { return r.BaseDN == "" })).
		Return(nil, errors.New("denied"))
	c.On("Search", mock.Anything, mock.MatchedBy(samSearch)).Return(samFound(t), nil)
	n := NewMemberNormalizer(c, "dc=example,dc=com", nil)
	rootDSE := func(r *SearchRequest) bool { return r.BaseDN == "" }

	for range 3 {
		_, err := n.Resolve("X\\jdoe")
		require.NoError(t, err, "fail-open still strips the prefix")
	}
	assert.Equal(t, 1, countSearches(c, rootDSE), "failure cached within the window")

	*now = now.Add(netbiosFailureTTL + time.Second)
	_, _ = n.Resolve("X\\jdoe")
	assert.Equal(t, 2, countSearches(c, rootDSE), "retried after the window")
}

func TestSAMDomainPrefix_FailureThenSuccessIsCachedForGood(t *testing.T) {
	now := fakeNetBIOSClock(t)
	r := &netbiosResolver{}
	bad := &MockClient{}
	bad.On("Search", mock.Anything, mock.Anything).Return(nil, errors.New("denied"))
	_, err := r.get(t.Context(), bad, "", time.Second)
	require.Error(t, err)

	*now = now.Add(netbiosFailureTTL + time.Second)
	good := &MockClient{}
	mockNetBIOS(good, "EXAMPLE")
	names, err := r.get(t.Context(), good, "", time.Second)
	require.NoError(t, err)
	assert.Equal(t, []string{"EXAMPLE"}, names)

	good.Calls = nil
	_, err = r.get(t.Context(), good, "", time.Second)
	require.NoError(t, err)
	good.AssertNotCalled(t, "Search", mock.Anything, mock.Anything)
}

func TestSAMDomainPrefix_LookupCachedOnSuccess(t *testing.T) {
	c := &MockClient{}
	mockNetBIOS(c, "EXAMPLE")
	c.On("Search", mock.Anything, mock.MatchedBy(samSearch)).Return(samFound(t), nil)
	n := NewMemberNormalizer(c, "dc=example,dc=com", nil)

	for _, sam := range []string{"EXAMPLE\\jdoe", "example\\jdoe", "EXAMPLE\\jdoe"} {
		_, err := n.Resolve(sam)
		require.NoError(t, err)
	}

	assert.Equal(t, 1, countSearches(c, func(r *SearchRequest) bool { return r.BaseDN == "" }), "rootDSE read once")
	assert.Equal(t, 1, countSearches(c, func(r *SearchRequest) bool { return r.BaseDN == "CN=Partitions,"+testConfigNC }), "partitions searched once")

}
