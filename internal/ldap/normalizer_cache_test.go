package ldap

import (
	"context"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func sidFound(t *testing.T) *SearchResult {
	return &SearchResult{Entries: []*ldap.Entry{{
		DN: "CN=John Doe,OU=Users,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", ByteValues: [][]byte{mustGUIDBytes(t, resolvedEntryGUID)}},
		},
	}}}
}

func anySearch(*SearchRequest) bool { return true }

// Each specific resolver must leave a cache entry that serves a repeat lookup
// without another search (Resolve used to re-Put the entry and wipe its indexes).
func TestResolve_CachesByIdentifierType(t *testing.T) {
	tests := []struct {
		name, identifier string
	}{
		{"SID", "S-1-5-21-1-2-3-1001"},
		{"UPN", "jdoe@example.com"},
		{"SAM", "jdoe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &MockClient{}
			c.On("Search", mock.Anything, mock.Anything).Return(sidFound(t), nil)
			n := NewMemberNormalizer(c, "dc=example,dc=com", NewCacheManager())

			first, err := n.Resolve(tt.identifier)
			require.NoError(t, err)
			second, err := n.Resolve(tt.identifier)
			require.NoError(t, err)

			assert.Equal(t, first, second)
			assert.Equal(t, 1, countSearches(c, anySearch))
		})
	}
}

func TestResolve_KeepsSIDIndexAfterResolveByDN(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	c := &MockClient{}
	c.On("Search", mock.Anything, mock.Anything).Return(sidFound(t), nil)
	cm := NewCacheManager()
	n := NewMemberNormalizer(c, "dc=example,dc=com", cm)

	res, err := n.Resolve(sid)
	require.NoError(t, err)
	_, ok := cm.Get(sid)
	require.True(t, ok)

	_, err = n.Resolve(res.DN)
	require.NoError(t, err)
	_, ok = cm.Get(sid)
	assert.True(t, ok, "SID index must survive Resolve")
}

func TestResolveSID_UsesCache(t *testing.T) {
	c := &MockClient{}
	c.On("Search", mock.Anything, mock.Anything).Return(sidFound(t), nil)
	n := NewMemberNormalizer(c, "dc=example,dc=com", NewCacheManager())

	for range 2 {
		res, err := n.ResolveSID("S-1-5-21-1-2-3-513")
		require.NoError(t, err)
		assert.Equal(t, "CN=John Doe,OU=Users,DC=example,DC=com", res.DN)
		assert.Equal(t, resolvedEntryGUID, res.GUID)
	}
	assert.Equal(t, 1, countSearches(c, anySearch))
}

func TestResolveBatch_CancelledContextSkipsSearches(t *testing.T) {
	c := &MockClient{}
	n := NewMemberNormalizer(c, "dc=example,dc=com", NewCacheManager())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n.SetContext(ctx)

	results, failures := n.ResolveBatch([]string{"jdoe", "asmith@example.com", "  ", "S-1-5-21-1-2-3-1001"})

	assert.Empty(t, results)
	assert.Len(t, failures, 3)
	for id, err := range failures {
		assert.ErrorIs(t, err, context.Canceled, id)
	}
	c.AssertNotCalled(t, "Search", mock.Anything, mock.Anything)
}

func TestResolve_DomainPrefixNotServedFromCache(t *testing.T) {
	c := &MockClient{}
	mockNetBIOS(c, "CORP")
	c.On("Search", mock.Anything, mock.MatchedBy(samSearch)).Return(samFound(t), nil)
	n := NewMemberNormalizer(c, "dc=example,dc=com", NewCacheManager())

	_, err := n.Resolve("CORP\\jdoe")
	require.NoError(t, err)

	_, err = n.Resolve("OTHER\\jdoe")
	require.Error(t, err, "OTHER\\jdoe must not resolve to CORP's cached jdoe")
	assert.Equal(t, 1, countSearches(c, samSearch))
}
