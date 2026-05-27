package ldap

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockClient implements the Client interface for testing.
type MockClient struct {
	mock.Mock
}

func (m *MockClient) Connect(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockClient) Bind(ctx context.Context, username, password string) error {
	args := m.Called(ctx, username, password)
	return args.Error(0)
}

func (m *MockClient) BindWithConfig(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockClient) Search(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	args := m.Called(ctx, req)
	if result := args.Get(0); result != nil {
		if searchResult, ok := result.(*SearchResult); ok {
			return searchResult, args.Error(1)
		}
	}
	return nil, args.Error(1)
}

func (m *MockClient) Add(ctx context.Context, req *AddRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockClient) Modify(ctx context.Context, req *ModifyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockClient) Delete(ctx context.Context, dn string) error {
	args := m.Called(ctx, dn)
	return args.Error(0)
}

func (m *MockClient) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockClient) Stats() PoolStats {
	args := m.Called()
	if result := args.Get(0); result != nil {
		if stats, ok := result.(PoolStats); ok {
			return stats
		}
	}
	return PoolStats{}
}

func (m *MockClient) SearchWithPaging(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	args := m.Called(ctx, req)
	if result := args.Get(0); result != nil {
		if searchResult, ok := result.(*SearchResult); ok {
			return searchResult, args.Error(1)
		}
	}
	return nil, args.Error(1)
}

func (m *MockClient) GetBaseDN(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *MockClient) WhoAmI(ctx context.Context) (*WhoAmIResult, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, ok := args.Get(0).(*WhoAmIResult)
	if !ok {
		return nil, args.Error(1)
	}
	return result, args.Error(1)
}

func (m *MockClient) GetRootDSE(ctx context.Context) (*RootDSEInfo, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, ok := args.Get(0).(*RootDSEInfo)
	if !ok {
		return nil, args.Error(1)
	}
	return result, args.Error(1)
}

func (m *MockClient) ModifyDN(ctx context.Context, req *ModifyDNRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func TestIdentifierType_String(t *testing.T) {
	tests := []struct {
		idType   IdentifierType
		expected string
	}{
		{IdentifierTypeDN, "DN"},
		{IdentifierTypeGUID, "GUID"},
		{IdentifierTypeSID, "SID"},
		{IdentifierTypeUPN, "UPN"},
		{IdentifierTypeSAM, "SAM"},
		{IdentifierTypeUnknown, "Unknown"},
		{IdentifierType(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.idType.String())
		})
	}
}

func TestMemberNormalizer_DetectIdentifierType(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	tests := []struct {
		name       string
		identifier string
		expected   IdentifierType
	}{
		{
			name:       "DN format",
			identifier: "CN=User,OU=Users,DC=example,DC=com",
			expected:   IdentifierTypeDN,
		},
		{
			name:       "DN format lowercase",
			identifier: "cn=user,ou=users,dc=example,dc=com",
			expected:   IdentifierTypeDN,
		},
		{
			name:       "DN format mixed case",
			identifier: "Cn=User,Ou=Users,Dc=example,Dc=com",
			expected:   IdentifierTypeDN,
		},
		{
			name:       "hyphenated GUID",
			identifier: "12345678-1234-1234-1234-123456789012",
			expected:   IdentifierTypeGUID,
		},
		{
			name:       "compact GUID",
			identifier: "12345678123412341234123456789012",
			expected:   IdentifierTypeGUID,
		},
		{
			name:       "SID format",
			identifier: "S-1-5-21-123456789-123456789-123456789-1001",
			expected:   IdentifierTypeSID,
		},
		{
			name:       "SID well-known",
			identifier: "S-1-5-32-544",
			expected:   IdentifierTypeSID,
		},
		{
			name:       "UPN format",
			identifier: "user@example.com",
			expected:   IdentifierTypeUPN,
		},
		{
			name:       "SAM with domain",
			identifier: "DOMAIN\\username",
			expected:   IdentifierTypeSAM,
		},
		{
			name:       "SAM without domain",
			identifier: "username",
			expected:   IdentifierTypeSAM,
		},
		{
			name:       "empty string",
			identifier: "",
			expected:   IdentifierTypeUnknown,
		},
		{
			name:       "invalid format",
			identifier: "invalid@identifier@format",
			expected:   IdentifierTypeUnknown,
		},
		{
			name:       "whitespace only",
			identifier: "   ",
			expected:   IdentifierTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizer.DetectIdentifierType(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMemberNormalizer_ValidateIdentifier(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	tests := []struct {
		name       string
		identifier string
		wantErr    bool
	}{
		{
			name:       "valid DN",
			identifier: "CN=User,OU=Users,DC=example,DC=com",
			wantErr:    false,
		},
		{
			name:       "valid GUID",
			identifier: "12345678-1234-1234-1234-123456789012",
			wantErr:    false,
		},
		{
			name:       "valid SID",
			identifier: "S-1-5-21-123456789-123456789-123456789-1001",
			wantErr:    false,
		},
		{
			name:       "valid UPN",
			identifier: "user@example.com",
			wantErr:    false,
		},
		{
			name:       "valid SAM",
			identifier: "DOMAIN\\username",
			wantErr:    false,
		},
		{
			name:       "empty string",
			identifier: "",
			wantErr:    true,
		},
		{
			name:       "unknown format",
			identifier: "invalid@identifier@format",
			wantErr:    true,
		},
		{
			name:       "invalid GUID",
			identifier: "invalid@guid@format",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := normalizer.ValidateIdentifier(tt.identifier)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMemberNormalizer_NormalizeToDN_DN(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	dn := "CN=User,OU=Users,DC=example,DC=com"
	canonicalDN := "CN=User,OU=Users,DC=example,DC=com"

	// Mock the DN validation search
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == dn && req.Scope == ScopeBaseObject
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: canonicalDN,
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   "distinguishedName",
						Values: []string{canonicalDN},
					},
				},
			},
		},
		Total: 1,
	}, nil)

	result, err := normalizer.NormalizeToDN(dn)

	require.NoError(t, err)
	assert.Equal(t, canonicalDN, result)
	mockClient.AssertExpectations(t)
}

func TestMemberNormalizer_NormalizeToDN_GUID(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	guid := "12345678-1234-1234-1234-123456789012"
	expectedDN := "CN=User,OU=Users,DC=example,DC=com"

	// Mock the GUID search
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Scope == ScopeWholeSubtree &&
			req.SizeLimit == 1
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: expectedDN,
			},
		},
		Total: 1,
	}, nil)

	result, err := normalizer.NormalizeToDN(guid)

	require.NoError(t, err)
	assert.Equal(t, expectedDN, result)
	mockClient.AssertExpectations(t)
}

func TestMemberNormalizer_NormalizeToDN_SID(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	sid := "S-1-5-21-123456789-123456789-123456789-1001"
	expectedDN := "CN=User,OU=Users,DC=example,DC=com"

	// Mock the SID search - filter now uses binary-encoded SID
	sidHandler := NewSIDHandler()
	expectedFilter, _ := sidHandler.SIDToSearchFilter(sid)
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Filter == expectedFilter
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: expectedDN,
			},
		},
		Total: 1,
	}, nil)

	result, err := normalizer.NormalizeToDN(sid)

	require.NoError(t, err)
	assert.Equal(t, expectedDN, result)
	mockClient.AssertExpectations(t)
}

func TestMemberNormalizer_NormalizeToDN_UPN(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	upn := "user@example.com"
	expectedDN := "CN=User,OU=Users,DC=example,DC=com"

	// Mock the UPN search
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Filter == fmt.Sprintf("(userPrincipalName=%s)", upn)
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: expectedDN,
			},
		},
		Total: 1,
	}, nil)

	result, err := normalizer.NormalizeToDN(upn)

	require.NoError(t, err)
	assert.Equal(t, expectedDN, result)
	mockClient.AssertExpectations(t)
}

func TestMemberNormalizer_NormalizeToDN_SAM(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	tests := []struct {
		name     string
		sam      string
		username string
	}{
		{
			name:     "SAM with domain",
			sam:      "DOMAIN\\username",
			username: "username",
		},
		{
			name:     "SAM without domain",
			sam:      "username",
			username: "username",
		},
	}

	expectedDN := "CN=User,OU=Users,DC=example,DC=com"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the SAM search
			mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return req.BaseDN == "dc=example,dc=com" &&
					req.Filter == fmt.Sprintf("(sAMAccountName=%s)", tt.username)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{
					{
						DN: expectedDN,
					},
				},
				Total: 1,
			}, nil).Once()

			result, err := normalizer.NormalizeToDN(tt.sam)

			require.NoError(t, err)
			assert.Equal(t, expectedDN, result)
		})
	}

	mockClient.AssertExpectations(t)
}

func TestMemberNormalizer_NormalizeToDN_NotFound(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	guid := "12345678-1234-1234-1234-123456789012"

	// Mock the GUID search with no results
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com"
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}, nil)

	result, err := normalizer.NormalizeToDN(guid)

	assert.Error(t, err)
	assert.Empty(t, result)
	assert.Contains(t, err.Error(), "not found")
	mockClient.AssertExpectations(t)
}

func TestMemberNormalizer_NormalizeToDNBatch(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	identifiers := []string{
		"CN=User1,OU=Users,DC=example,DC=com",
		"12345678-1234-1234-1234-123456789012",
		"user2@example.com",
	}

	expectedResults := map[string]string{
		"CN=User1,OU=Users,DC=example,DC=com":  "CN=User1,OU=Users,DC=example,DC=com",
		"12345678-1234-1234-1234-123456789012": "CN=User2,OU=Users,DC=example,DC=com",
		"user2@example.com":                    "CN=User2,OU=Users,DC=example,DC=com",
	}

	// Mock DN validation
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "CN=User1,OU=Users,DC=example,DC=com" && req.Scope == ScopeBaseObject
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{{DN: "CN=User1,OU=Users,DC=example,DC=com"}},
		Total:   1,
	}, nil)

	// Mock GUID search
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" && req.SizeLimit == 1
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{{DN: "CN=User2,OU=Users,DC=example,DC=com"}},
		Total:   1,
	}, nil)

	// Mock UPN search
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Filter == "(userPrincipalName=user2@example.com)"
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{{DN: "CN=User2,OU=Users,DC=example,DC=com"}},
		Total:   1,
	}, nil)

	results, failures := normalizer.NormalizeToDNBatch(identifiers)

	assert.Empty(t, failures, "expected no failures")
	assert.Equal(t, expectedResults, results)
	mockClient.AssertExpectations(t)
}

func TestMemberNormalizer_NormalizeToDNBatch_PartialFailures(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	identifiers := []string{
		"CN=User1,OU=Users,DC=example,DC=com", // Will succeed
		"nonexistent@example.com",             // Will fail
		"CN=User2,OU=Users,DC=example,DC=com", // Will succeed
	}

	// Mock DN validation for User1 - success
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "CN=User1,OU=Users,DC=example,DC=com" && req.Scope == ScopeBaseObject
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{{DN: "CN=User1,OU=Users,DC=example,DC=com"}},
		Total:   1,
	}, nil)

	// Mock DN validation for User2 - success
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "CN=User2,OU=Users,DC=example,DC=com" && req.Scope == ScopeBaseObject
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{{DN: "CN=User2,OU=Users,DC=example,DC=com"}},
		Total:   1,
	}, nil)

	// Mock UPN search for nonexistent - not found
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.Filter == "(userPrincipalName=nonexistent@example.com)"
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}, nil)

	// Mock SAM search for nonexistent - also not found
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.Filter == "(sAMAccountName=nonexistent@example.com)"
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}, nil)

	results, failures := normalizer.NormalizeToDNBatch(identifiers)

	// Should have 2 successful results
	assert.Len(t, results, 2)
	assert.Equal(t, "CN=User1,OU=Users,DC=example,DC=com", results["CN=User1,OU=Users,DC=example,DC=com"])
	assert.Equal(t, "CN=User2,OU=Users,DC=example,DC=com", results["CN=User2,OU=Users,DC=example,DC=com"])

	// Should have 1 failure
	assert.Len(t, failures, 1)
	assert.Contains(t, failures, "nonexistent@example.com")
	assert.Contains(t, failures["nonexistent@example.com"].Error(), "nonexistent@example.com")
}

func TestMemberNormalizer_NormalizeToDNBatch_AllFail(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	identifiers := []string{
		"bad1@example.com",
		"bad2@example.com",
	}

	// Mock searches for bad1 - not found
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.Filter == "(userPrincipalName=bad1@example.com)"
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}, nil)

	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.Filter == "(sAMAccountName=bad1@example.com)"
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}, nil)

	// Mock searches for bad2 - not found
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.Filter == "(userPrincipalName=bad2@example.com)"
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}, nil)

	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.Filter == "(sAMAccountName=bad2@example.com)"
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}, nil)

	results, failures := normalizer.NormalizeToDNBatch(identifiers)

	// Should have no successful results
	assert.Empty(t, results, "expected no successful normalizations")

	// Should have 2 failures
	assert.Len(t, failures, 2)
	assert.Contains(t, failures, "bad1@example.com")
	assert.Contains(t, failures, "bad2@example.com")
}

// TestMemberNormalizer_NormalizeToDNBatch_WhitespacePreservation asserts the
// external contract: result and failure maps are keyed by the caller's
// original identifier (whitespace preserved), while internal cache and LDAP
// lookups use the trimmed value. Empty/whitespace-only entries are skipped.
func TestMemberNormalizer_NormalizeToDNBatch_WhitespacePreservation(t *testing.T) {
	t.Run("padded_DN_success", func(t *testing.T) {
		mockClient := &MockClient{}
		normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

		paddedDN := "  CN=alice,DC=ex,DC=com  "
		canonicalDN := "CN=alice,DC=ex,DC=com"

		// LDAP base-object search uses the trimmed DN.
		mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
			return req.BaseDN == canonicalDN && req.Scope == ScopeBaseObject
		})).Return(&SearchResult{
			Entries: []*ldap.Entry{{
				DN: canonicalDN,
				Attributes: []*ldap.EntryAttribute{
					{Name: "distinguishedName", Values: []string{canonicalDN}},
				},
			}},
			Total: 1,
		}, nil).Once()

		results, failures := normalizer.NormalizeToDNBatch([]string{paddedDN})

		assert.Empty(t, failures, "expected no failures")
		assert.Contains(t, results, paddedDN)
		assert.NotContains(t, results, canonicalDN)
		assert.Equal(t, canonicalDN, results[paddedDN])
		mockClient.AssertExpectations(t)
	})

	t.Run("padded_UPN_success", func(t *testing.T) {
		mockClient := &MockClient{}
		normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

		paddedUPN := "\talice@ex.com\n"
		trimmedUPN := "alice@ex.com"
		canonicalDN := "CN=Alice,OU=Users,DC=ex,DC=com"

		// LDAP UPN search uses the trimmed value.
		mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
			return req.BaseDN == "dc=example,dc=com" &&
				req.Filter == fmt.Sprintf("(userPrincipalName=%s)", trimmedUPN)
		})).Return(&SearchResult{
			Entries: []*ldap.Entry{{DN: canonicalDN}},
			Total:   1,
		}, nil).Once()

		results, failures := normalizer.NormalizeToDNBatch([]string{paddedUPN})

		assert.Empty(t, failures, "expected no failures")
		assert.Contains(t, results, paddedUPN)
		assert.NotContains(t, results, trimmedUPN)
		assert.Equal(t, canonicalDN, results[paddedUPN])
		mockClient.AssertExpectations(t)
	})

	t.Run("padded_unknown_failure", func(t *testing.T) {
		mockClient := &MockClient{}
		normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

		paddedBad := "  bad  "
		trimmedBad := "bad"

		// Trimmed "bad" matches the SAM regex (no @, no whitespace), so the
		// normalizer issues a sAMAccountName search that returns no results.
		mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
			return req.BaseDN == "dc=example,dc=com" &&
				req.Filter == fmt.Sprintf("(sAMAccountName=%s)", trimmedBad)
		})).Return(&SearchResult{
			Entries: []*ldap.Entry{},
			Total:   0,
		}, nil).Once()

		results, failures := normalizer.NormalizeToDNBatch([]string{paddedBad})

		assert.Empty(t, results, "expected no successful normalizations")
		assert.Contains(t, failures, paddedBad)
		assert.NotContains(t, failures, trimmedBad)
		require.NotNil(t, failures[paddedBad])
		mockClient.AssertExpectations(t)
	})

	// Cache lookup keys on the trimmed value but the result map keys on
	// the padded original. UPN is used because the cache's SAM lookup
	// gates on a "DOMAIN\" or "sam:" prefix, which a bare username lacks.
	t.Run("cache_hit_padded_key", func(t *testing.T) {
		mockClient := &MockClient{}
		cacheManager := NewCacheManager()
		normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", cacheManager)

		paddedUPN := "  alice@ex.com  "
		trimmedUPN := "alice@ex.com"
		canonicalDN := "CN=Alice,OU=Users,DC=ex,DC=com"

		// Pre-populate the cache so a Get on the trimmed value succeeds.
		require.NoError(t, cacheManager.Put(&LDAPCacheEntry{
			DN: canonicalDN,
			Attributes: map[string][]string{
				"userPrincipalName": {trimmedUPN},
			},
		}))

		// Sanity-check: the cache really does serve the trimmed key.
		cached, found := cacheManager.Get(trimmedUPN)
		require.True(t, found, "cache must serve the trimmed UPN lookup")
		require.Equal(t, canonicalDN, cached.DN)

		results, failures := normalizer.NormalizeToDNBatch([]string{paddedUPN})

		assert.Empty(t, failures, "expected no failures")
		assert.Contains(t, results, paddedUPN)
		assert.NotContains(t, results, trimmedUPN)
		assert.Equal(t, canonicalDN, results[paddedUPN])
		// Verify no LDAP search was issued (cache served the request).
		mockClient.AssertNotCalled(t, "Search", mock.Anything, mock.Anything)
	})

	t.Run("empty_and_whitespace_skipped", func(t *testing.T) {
		mockClient := &MockClient{}
		normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

		identifiers := []string{"", "   ", "\t\n"}

		results, failures := normalizer.NormalizeToDNBatch(identifiers)

		assert.Empty(t, results, "skipped entries must not appear in results")
		assert.Empty(t, failures, "skipped entries must not appear in failures")
		// Verify no LDAP search was issued for skipped entries.
		mockClient.AssertNotCalled(t, "Search", mock.Anything, mock.Anything)
	})

	// Mirror the resource_group_membership lookup pattern: walk the
	// caller's original slice and index into results/failures by the
	// original string. Mix padded, unpadded and a missing entry.
	t.Run("lookup_by_original_identifier", func(t *testing.T) {
		mockClient := &MockClient{}
		normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

		members := []string{
			"  CN=User1,OU=Users,DC=example,DC=com  ", // padded DN
			"user2@example.com",                       // unpadded UPN
			"  missing  ",                             // padded, not found
		}

		// Padded DN -> base-object search uses the trimmed DN.
		mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
			return req.BaseDN == "CN=User1,OU=Users,DC=example,DC=com" &&
				req.Scope == ScopeBaseObject
		})).Return(&SearchResult{
			Entries: []*ldap.Entry{{
				DN: "CN=User1,OU=Users,DC=example,DC=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "distinguishedName", Values: []string{"CN=User1,OU=Users,DC=example,DC=com"}},
				},
			}},
			Total: 1,
		}, nil).Once()

		// UPN search.
		mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
			return req.Filter == "(userPrincipalName=user2@example.com)"
		})).Return(&SearchResult{
			Entries: []*ldap.Entry{{DN: "CN=User2,OU=Users,DC=example,DC=com"}},
			Total:   1,
		}, nil).Once()

		// "missing" -> SAM search returns nothing.
		mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
			return req.Filter == "(sAMAccountName=missing)"
		})).Return(&SearchResult{
			Entries: []*ldap.Entry{},
			Total:   0,
		}, nil).Once()

		results, failures := normalizer.NormalizeToDNBatch(members)

		var found, missing []string
		for _, member := range members {
			if dn, ok := results[member]; ok {
				found = append(found, dn)
				continue
			}
			if _, ok := failures[member]; ok {
				missing = append(missing, member)
			}
		}

		assert.Len(t, found, 2, "padded DN and unpadded UPN must round-trip")
		assert.Equal(t, []string{
			"CN=User1,OU=Users,DC=example,DC=com",
			"CN=User2,OU=Users,DC=example,DC=com",
		}, found)
		assert.Equal(t, []string{"  missing  "}, missing,
			"failure must be reported under the caller's padded key")
		mockClient.AssertExpectations(t)
	})
}

func TestMemberNormalizer_GetSupportedFormats(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	formats := normalizer.GetSupportedFormats()

	assert.Len(t, formats, 5)
	assert.Contains(t, formats, "Distinguished Name (DN): CN=User,OU=Users,DC=example,DC=com")
	assert.Contains(t, formats, "GUID: 12345678-1234-1234-1234-123456789012")
	assert.Contains(t, formats, "Security Identifier (SID): S-1-5-21-123456789-123456789-123456789-1001")
	assert.Contains(t, formats, "User Principal Name (UPN): user@example.com")
	assert.Contains(t, formats, "SAM Account Name: DOMAIN\\username or username")
}

func TestMemberNormalizer_SetBaseDN(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	assert.Equal(t, "dc=example,dc=com", normalizer.GetBaseDN())

	newBaseDN := "dc=test,dc=org"
	normalizer.SetBaseDN(newBaseDN)

	assert.Equal(t, newBaseDN, normalizer.GetBaseDN())
}

func TestMemberNormalizer_ErrorHandling(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	tests := []struct {
		name       string
		identifier string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "empty identifier",
			identifier: "",
			wantErr:    true,
			errMsg:     "identifier cannot be empty",
		},
		{
			name:       "whitespace only identifier",
			identifier: "   ",
			wantErr:    true,
			errMsg:     "unable to determine identifier type",
		},
		{
			name:       "unknown format",
			identifier: "invalid@format@test",
			wantErr:    true,
			errMsg:     "unable to determine identifier type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := normalizer.NormalizeToDN(tt.identifier)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, result)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Benchmark tests for performance validation.
func BenchmarkMemberNormalizer_DetectIdentifierType(b *testing.B) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	identifiers := []string{
		"CN=User,OU=Users,DC=example,DC=com",
		"12345678-1234-1234-1234-123456789012",
		"S-1-5-21-123456789-123456789-123456789-1001",
		"user@example.com",
		"DOMAIN\\username",
	}

	for b.Loop() {
		for _, identifier := range identifiers {
			normalizer.DetectIdentifierType(identifier)
		}
	}
}

func TestMemberNormalizer_SearchErrors(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	guid := "12345678-1234-1234-1234-123456789012"

	// Mock search failure
	mockClient.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).
		Return((*SearchResult)(nil), fmt.Errorf("connection failed"))

	result, err := normalizer.NormalizeToDN(guid)

	assert.Error(t, err)
	assert.Empty(t, result)
	assert.Contains(t, err.Error(), "failed to normalize identifier")
	mockClient.AssertExpectations(t)
}

func TestMemberNormalizer_IntegrationScenarios(t *testing.T) {
	mockClient := &MockClient{}
	normalizer := NewMemberNormalizer(mockClient, "dc=example,dc=com", nil)

	// Test mixed batch with different identifier types
	identifiers := []string{
		"CN=Admin,CN=Users,DC=example,DC=com",
		"12345678-1234-1234-1234-123456789012",
		"S-1-5-21-123456789-123456789-123456789-500",
		"admin@example.com",
		"EXAMPLE\\service-account",
	}

	// Mock all the necessary searches
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "CN=Admin,CN=Users,DC=example,DC=com"
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{{DN: "CN=Admin,CN=Users,DC=example,DC=com"}},
		Total:   1,
	}, nil)

	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.SizeLimit == 1 // GUID search
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{{DN: "CN=User,OU=Users,DC=example,DC=com"}},
		Total:   1,
	}, nil)

	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return strings.Contains(req.Filter, "objectSid")
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{{DN: "CN=Administrator,CN=Users,DC=example,DC=com"}},
		Total:   1,
	}, nil)

	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return strings.Contains(req.Filter, "userPrincipalName")
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{{DN: "CN=Admin User,OU=Users,DC=example,DC=com"}},
		Total:   1,
	}, nil)

	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return strings.Contains(req.Filter, "sAMAccountName")
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{{DN: "CN=Service Account,OU=Service,DC=example,DC=com"}},
		Total:   1,
	}, nil)

	results, failures := normalizer.NormalizeToDNBatch(identifiers)

	assert.Empty(t, failures, "expected no failures")
	assert.Len(t, results, 5)

	// Verify all identifiers were resolved
	for _, identifier := range identifiers {
		assert.Contains(t, results, identifier)
		assert.NotEmpty(t, results[identifier])
	}

	mockClient.AssertExpectations(t)
}
