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

	// Mock the SID search
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Filter == fmt.Sprintf("(objectSid=%s)", sid)
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

	results, err := normalizer.NormalizeToDNBatch(identifiers)

	require.NoError(t, err)
	assert.Equal(t, expectedResults, results)
	mockClient.AssertExpectations(t)
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

	results, err := normalizer.NormalizeToDNBatch(identifiers)

	require.NoError(t, err)
	assert.Len(t, results, 5)

	// Verify all identifiers were resolved
	for _, identifier := range identifiers {
		assert.Contains(t, results, identifier)
		assert.NotEmpty(t, results[identifier])
	}

	mockClient.AssertExpectations(t)
}
