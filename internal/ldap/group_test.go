package ldap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockGroupClient implements the Client interface for testing group operations.
type MockGroupClient struct {
	mock.Mock
}

func (m *MockGroupClient) Connect(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockGroupClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockGroupClient) Bind(ctx context.Context, username, password string) error {
	args := m.Called(ctx, username, password)
	return args.Error(0)
}

func (m *MockGroupClient) BindWithConfig(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockGroupClient) Search(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	args := m.Called(ctx, req)
	if result := args.Get(0); result != nil {
		if searchResult, ok := result.(*SearchResult); ok {
			return searchResult, args.Error(1)
		}
	}
	return nil, args.Error(1)
}

func (m *MockGroupClient) Add(ctx context.Context, req *AddRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockGroupClient) Modify(ctx context.Context, req *ModifyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockGroupClient) ModifyDN(ctx context.Context, req *ModifyDNRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockGroupClient) Delete(ctx context.Context, dn string) error {
	args := m.Called(ctx, dn)
	return args.Error(0)
}

func (m *MockGroupClient) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockGroupClient) Stats() PoolStats {
	args := m.Called()
	if result := args.Get(0); result != nil {
		if stats, ok := result.(PoolStats); ok {
			return stats
		}
	}
	return PoolStats{}
}

func (m *MockGroupClient) SearchWithPaging(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	args := m.Called(ctx, req)
	if result := args.Get(0); result != nil {
		if searchResult, ok := result.(*SearchResult); ok {
			return searchResult, args.Error(1)
		}
	}
	return nil, args.Error(1)
}

func (m *MockGroupClient) GetBaseDN(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *MockGroupClient) WhoAmI(ctx context.Context) (*WhoAmIResult, error) {
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

// Helper function to create a mock LDAP entry for a group.
func createMockGroupEntry(name, guid, dn string, groupType int32) *ldap.Entry {
	guidHandler := NewGUIDHandler()
	guidBytes, _ := guidHandler.StringToGUIDBytes(guid)

	entry := &ldap.Entry{
		DN: dn,
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", ByteValues: [][]byte{guidBytes}},
			{Name: "distinguishedName", Values: []string{dn}},
			{Name: "cn", Values: []string{name}},
			{Name: "sAMAccountName", Values: []string{name}},
			{Name: "groupType", Values: []string{strconv.FormatInt(int64(groupType), 10)}},
			{Name: "description", Values: []string{fmt.Sprintf("Test group %s", name)}},
			{Name: "whenCreated", Values: []string{"20240101120000.0Z"}},
			{Name: "whenChanged", Values: []string{"20240101120000.0Z"}},
		},
	}

	return entry
}

// Helper function to create a test GroupManager with mock client.
func createTestGroupManager(t *testing.T) (*GroupManager, *MockGroupClient) {
	mockClient := &MockGroupClient{}
	baseDN := "DC=test,DC=local"
	gm := NewGroupManager(t.Context(), mockClient, baseDN, nil)
	return gm, mockClient
}

func TestCalculateGroupType(t *testing.T) {
	tests := []struct {
		name         string
		scope        GroupScope
		category     GroupCategory
		expectedType int32
	}{
		{
			name:         "Global Security",
			scope:        GroupScopeGlobal,
			category:     GroupCategorySecurity,
			expectedType: GroupTypeFlagGlobal | GroupTypeFlagSecurity,
		},
		{
			name:         "Global Distribution",
			scope:        GroupScopeGlobal,
			category:     GroupCategoryDistribution,
			expectedType: GroupTypeFlagGlobal,
		},
		{
			name:         "Universal Security",
			scope:        GroupScopeUniversal,
			category:     GroupCategorySecurity,
			expectedType: GroupTypeFlagUniversal | GroupTypeFlagSecurity,
		},
		{
			name:         "Universal Distribution",
			scope:        GroupScopeUniversal,
			category:     GroupCategoryDistribution,
			expectedType: GroupTypeFlagUniversal,
		},
		{
			name:         "Domain Local Security",
			scope:        GroupScopeDomainLocal,
			category:     GroupCategorySecurity,
			expectedType: GroupTypeFlagDomainLocal | GroupTypeFlagSecurity,
		},
		{
			name:         "Domain Local Distribution",
			scope:        GroupScopeDomainLocal,
			category:     GroupCategoryDistribution,
			expectedType: GroupTypeFlagDomainLocal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateGroupType(tt.scope, tt.category)
			assert.Equal(t, tt.expectedType, result, "Group type calculation mismatch")
		})
	}
}

func TestParseGroupType(t *testing.T) {
	tests := []struct {
		name             string
		groupType        int32
		expectedScope    GroupScope
		expectedCategory GroupCategory
	}{
		{
			name:             "Global Security",
			groupType:        GroupTypeFlagGlobal | GroupTypeFlagSecurity,
			expectedScope:    GroupScopeGlobal,
			expectedCategory: GroupCategorySecurity,
		},
		{
			name:             "Global Distribution",
			groupType:        GroupTypeFlagGlobal,
			expectedScope:    GroupScopeGlobal,
			expectedCategory: GroupCategoryDistribution,
		},
		{
			name:             "Universal Security",
			groupType:        GroupTypeFlagUniversal | GroupTypeFlagSecurity,
			expectedScope:    GroupScopeUniversal,
			expectedCategory: GroupCategorySecurity,
		},
		{
			name:             "Domain Local Distribution",
			groupType:        GroupTypeFlagDomainLocal,
			expectedScope:    GroupScopeDomainLocal,
			expectedCategory: GroupCategoryDistribution,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, category := ParseGroupType(tt.groupType)
			assert.Equal(t, tt.expectedScope, scope, "Scope parsing mismatch")
			assert.Equal(t, tt.expectedCategory, category, "Category parsing mismatch")
		})
	}
}

func TestNormalizeGroupScope(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedScope GroupScope
		expectError   bool
	}{
		{
			name:          "Global - exact case",
			input:         "Global",
			expectedScope: GroupScopeGlobal,
			expectError:   false,
		},
		{
			name:          "Global - lowercase",
			input:         "global",
			expectedScope: GroupScopeGlobal,
			expectError:   false,
		},
		{
			name:          "Global - uppercase",
			input:         "GLOBAL",
			expectedScope: GroupScopeGlobal,
			expectError:   false,
		},
		{
			name:          "Global - mixed case",
			input:         "gLoBaL",
			expectedScope: GroupScopeGlobal,
			expectError:   false,
		},
		{
			name:          "Global - with whitespace",
			input:         "  Global  ",
			expectedScope: GroupScopeGlobal,
			expectError:   false,
		},
		{
			name:          "Universal - exact case",
			input:         "Universal",
			expectedScope: GroupScopeUniversal,
			expectError:   false,
		},
		{
			name:          "Universal - lowercase",
			input:         "universal",
			expectedScope: GroupScopeUniversal,
			expectError:   false,
		},
		{
			name:          "Universal - uppercase",
			input:         "UNIVERSAL",
			expectedScope: GroupScopeUniversal,
			expectError:   false,
		},
		{
			name:          "DomainLocal - exact case",
			input:         "DomainLocal",
			expectedScope: GroupScopeDomainLocal,
			expectError:   false,
		},
		{
			name:          "DomainLocal - lowercase",
			input:         "domainlocal",
			expectedScope: GroupScopeDomainLocal,
			expectError:   false,
		},
		{
			name:          "DomainLocal - uppercase",
			input:         "DOMAINLOCAL",
			expectedScope: GroupScopeDomainLocal,
			expectError:   false,
		},
		{
			name:          "DomainLocal - mixed case",
			input:         "DoMaInLoCaL",
			expectedScope: GroupScopeDomainLocal,
			expectError:   false,
		},
		{
			name:        "Invalid scope",
			input:       "Invalid",
			expectError: true,
		},
		{
			name:        "Empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "Whitespace only",
			input:       "   ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeGroupScope(tt.input)

			if tt.expectError {
				assert.Error(t, err, "Expected an error for input: %s", tt.input)
				assert.Empty(t, result, "Expected empty result for invalid input")
			} else {
				assert.NoError(t, err, "Unexpected error for input: %s", tt.input)
				assert.Equal(t, tt.expectedScope, result, "Scope normalization mismatch")
			}
		})
	}
}

func TestNormalizeGroupCategory(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedCategory GroupCategory
		expectError      bool
	}{
		{
			name:             "Security - exact case",
			input:            "Security",
			expectedCategory: GroupCategorySecurity,
			expectError:      false,
		},
		{
			name:             "Security - lowercase",
			input:            "security",
			expectedCategory: GroupCategorySecurity,
			expectError:      false,
		},
		{
			name:             "Security - uppercase",
			input:            "SECURITY",
			expectedCategory: GroupCategorySecurity,
			expectError:      false,
		},
		{
			name:             "Security - mixed case",
			input:            "SeCuRiTy",
			expectedCategory: GroupCategorySecurity,
			expectError:      false,
		},
		{
			name:             "Security - with whitespace",
			input:            "  Security  ",
			expectedCategory: GroupCategorySecurity,
			expectError:      false,
		},
		{
			name:             "Distribution - exact case",
			input:            "Distribution",
			expectedCategory: GroupCategoryDistribution,
			expectError:      false,
		},
		{
			name:             "Distribution - lowercase",
			input:            "distribution",
			expectedCategory: GroupCategoryDistribution,
			expectError:      false,
		},
		{
			name:             "Distribution - uppercase",
			input:            "DISTRIBUTION",
			expectedCategory: GroupCategoryDistribution,
			expectError:      false,
		},
		{
			name:             "Distribution - mixed case",
			input:            "DiStRiBuTiOn",
			expectedCategory: GroupCategoryDistribution,
			expectError:      false,
		},
		{
			name:        "Invalid category",
			input:       "Invalid",
			expectError: true,
		},
		{
			name:        "Empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "Whitespace only",
			input:       "   ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeGroupCategory(tt.input)

			if tt.expectError {
				assert.Error(t, err, "Expected an error for input: %s", tt.input)
				assert.Empty(t, result, "Expected empty result for invalid input")
			} else {
				assert.NoError(t, err, "Unexpected error for input: %s", tt.input)
				assert.Equal(t, tt.expectedCategory, result, "Category normalization mismatch")
			}
		})
	}
}

func TestValidateGroupRequest(t *testing.T) {
	gm, _ := createTestGroupManager(t)

	tests := []struct {
		name        string
		request     *CreateGroupRequest
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Nil request",
			request:     nil,
			expectError: true,
			errorMsg:    "create group request cannot be nil",
		},
		{
			name: "Empty name",
			request: &CreateGroupRequest{
				Name:           "",
				SAMAccountName: "test",
				Container:      "CN=Users,DC=test,DC=local",
				Scope:          GroupScopeGlobal,
				Category:       GroupCategorySecurity,
			},
			expectError: true,
			errorMsg:    "group name is required",
		},
		{
			name: "Empty SAM account name",
			request: &CreateGroupRequest{
				Name:           "TestGroup",
				SAMAccountName: "",
				Container:      "CN=Users,DC=test,DC=local",
				Scope:          GroupScopeGlobal,
				Category:       GroupCategorySecurity,
			},
			expectError: true,
			errorMsg:    "SAM account name is required",
		},
		{
			name: "Empty container",
			request: &CreateGroupRequest{
				Name:           "TestGroup",
				SAMAccountName: "TestGroup",
				Container:      "",
				Scope:          GroupScopeGlobal,
				Category:       GroupCategorySecurity,
			},
			expectError: true,
			errorMsg:    "container DN is required",
		},
		{
			name: "Invalid scope",
			request: &CreateGroupRequest{
				Name:           "TestGroup",
				SAMAccountName: "TestGroup",
				Container:      "CN=Users,DC=test,DC=local",
				Scope:          GroupScope("Invalid"),
				Category:       GroupCategorySecurity,
			},
			expectError: true,
			errorMsg:    "invalid group scope",
		},
		{
			name: "Invalid category",
			request: &CreateGroupRequest{
				Name:           "TestGroup",
				SAMAccountName: "TestGroup",
				Container:      "CN=Users,DC=test,DC=local",
				Scope:          GroupScopeGlobal,
				Category:       GroupCategory("Invalid"),
			},
			expectError: true,
			errorMsg:    "invalid group category",
		},
		{
			name: "Invalid SAM account name with spaces",
			request: &CreateGroupRequest{
				Name:           "TestGroup",
				SAMAccountName: "Test Group",
				Container:      "CN=Users,DC=test,DC=local",
				Scope:          GroupScopeGlobal,
				Category:       GroupCategorySecurity,
			},
			expectError: true,
			errorMsg:    "SAM account name contains invalid characters",
		},
		{
			name: "Invalid email for distribution group",
			request: &CreateGroupRequest{
				Name:           "TestGroup",
				SAMAccountName: "TestGroup",
				Container:      "CN=Users,DC=test,DC=local",
				Scope:          GroupScopeGlobal,
				Category:       GroupCategoryDistribution,
				Mail:           "invalid-email",
			},
			expectError: true,
			errorMsg:    "invalid email address format",
		},
		{
			name: "Valid request",
			request: &CreateGroupRequest{
				Name:           "TestGroup",
				SAMAccountName: "TestGroup",
				Container:      "CN=Users,DC=test,DC=local",
				Scope:          GroupScopeGlobal,
				Category:       GroupCategorySecurity,
				Description:    "Test group",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := gm.ValidateGroupRequest(tt.request)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateGroup(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	req := &CreateGroupRequest{
		Name:           "TestGroup",
		SAMAccountName: "TestGroup",
		Container:      "CN=Users,DC=test,DC=local",
		Scope:          GroupScopeGlobal,
		Category:       GroupCategorySecurity,
		Description:    "Test group",
	}

	// Mock successful group creation
	mockClient.On("Add", mock.Anything, mock.MatchedBy(func(addReq *AddRequest) bool {
		return addReq.DN == testDN &&
			addReq.Attributes["cn"][0] == "TestGroup" &&
			addReq.Attributes["sAMAccountName"][0] == "TestGroup"
	})).Return(nil)

	// Mock successful group retrieval after creation
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == testDN && searchReq.Scope == ScopeBaseObject
	})).Return(searchResult, nil)

	// Execute test
	group, err := gm.CreateGroup(req)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, testDN, group.DistinguishedName)
	assert.Equal(t, "TestGroup", group.Name)
	assert.Equal(t, "TestGroup", group.SAMAccountName)
	assert.Equal(t, GroupScopeGlobal, group.Scope)
	assert.Equal(t, GroupCategorySecurity, group.Category)

	mockClient.AssertExpectations(t)
}

func TestCreateGroupValidationError(t *testing.T) {
	gm, _ := createTestGroupManager(t)

	// Test with invalid request
	req := &CreateGroupRequest{
		Name:           "", // Invalid: empty name
		SAMAccountName: "TestGroup",
		Container:      "CN=Users,DC=test,DC=local",
		Scope:          GroupScopeGlobal,
		Category:       GroupCategorySecurity,
	}

	group, err := gm.CreateGroup(req)

	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "group name is required")
}

func TestGetGroup(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Create mock search result
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	// Mock GUID-based search
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" &&
			searchReq.Scope == ScopeWholeSubtree &&
			searchReq.SizeLimit == 1
	})).Return(searchResult, nil)

	// Execute test
	group, err := gm.GetGroup(testGUID)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, testDN, group.DistinguishedName)
	assert.Equal(t, "TestGroup", group.Name)
	assert.Equal(t, GroupScopeGlobal, group.Scope)
	assert.Equal(t, GroupCategorySecurity, group.Category)

	mockClient.AssertExpectations(t)
}

func TestGetGroupNotFound(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"

	// Mock empty search result
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}

	mockClient.On("Search", gm.ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Execute test
	group, err := gm.GetGroup(testGUID)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "not found")

	mockClient.AssertExpectations(t)
}

func TestGetGroupInvalidGUID(t *testing.T) {
	gm, _ := createTestGroupManager(t)

	// Test with invalid GUID
	group, err := gm.GetGroup("invalid-guid")

	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "invalid GUID format")
}

func TestUpdateGroup(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Create initial group state
	initialEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(initialSearchResult, nil).Once()

	// Mock modification
	newDescription := "Updated description"
	updateReq := &UpdateGroupRequest{
		Description: &newDescription,
	}

	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return modReq.DN == testDN &&
			modReq.ReplaceAttributes["description"][0] == newDescription
	})).Return(nil)

	// Create updated group state
	updatedEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	// Update description in the entry
	for _, attr := range updatedEntry.Attributes {
		if attr.Name == "description" {
			attr.Values = []string{newDescription}
			break
		}
	}
	updatedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{updatedEntry},
		Total:   1,
	}

	// Mock updated group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(updatedSearchResult, nil).Once()

	// Execute test
	group, err := gm.UpdateGroup(testGUID, updateReq)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, newDescription, group.Description)

	mockClient.AssertExpectations(t)
}

func TestUpdateGroupNoChanges(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Create initial group state
	initialEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval
	mockClient.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(initialSearchResult, nil)

	// Empty update request (no changes)
	updateReq := &UpdateGroupRequest{}

	// Execute test
	group, err := gm.UpdateGroup(testGUID, updateReq)

	// Assertions - should return current group without modifications
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)

	// Verify no Modify call was made
	mockClient.AssertNotCalled(t, "Modify", mock.Anything, mock.Anything)
	mockClient.AssertExpectations(t)
}

func TestDeleteGroup(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Mock group retrieval for deletion
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	mockClient.On("Search", gm.ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Mock deletion
	mockClient.On("Delete", mock.Anything, testDN).Return(nil)

	// Execute test
	err := gm.DeleteGroup(testGUID)

	// Assertions
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestDeleteGroupNotFound(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"

	// Mock empty search result (group not found)
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}

	mockClient.On("Search", gm.ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Execute test - should return without error if group doesn't exist
	err := gm.DeleteGroup(testGUID)

	// Assertions - deletion of non-existent group should succeed
	assert.NoError(t, err)
	mockClient.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	mockClient.AssertExpectations(t)
}

func TestAddMembers(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Mock group retrieval
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(searchResult, nil)

	// Mock member normalization
	memberDN := "CN=TestUser,CN=Users,DC=test,DC=local"
	memberEntry := &ldap.Entry{
		DN: memberDN,
		Attributes: []*ldap.EntryAttribute{
			{Name: "distinguishedName", Values: []string{memberDN}},
		},
	}
	memberSearchResult := &SearchResult{
		Entries: []*ldap.Entry{memberEntry},
		Total:   1,
	}

	mockClient.On("Search", mock.AnythingOfType("*context.timerCtx"), mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == memberDN && searchReq.Scope == ScopeBaseObject
	})).Return(memberSearchResult, nil)

	// Mock add member modification
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return modReq.DN == testDN &&
			len(modReq.AddAttributes["member"]) == 1 &&
			modReq.AddAttributes["member"][0] == memberDN
	})).Return(nil)

	// Execute test
	err := gm.AddMembers(testGUID, []string{memberDN})

	// Assertions
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestRemoveMembers(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	memberDN := "CN=TestUser,CN=Users,DC=test,DC=local"

	// Create group entry with existing member
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	// Add member attribute
	groupEntry.Attributes = append(groupEntry.Attributes, &ldap.EntryAttribute{
		Name:   "member",
		Values: []string{memberDN},
	})

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(searchResult, nil)

	// Mock member normalization
	memberEntry := &ldap.Entry{
		DN: memberDN,
		Attributes: []*ldap.EntryAttribute{
			{Name: "distinguishedName", Values: []string{memberDN}},
		},
	}
	memberSearchResult := &SearchResult{
		Entries: []*ldap.Entry{memberEntry},
		Total:   1,
	}

	mockClient.On("Search", mock.AnythingOfType("*context.timerCtx"), mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == memberDN && searchReq.Scope == ScopeBaseObject
	})).Return(memberSearchResult, nil)

	// Mock remove member modification (should delete member attribute since no members left)
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return modReq.DN == testDN &&
			len(modReq.DeleteAttributes) == 1 &&
			modReq.DeleteAttributes[0] == "member"
	})).Return(nil)

	// Execute test
	err := gm.RemoveMembers(testGUID, []string{memberDN})

	// Assertions
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestGetMembers(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	member1DN := "CN=User1,CN=Users,DC=test,DC=local"
	member2DN := "CN=User2,CN=Users,DC=test,DC=local"

	// Create group entry with members
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	groupEntry.Attributes = append(groupEntry.Attributes, &ldap.EntryAttribute{
		Name:   "member",
		Values: []string{member1DN, member2DN},
	})

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	mockClient.On("Search", gm.ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Execute test
	members, err := gm.GetMembers(testGUID)

	// Assertions
	require.NoError(t, err)
	assert.Len(t, members, 2)
	assert.Contains(t, members, member1DN)
	assert.Contains(t, members, member2DN)

	mockClient.AssertExpectations(t)
}

func TestSearchGroups(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	// Create multiple mock group entries
	group1GUID := "12345678-1234-1234-1234-123456789012"
	group1DN := "CN=Group1,CN=Users,DC=test,DC=local"
	group1Entry := createMockGroupEntry("Group1", group1GUID, group1DN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))

	group2GUID := "87654321-4321-4321-4321-210987654321"
	group2DN := "CN=Group2,CN=Users,DC=test,DC=local"
	group2Entry := createMockGroupEntry("Group2", group2GUID, group2DN, CalculateGroupType(GroupScopeUniversal, GroupCategoryDistribution))

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{group1Entry, group2Entry},
		Total:   2,
	}

	mockClient.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" &&
			searchReq.Scope == ScopeWholeSubtree &&
			searchReq.Filter == "(&(objectClass=group)(cn=Group*))"
	})).Return(searchResult, nil)

	// Execute test
	groups, err := gm.SearchGroups("(cn=Group*)", nil)

	// Assertions
	require.NoError(t, err)
	assert.Len(t, groups, 2)

	// Verify first group
	assert.Equal(t, group1GUID, groups[0].ObjectGUID)
	assert.Equal(t, "Group1", groups[0].Name)
	assert.Equal(t, GroupScopeGlobal, groups[0].Scope)
	assert.Equal(t, GroupCategorySecurity, groups[0].Category)

	// Verify second group
	assert.Equal(t, group2GUID, groups[1].ObjectGUID)
	assert.Equal(t, "Group2", groups[1].Name)
	assert.Equal(t, GroupScopeUniversal, groups[1].Scope)
	assert.Equal(t, GroupCategoryDistribution, groups[1].Category)

	mockClient.AssertExpectations(t)
}

func TestEntryToGroup(t *testing.T) {
	gm, _ := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	groupType := CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity)

	entry := createMockGroupEntry("TestGroup", testGUID, testDN, groupType)

	// Add additional attributes for comprehensive testing
	entry.Attributes = append(entry.Attributes,
		&ldap.EntryAttribute{Name: "objectSid", Values: []string{"S-1-5-21-123456789-123456789-123456789-1001"}},
		&ldap.EntryAttribute{Name: "mail", Values: []string{"testgroup@test.local"}},
		&ldap.EntryAttribute{Name: "mailNickname", Values: []string{"testgroup"}},
		&ldap.EntryAttribute{Name: "member", Values: []string{"CN=User1,CN=Users,DC=test,DC=local", "CN=User2,CN=Users,DC=test,DC=local"}},
		&ldap.EntryAttribute{Name: "memberOf", Values: []string{"CN=ParentGroup,CN=Users,DC=test,DC=local"}},
	)

	// Execute test
	group, err := gm.entryToGroup(entry)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, testDN, group.DistinguishedName)
	assert.Equal(t, "S-1-5-21-123456789-123456789-123456789-1001", group.ObjectSid)
	assert.Equal(t, "TestGroup", group.Name)
	assert.Equal(t, "TestGroup", group.SAMAccountName)
	assert.Equal(t, "Test group TestGroup", group.Description)
	assert.Equal(t, "testgroup@test.local", group.Mail)
	assert.Equal(t, "testgroup", group.MailNickname)
	assert.Equal(t, GroupScopeGlobal, group.Scope)
	assert.Equal(t, GroupCategorySecurity, group.Category)
	assert.Equal(t, groupType, group.GroupType)
	assert.Equal(t, "cn=Users,dc=test,dc=local", group.Container)
	assert.Len(t, group.MemberDNs, 2)
	assert.Contains(t, group.MemberDNs, "CN=User1,CN=Users,DC=test,DC=local")
	assert.Contains(t, group.MemberDNs, "CN=User2,CN=Users,DC=test,DC=local")
	assert.Len(t, group.MemberOf, 1)
	assert.Contains(t, group.MemberOf, "CN=ParentGroup,CN=Users,DC=test,DC=local")
}

func TestValidateScopeChange(t *testing.T) {
	gm, _ := createTestGroupManager(t)

	tests := []struct {
		name         string
		currentScope GroupScope
		newScope     GroupScope
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "No change",
			currentScope: GroupScopeGlobal,
			newScope:     GroupScopeGlobal,
			expectError:  false,
		},
		{
			name:         "Global to Universal",
			currentScope: GroupScopeGlobal,
			newScope:     GroupScopeUniversal,
			expectError:  false,
		},
		{
			name:         "Universal to Global",
			currentScope: GroupScopeUniversal,
			newScope:     GroupScopeGlobal,
			expectError:  false,
		},
		{
			name:         "Domain Local to Universal",
			currentScope: GroupScopeDomainLocal,
			newScope:     GroupScopeUniversal,
			expectError:  false,
		},
		{
			name:         "Universal to Domain Local",
			currentScope: GroupScopeUniversal,
			newScope:     GroupScopeDomainLocal,
			expectError:  false,
		},
		{
			name:         "Global to Domain Local (invalid)",
			currentScope: GroupScopeGlobal,
			newScope:     GroupScopeDomainLocal,
			expectError:  true,
			errorMsg:     "direct conversion from global to domainlocal is not allowed",
		},
		{
			name:         "Domain Local to Global (invalid)",
			currentScope: GroupScopeDomainLocal,
			newScope:     GroupScopeGlobal,
			expectError:  true,
			errorMsg:     "direct conversion from domainlocal to global is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := gm.validateScopeChange(tt.currentScope, tt.newScope)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetGroupStats(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	// Create mock groups with different types
	groups := []*ldap.Entry{
		createMockGroupEntry("Group1", "12345678-1234-1234-1234-123456789012", "CN=Group1,CN=Users,DC=test,DC=local", CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity)),
		createMockGroupEntry("Group2", "87654321-4321-4321-4321-210987654321", "CN=Group2,CN=Users,DC=test,DC=local", CalculateGroupType(GroupScopeUniversal, GroupCategoryDistribution)),
		createMockGroupEntry("Group3", "11111111-2222-3333-4444-555555555555", "CN=Group3,CN=Users,DC=test,DC=local", CalculateGroupType(GroupScopeDomainLocal, GroupCategorySecurity)),
	}

	searchResult := &SearchResult{
		Entries: groups,
		Total:   len(groups),
	}

	mockClient.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.Filter == "(objectClass=group)" &&
			searchReq.BaseDN == "DC=test,DC=local" &&
			searchReq.Scope == ScopeWholeSubtree
	})).Return(searchResult, nil)

	// Execute test
	stats, err := gm.GetGroupStats()

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, 3, stats["total"])
	assert.Equal(t, 1, stats["scope_global"])
	assert.Equal(t, 1, stats["scope_universal"])
	assert.Equal(t, 1, stats["scope_domainlocal"])
	assert.Equal(t, 2, stats["category_security"])
	assert.Equal(t, 1, stats["category_distribution"])

	mockClient.AssertExpectations(t)
}

func TestGroupScopeAndCategoryStrings(t *testing.T) {
	// Test GroupScope String method
	assert.Equal(t, "global", GroupScopeGlobal.String())
	assert.Equal(t, "universal", GroupScopeUniversal.String())
	assert.Equal(t, "domainlocal", GroupScopeDomainLocal.String())

	// Test GroupCategory String method
	assert.Equal(t, "security", GroupCategorySecurity.String())
	assert.Equal(t, "distribution", GroupCategoryDistribution.String())
}

func TestSetTimeout(t *testing.T) {
	gm, _ := createTestGroupManager(t)

	newTimeout := 60 * time.Second
	gm.SetTimeout(newTimeout)

	assert.Equal(t, newTimeout, gm.timeout)
	assert.Equal(t, newTimeout, gm.normalizer.timeout)
}

// Test error scenarios.
func TestCreateGroupLDAPError(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	req := &CreateGroupRequest{
		Name:           "TestGroup",
		SAMAccountName: "TestGroup",
		Container:      "CN=Users,DC=test,DC=local",
		Scope:          GroupScopeGlobal,
		Category:       GroupCategorySecurity,
	}

	// Mock LDAP error during creation
	ldapErr := &ldap.Error{
		ResultCode: ldap.LDAPResultEntryAlreadyExists,
		Err:        fmt.Errorf("group already exists"),
	}

	mockClient.On("Add", mock.Anything, mock.AnythingOfType("*ldap.AddRequest")).Return(ldapErr)

	// Execute test
	group, err := gm.CreateGroup(req)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "create_group")

	mockClient.AssertExpectations(t)
}

func TestSearchGroupsWithFilter(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	// Create multiple mock group entries with different characteristics
	// Security Global Group with members
	group1GUID := "12345678-1234-1234-1234-123456789012"
	group1DN := "CN=SecurityTeam,OU=Groups,DC=test,DC=local"
	group1Entry := createMockGroupEntry("SecurityTeam", group1GUID, group1DN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	group1Entry.Attributes = append(group1Entry.Attributes, &ldap.EntryAttribute{
		Name:   "member",
		Values: []string{"CN=User1,CN=Users,DC=test,DC=local"},
	})

	// Distribution Universal Group without members
	group2GUID := "87654321-4321-4321-4321-210987654321"
	group2DN := "CN=AllUsers,CN=Users,DC=test,DC=local"
	group2Entry := createMockGroupEntry("AllUsers", group2GUID, group2DN, CalculateGroupType(GroupScopeUniversal, GroupCategoryDistribution))

	// Security Domain Local Group
	group3GUID := "11111111-2222-3333-4444-555555555555"
	group3DN := "CN=LocalAdmins,OU=Groups,DC=test,DC=local"
	group3Entry := createMockGroupEntry("LocalAdmins", group3GUID, group3DN, CalculateGroupType(GroupScopeDomainLocal, GroupCategorySecurity))

	tests := []struct {
		name           string
		filter         *GroupSearchFilter
		expectedFilter string
		expectedBaseDN string
		mockEntries    []*ldap.Entry
		expectedCount  int
	}{
		{
			name:           "Empty filter returns all groups",
			filter:         &GroupSearchFilter{},
			expectedFilter: "(objectClass=group)",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group1Entry, group2Entry, group3Entry},
			expectedCount:  3,
		},
		{
			name:           "Nil filter returns all groups",
			filter:         nil,
			expectedFilter: "(objectClass=group)",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group1Entry, group2Entry, group3Entry},
			expectedCount:  3,
		},
		{
			name: "Name prefix filter",
			filter: &GroupSearchFilter{
				NamePrefix: "Security",
			},
			expectedFilter: "(&(objectClass=group)(cn=Security*))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group1Entry},
			expectedCount:  1,
		},
		{
			name: "Name suffix filter",
			filter: &GroupSearchFilter{
				NameSuffix: "Users",
			},
			expectedFilter: "(&(objectClass=group)(cn=*Users))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group2Entry},
			expectedCount:  1,
		},
		{
			name: "Name contains filter",
			filter: &GroupSearchFilter{
				NameContains: "Admin",
			},
			expectedFilter: "(&(objectClass=group)(cn=*Admin*))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group3Entry},
			expectedCount:  1,
		},
		{
			name: "Security category filter",
			filter: &GroupSearchFilter{
				Category: "security",
			},
			expectedFilter: "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group1Entry, group3Entry},
			expectedCount:  2,
		},
		{
			name: "Distribution category filter",
			filter: &GroupSearchFilter{
				Category: "distribution",
			},
			expectedFilter: "(&(objectClass=group)(!(groupType:1.2.840.113556.1.4.803:=2147483648)))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group2Entry},
			expectedCount:  1,
		},
		{
			name: "Global scope filter",
			filter: &GroupSearchFilter{
				Scope: "global",
			},
			expectedFilter: "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group1Entry},
			expectedCount:  1,
		},
		{
			name: "Universal scope filter",
			filter: &GroupSearchFilter{
				Scope: "universal",
			},
			expectedFilter: "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=8))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group2Entry},
			expectedCount:  1,
		},
		{
			name: "Domain Local scope filter",
			filter: &GroupSearchFilter{
				Scope: "domainlocal",
			},
			expectedFilter: "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=4))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group3Entry},
			expectedCount:  1,
		},
		{
			name: "Has members filter (true)",
			filter: &GroupSearchFilter{
				HasMembers: func(b bool) *bool { return &b }(true),
			},
			expectedFilter: "(&(objectClass=group)(member=*))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group1Entry},
			expectedCount:  1,
		},
		{
			name: "Has members filter (false)",
			filter: &GroupSearchFilter{
				HasMembers: func(b bool) *bool { return &b }(false),
			},
			expectedFilter: "(&(objectClass=group)(!(member=*)))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group2Entry, group3Entry},
			expectedCount:  2,
		},
		{
			name: "Custom container",
			filter: &GroupSearchFilter{
				Container: "OU=Groups,DC=test,DC=local",
			},
			expectedFilter: "(objectClass=group)",
			expectedBaseDN: "OU=Groups,DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group1Entry, group3Entry},
			expectedCount:  2,
		},
		{
			name: "Combined filters",
			filter: &GroupSearchFilter{
				NameContains: "Security",
				Category:     "security",
				Scope:        "global",
				HasMembers:   func(b bool) *bool { return &b }(true),
			},
			expectedFilter: "(&(objectClass=group)(&(cn=*Security*)(groupType:1.2.840.113556.1.4.803:=2147483648)(groupType:1.2.840.113556.1.4.803:=2)(member=*)))",
			expectedBaseDN: "DC=test,DC=local",
			mockEntries:    []*ldap.Entry{group1Entry},
			expectedCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create search result
			searchResult := &SearchResult{
				Entries: tt.mockEntries,
				Total:   len(tt.mockEntries),
			}

			// Mock the search call
			mockClient.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
				return searchReq.BaseDN == tt.expectedBaseDN &&
					searchReq.Scope == ScopeWholeSubtree &&
					searchReq.Filter == tt.expectedFilter
			})).Return(searchResult, nil).Once()

			// Execute test
			groups, err := gm.SearchGroupsWithFilter(tt.filter)

			// Assertions
			require.NoError(t, err)
			assert.Len(t, groups, tt.expectedCount)
			mockClient.AssertExpectations(t)
		})
	}
}

func TestValidateSearchFilter(t *testing.T) {
	gm, _ := createTestGroupManager(t)

	tests := []struct {
		name        string
		filter      *GroupSearchFilter
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Nil filter is valid",
			filter:      nil,
			expectError: false,
		},
		{
			name:        "Empty filter is valid",
			filter:      &GroupSearchFilter{},
			expectError: false,
		},
		{
			name: "Valid security category",
			filter: &GroupSearchFilter{
				Category: "security",
			},
			expectError: false,
		},
		{
			name: "Valid distribution category",
			filter: &GroupSearchFilter{
				Category: "distribution",
			},
			expectError: false,
		},
		{
			name: "Invalid category",
			filter: &GroupSearchFilter{
				Category: "invalid",
			},
			expectError: true,
			errorMsg:    "invalid category 'invalid': must be 'security', 'distribution', or empty",
		},
		{
			name: "Valid global scope",
			filter: &GroupSearchFilter{
				Scope: "global",
			},
			expectError: false,
		},
		{
			name: "Valid domainlocal scope",
			filter: &GroupSearchFilter{
				Scope: "domainlocal",
			},
			expectError: false,
		},
		{
			name: "Valid universal scope",
			filter: &GroupSearchFilter{
				Scope: "universal",
			},
			expectError: false,
		},
		{
			name: "Invalid scope",
			filter: &GroupSearchFilter{
				Scope: "invalid",
			},
			expectError: true,
			errorMsg:    "invalid scope 'invalid': must be 'global', 'domainlocal', 'universal', or empty",
		},
		{
			name: "Valid container DN",
			filter: &GroupSearchFilter{
				Container: "OU=Groups,DC=test,DC=local",
			},
			expectError: false,
		},
		{
			name: "Invalid container DN",
			filter: &GroupSearchFilter{
				Container: "invalid-dn",
			},
			expectError: true,
			errorMsg:    "invalid container DN 'invalid-dn'",
		},
		{
			name: "Valid name filters",
			filter: &GroupSearchFilter{
				NamePrefix:   "Test",
				NameSuffix:   "Group",
				NameContains: "Admin",
			},
			expectError: false,
		},
		{
			name: "Valid has members true",
			filter: &GroupSearchFilter{
				HasMembers: func(b bool) *bool { return &b }(true),
			},
			expectError: false,
		},
		{
			name: "Valid has members false",
			filter: &GroupSearchFilter{
				HasMembers: func(b bool) *bool { return &b }(false),
			},
			expectError: false,
		},
		{
			name: "Complex valid filter",
			filter: &GroupSearchFilter{
				NamePrefix: "Admin",
				Category:   "security",
				Scope:      "global",
				Container:  "OU=Groups,DC=test,DC=local",
				HasMembers: func(b bool) *bool { return &b }(true),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := gm.validateSearchFilter(tt.filter)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildLDAPFilter(t *testing.T) {
	gm, _ := createTestGroupManager(t)

	tests := []struct {
		name           string
		filter         *GroupSearchFilter
		expectedFilter string
	}{
		{
			name:           "Nil filter",
			filter:         nil,
			expectedFilter: "",
		},
		{
			name:           "Empty filter",
			filter:         &GroupSearchFilter{},
			expectedFilter: "",
		},
		{
			name: "Name prefix only",
			filter: &GroupSearchFilter{
				NamePrefix: "Test",
			},
			expectedFilter: "(cn=Test*)",
		},
		{
			name: "Name suffix only",
			filter: &GroupSearchFilter{
				NameSuffix: "Group",
			},
			expectedFilter: "(cn=*Group)",
		},
		{
			name: "Name contains only",
			filter: &GroupSearchFilter{
				NameContains: "Admin",
			},
			expectedFilter: "(cn=*Admin*)",
		},
		{
			name: "Security category",
			filter: &GroupSearchFilter{
				Category: "security",
			},
			expectedFilter: "(groupType:1.2.840.113556.1.4.803:=2147483648)",
		},
		{
			name: "Distribution category",
			filter: &GroupSearchFilter{
				Category: "distribution",
			},
			expectedFilter: "(!(groupType:1.2.840.113556.1.4.803:=2147483648))",
		},
		{
			name: "Global scope",
			filter: &GroupSearchFilter{
				Scope: "global",
			},
			expectedFilter: "(groupType:1.2.840.113556.1.4.803:=2)",
		},
		{
			name: "Domain Local scope",
			filter: &GroupSearchFilter{
				Scope: "domainlocal",
			},
			expectedFilter: "(groupType:1.2.840.113556.1.4.803:=4)",
		},
		{
			name: "Universal scope",
			filter: &GroupSearchFilter{
				Scope: "universal",
			},
			expectedFilter: "(groupType:1.2.840.113556.1.4.803:=8)",
		},
		{
			name: "Has members true",
			filter: &GroupSearchFilter{
				HasMembers: func(b bool) *bool { return &b }(true),
			},
			expectedFilter: "(member=*)",
		},
		{
			name: "Has members false",
			filter: &GroupSearchFilter{
				HasMembers: func(b bool) *bool { return &b }(false),
			},
			expectedFilter: "(!(member=*))",
		},
		{
			name: "Multiple name filters",
			filter: &GroupSearchFilter{
				NamePrefix:   "Test",
				NameContains: "Admin",
			},
			expectedFilter: "(&(cn=Test*)(cn=*Admin*))",
		},
		{
			name: "Complex filter",
			filter: &GroupSearchFilter{
				NameContains: "Admin",
				Category:     "security",
				Scope:        "global",
				HasMembers:   func(b bool) *bool { return &b }(true),
			},
			expectedFilter: "(&(cn=*Admin*)(groupType:1.2.840.113556.1.4.803:=2147483648)(groupType:1.2.840.113556.1.4.803:=2)(member=*))",
		},
		{
			name: "LDAP injection protection",
			filter: &GroupSearchFilter{
				NamePrefix: "Test)(objectClass=*",
			},
			expectedFilter: "(cn=Test\\29\\28objectClass=\\2a*)", // Should be properly escaped
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gm.buildLDAPFilter(tt.filter)
			assert.Equal(t, tt.expectedFilter, result)
		})
	}
}

func TestSearchGroupsWithFilterEdgeCases(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	t.Run("Search with invalid filter returns error", func(t *testing.T) {
		filter := &GroupSearchFilter{
			Category: "invalid",
		}

		_, err := gm.SearchGroupsWithFilter(filter)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid category")
	})

	t.Run("Search with LDAP error is wrapped", func(t *testing.T) {
		filter := &GroupSearchFilter{
			NamePrefix: "Test",
		}

		ldapErr := fmt.Errorf("LDAP connection failed")
		mockClient.On("SearchWithPaging", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(nil, ldapErr).Once()

		_, err := gm.SearchGroupsWithFilter(filter)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "search_groups_in_container")
		mockClient.AssertExpectations(t)
	})

	t.Run("Search with malformed entry is skipped", func(t *testing.T) {
		filter := &GroupSearchFilter{
			NamePrefix: "Test",
		}

		// Create a malformed entry (missing objectGUID)
		malformedEntry := &ldap.Entry{
			DN: "CN=MalformedGroup,CN=Users,DC=test,DC=local",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"MalformedGroup"}},
				// Missing objectGUID
			},
		}

		// Create a valid entry
		validGUID := "12345678-1234-1234-1234-123456789012"
		validDN := "CN=ValidGroup,CN=Users,DC=test,DC=local"
		validEntry := createMockGroupEntry("ValidGroup", validGUID, validDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))

		searchResult := &SearchResult{
			Entries: []*ldap.Entry{malformedEntry, validEntry},
			Total:   2,
		}

		mockClient.On("SearchWithPaging", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil).Once()

		groups, err := gm.SearchGroupsWithFilter(filter)
		require.NoError(t, err)
		assert.Len(t, groups, 1) // Only valid entry should be returned
		assert.Equal(t, validGUID, groups[0].ObjectGUID)
		mockClient.AssertExpectations(t)
	})

	t.Run("Case insensitive category and scope", func(t *testing.T) {
		tests := []struct {
			name  string
			value string
			valid bool
		}{
			{"Category uppercase", "SECURITY", true},
			{"Category mixed case", "Security", true},
			{"Scope uppercase", "GLOBAL", true},
			{"Scope mixed case", "Global", true},
			{"Invalid category case insensitive", "INVALID", false},
			{"Invalid scope case insensitive", "INVALID", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				filter := &GroupSearchFilter{}
				if strings.Contains(strings.ToLower(tt.name), "category") {
					filter.Category = tt.value
				} else {
					filter.Scope = tt.value
				}

				err := gm.validateSearchFilter(filter)
				if tt.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})
}

func TestSearchGroupsWithFilterBackwardCompatibility(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	// Create some test groups
	group1GUID := "12345678-1234-1234-1234-123456789012"
	group1DN := "CN=TestGroup1,CN=Users,DC=test,DC=local"
	group1Entry := createMockGroupEntry("TestGroup1", group1GUID, group1DN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))

	group2GUID := "87654321-4321-4321-4321-210987654321"
	group2DN := "CN=TestGroup2,CN=Users,DC=test,DC=local"
	group2Entry := createMockGroupEntry("TestGroup2", group2GUID, group2DN, CalculateGroupType(GroupScopeUniversal, GroupCategoryDistribution))

	t.Run("Nil filter calls existing SearchGroups", func(t *testing.T) {
		searchResult := &SearchResult{
			Entries: []*ldap.Entry{group1Entry, group2Entry},
			Total:   2,
		}

		// Mock the SearchWithPaging call that SearchGroups makes
		mockClient.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
			return searchReq.BaseDN == "DC=test,DC=local" &&
				searchReq.Scope == ScopeWholeSubtree &&
				searchReq.Filter == "(objectClass=group)"
		})).Return(searchResult, nil).Once()

		groups, err := gm.SearchGroupsWithFilter(nil)

		require.NoError(t, err)
		assert.Len(t, groups, 2)
		mockClient.AssertExpectations(t)
	})

	t.Run("Existing SearchGroups method still works", func(t *testing.T) {
		searchResult := &SearchResult{
			Entries: []*ldap.Entry{group1Entry},
			Total:   1,
		}

		// Test that the original SearchGroups method works unchanged
		mockClient.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
			return searchReq.BaseDN == "DC=test,DC=local" &&
				searchReq.Scope == ScopeWholeSubtree &&
				searchReq.Filter == "(&(objectClass=group)(cn=TestGroup1))"
		})).Return(searchResult, nil).Once()

		groups, err := gm.SearchGroups("(cn=TestGroup1)", nil)

		require.NoError(t, err)
		assert.Len(t, groups, 1)
		assert.Equal(t, "TestGroup1", groups[0].Name)
		mockClient.AssertExpectations(t)
	})

	t.Run("SearchGroupsWithFilter uses custom attributes", func(t *testing.T) {
		// Test that if we need specific attributes, they get passed through
		filter := &GroupSearchFilter{
			NamePrefix: "Test",
		}

		searchResult := &SearchResult{
			Entries: []*ldap.Entry{group1Entry},
			Total:   1,
		}

		mockClient.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
			return searchReq.BaseDN == "DC=test,DC=local" &&
				searchReq.Scope == ScopeWholeSubtree &&
				searchReq.Filter == "(&(objectClass=group)(cn=Test*))" &&
				len(searchReq.Attributes) > 0
		})).Return(searchResult, nil).Once()

		groups, err := gm.SearchGroupsWithFilter(filter)

		require.NoError(t, err)
		assert.Len(t, groups, 1)
		mockClient.AssertExpectations(t)
	})
}

func TestSearchGroupsInContainer(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=TestOU,DC=test,DC=local"
	groupEntry := createMockGroupEntry("TestGroup", groupGUID, groupDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))

	t.Run("Search in custom container", func(t *testing.T) {
		customBaseDN := "OU=TestOU,DC=test,DC=local"
		filter := "(cn=Test*)"
		attributes := []string{"cn", "objectGUID"}

		searchResult := &SearchResult{
			Entries: []*ldap.Entry{groupEntry},
			Total:   1,
		}

		mockClient.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
			return searchReq.BaseDN == customBaseDN &&
				searchReq.Scope == ScopeWholeSubtree &&
				searchReq.Filter == "(&(objectClass=group)(cn=Test*))" &&
				len(searchReq.Attributes) == 2
		})).Return(searchResult, nil)

		groups, err := gm.searchGroupsInContainer(customBaseDN, filter, attributes)

		require.NoError(t, err)
		assert.Len(t, groups, 1)
		assert.Equal(t, groupGUID, groups[0].ObjectGUID)
		mockClient.AssertExpectations(t)
	})

	t.Run("Empty filter uses default", func(t *testing.T) {
		searchResult := &SearchResult{
			Entries: []*ldap.Entry{groupEntry},
			Total:   1,
		}

		mockClient.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
			return searchReq.Filter == "(objectClass=group)"
		})).Return(searchResult, nil)

		groups, err := gm.searchGroupsInContainer("DC=test,DC=local", "", nil)

		require.NoError(t, err)
		assert.Len(t, groups, 1)
		mockClient.AssertExpectations(t)
	})

	t.Run("Empty attributes uses defaults", func(t *testing.T) {
		searchResult := &SearchResult{
			Entries: []*ldap.Entry{groupEntry},
			Total:   1,
		}

		mockClient.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
			return len(searchReq.Attributes) > 5 // Should have default attributes
		})).Return(searchResult, nil)

		groups, err := gm.searchGroupsInContainer("DC=test,DC=local", "", nil)

		require.NoError(t, err)
		assert.Len(t, groups, 1)
		mockClient.AssertExpectations(t)
	})
}

func TestAddMembersConflictHandling(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Mock group retrieval
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(searchResult, nil)

	// Mock member normalization
	memberDN := "CN=TestUser,CN=Users,DC=test,DC=local"
	memberEntry := &ldap.Entry{
		DN: memberDN,
		Attributes: []*ldap.EntryAttribute{
			{Name: "distinguishedName", Values: []string{memberDN}},
		},
	}
	memberSearchResult := &SearchResult{
		Entries: []*ldap.Entry{memberEntry},
		Total:   1,
	}

	mockClient.On("Search", mock.AnythingOfType("*context.timerCtx"), mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == memberDN && searchReq.Scope == ScopeBaseObject
	})).Return(memberSearchResult, nil)

	// Mock conflict error during bulk add
	conflictErr := &ldap.Error{
		ResultCode: ldap.LDAPResultAttributeOrValueExists,
		Err:        fmt.Errorf("member already exists"),
	}

	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return len(modReq.AddAttributes["member"]) > 0
	})).Return(conflictErr).Once()

	// Mock individual member add (should succeed)
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return len(modReq.AddAttributes["member"]) == 1 &&
			modReq.AddAttributes["member"][0] == memberDN
	})).Return(conflictErr) // Still conflict, but this is handled gracefully

	// Execute test
	err := gm.AddMembers(testGUID, []string{memberDN})

	// Assertions - should succeed even with conflicts (member already exists)
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestMoveGroup(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	currentDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	newContainerDN := "OU=NewOU,DC=test,DC=local"
	expectedNewDN := "CN=TestGroup,OU=NewOU,DC=test,DC=local"

	// Create initial group entry
	initialEntry := createMockGroupEntry("TestGroup", testGUID, currentDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(initialSearchResult, nil).Once()

	// Mock ModifyDN operation
	mockClient.On("ModifyDN", mock.Anything, mock.MatchedBy(func(modifyDNReq *ModifyDNRequest) bool {
		return modifyDNReq.DN == currentDN &&
			modifyDNReq.NewRDN == "cn=TestGroup" && // DN parsing normalizes to lowercase
			modifyDNReq.DeleteOldRDN == true &&
			modifyDNReq.NewSuperior == newContainerDN
	})).Return(nil)

	// Create moved group entry
	movedEntry := createMockGroupEntry("TestGroup", testGUID, expectedNewDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	movedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{movedEntry},
		Total:   1,
	}

	// Mock group retrieval after move
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(movedSearchResult, nil).Once()

	// Execute test
	group, err := gm.MoveGroup(testGUID, newContainerDN)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, expectedNewDN, group.DistinguishedName)
	// Container DN is normalized with lowercase attribute names but preserved values
	assert.Equal(t, "ou=NewOU,dc=test,dc=local", group.Container)

	mockClient.AssertExpectations(t)
}

func TestMoveGroupNotFound(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	newContainerDN := "OU=NewOU,DC=test,DC=local"

	// Mock empty search result (group not found)
	emptySearchResult := &SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}

	mockClient.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(emptySearchResult, nil)

	// Execute test
	group, err := gm.MoveGroup(testGUID, newContainerDN)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "not found")

	mockClient.AssertExpectations(t)
}

func TestMoveGroupInvalidGUID(t *testing.T) {
	gm, _ := createTestGroupManager(t)

	newContainerDN := "OU=NewOU,DC=test,DC=local"

	// Test with invalid GUID
	group, err := gm.MoveGroup("invalid-guid", newContainerDN)

	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "invalid GUID format")
}

func TestMoveGroupInvalidContainer(t *testing.T) {
	gm, _ := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"

	// Test with empty container
	group, err := gm.MoveGroup(testGUID, "")
	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "new container DN cannot be empty")
}

func TestMoveGroupToSameContainer(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	currentDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	sameContainerDN := "CN=Users,DC=test,DC=local" // Same container

	// Create group entry
	groupEntry := createMockGroupEntry("TestGroup", testGUID, currentDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	// Mock group retrieval
	mockClient.On("Search", gm.ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Execute test
	group, err := gm.MoveGroup(testGUID, sameContainerDN)

	// Assertions - should succeed without calling ModifyDN
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, currentDN, group.DistinguishedName)

	// Verify ModifyDN was not called
	mockClient.AssertNotCalled(t, "ModifyDN", mock.Anything, mock.Anything)
	mockClient.AssertExpectations(t)
}

func TestMoveGroupLDAPError(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	currentDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	newContainerDN := "OU=NewOU,DC=test,DC=local"

	// Create group entry
	groupEntry := createMockGroupEntry("TestGroup", testGUID, currentDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	// Mock group retrieval
	mockClient.On("Search", gm.ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Mock ModifyDN failure
	ldapErr := &ldap.Error{
		ResultCode: ldap.LDAPResultInsufficientAccessRights,
		Err:        fmt.Errorf("insufficient access rights"),
	}
	mockClient.On("ModifyDN", mock.Anything, mock.AnythingOfType("*ldap.ModifyDNRequest")).Return(ldapErr)

	// Execute test
	group, err := gm.MoveGroup(testGUID, newContainerDN)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "move_group")

	mockClient.AssertExpectations(t)
}

func TestMoveGroupPreservesMembers(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	currentDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	newContainerDN := "OU=NewOU,DC=test,DC=local"
	expectedNewDN := "CN=TestGroup,OU=NewOU,DC=test,DC=local"
	memberDN := "CN=TestUser,CN=Users,DC=test,DC=local"

	// Create initial group entry with members
	initialEntry := createMockGroupEntry("TestGroup", testGUID, currentDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	initialEntry.Attributes = append(initialEntry.Attributes, &ldap.EntryAttribute{
		Name:   "member",
		Values: []string{memberDN},
	})
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(initialSearchResult, nil).Once()

	// Mock ModifyDN operation
	mockClient.On("ModifyDN", mock.Anything, mock.MatchedBy(func(modifyDNReq *ModifyDNRequest) bool {
		return modifyDNReq.DN == currentDN &&
			modifyDNReq.NewRDN == "cn=TestGroup" && // DN parsing normalizes to lowercase
			modifyDNReq.DeleteOldRDN == true &&
			modifyDNReq.NewSuperior == newContainerDN
	})).Return(nil)

	// Create moved group entry with preserved members
	movedEntry := createMockGroupEntry("TestGroup", testGUID, expectedNewDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	movedEntry.Attributes = append(movedEntry.Attributes, &ldap.EntryAttribute{
		Name:   "member",
		Values: []string{memberDN},
	})
	movedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{movedEntry},
		Total:   1,
	}

	// Mock group retrieval after move
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(movedSearchResult, nil).Once()

	// Execute test
	group, err := gm.MoveGroup(testGUID, newContainerDN)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, expectedNewDN, group.DistinguishedName)
	assert.Len(t, group.MemberDNs, 1)
	assert.Contains(t, group.MemberDNs, memberDN)

	mockClient.AssertExpectations(t)
}

func TestUpdateGroupWithContainer(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	currentDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	newContainerDN := "OU=NewOU,DC=test,DC=local"
	expectedNewDN := "CN=TestGroup,OU=NewOU,DC=test,DC=local"

	// Create initial group entry
	initialEntry := createMockGroupEntry("TestGroup", testGUID, currentDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval (called by UpdateGroup)
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(initialSearchResult, nil).Once()

	// Mock ModifyDN operation (called by renameAndMoveGroup)
	mockClient.On("ModifyDN", mock.Anything, mock.AnythingOfType("*ldap.ModifyDNRequest")).Return(nil)

	// Create moved group entry
	movedEntry := createMockGroupEntry("TestGroup", testGUID, expectedNewDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	movedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{movedEntry},
		Total:   1,
	}

	// Mock group retrieval after move (called by renameAndMoveGroup)
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(movedSearchResult, nil).Once()

	// Update request with container change
	updateReq := &UpdateGroupRequest{
		Container: &newContainerDN,
	}

	// Execute test
	group, err := gm.UpdateGroup(testGUID, updateReq)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, expectedNewDN, group.DistinguishedName)
	// Container DN is normalized with lowercase attribute names but preserved values
	assert.Equal(t, "ou=NewOU,dc=test,dc=local", group.Container)

	// Verify ModifyDN was called (not Modify)
	mockClient.AssertNotCalled(t, "Modify", mock.Anything, mock.Anything)
	mockClient.AssertExpectations(t)
}

func TestUpdateGroupWithContainerAndOtherChanges(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	currentDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	newContainerDN := "OU=NewOU,DC=test,DC=local"
	expectedNewDN := "CN=TestGroup,OU=NewOU,DC=test,DC=local"
	newDescription := "Updated description"

	// Create initial group entry
	initialEntry := createMockGroupEntry("TestGroup", testGUID, currentDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval (called by UpdateGroup)
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(initialSearchResult, nil).Once()

	// Mock ModifyDN operation (called by renameAndMoveGroup)
	mockClient.On("ModifyDN", mock.Anything, mock.AnythingOfType("*ldap.ModifyDNRequest")).Return(nil)

	// Create moved group entry for retrieval after move
	movedEntry := createMockGroupEntry("TestGroup", testGUID, expectedNewDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	movedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{movedEntry},
		Total:   1,
	}

	// Mock group retrieval after move (called by renameAndMoveGroup)
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(movedSearchResult, nil).Once()

	// Mock modification of other attributes (uses new DN from move)
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return modReq.DN == expectedNewDN &&
			modReq.ReplaceAttributes["description"][0] == newDescription
	})).Return(nil)

	// Create final group entry with updated description
	finalEntry := createMockGroupEntry("TestGroup", testGUID, expectedNewDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	// Update description in the entry
	for _, attr := range finalEntry.Attributes {
		if attr.Name == "description" {
			attr.Values = []string{newDescription}
			break
		}
	}
	finalSearchResult := &SearchResult{
		Entries: []*ldap.Entry{finalEntry},
		Total:   1,
	}

	// Mock final group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(finalSearchResult, nil).Once()

	// Update request with both container and description changes
	updateReq := &UpdateGroupRequest{
		Container:   &newContainerDN,
		Description: &newDescription,
	}

	// Execute test
	group, err := gm.UpdateGroup(testGUID, updateReq)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, expectedNewDN, group.DistinguishedName)
	// Container DN is normalized with lowercase attribute names but preserved values
	assert.Equal(t, "ou=NewOU,dc=test,dc=local", group.Container)
	assert.Equal(t, newDescription, group.Description)

	mockClient.AssertExpectations(t)
}

func TestUpdateGroupSAMAccountName(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	oldSAMAccountName := "OldSAM"
	newSAMAccountName := "NewSAM"

	// Create initial group state
	initialEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	// Set initial SAM account name
	for _, attr := range initialEntry.Attributes {
		if attr.Name == "sAMAccountName" {
			attr.Values = []string{oldSAMAccountName}
			break
		}
	}
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(initialSearchResult, nil).Once()

	// Mock modification for SAM account name change
	updateReq := &UpdateGroupRequest{
		SAMAccountName: &newSAMAccountName,
	}

	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return modReq.DN == testDN &&
			modReq.ReplaceAttributes["sAMAccountName"][0] == newSAMAccountName
	})).Return(nil)

	// Create updated group state
	updatedEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	// Update SAM account name in the entry
	for _, attr := range updatedEntry.Attributes {
		if attr.Name == "sAMAccountName" {
			attr.Values = []string{newSAMAccountName}
			break
		}
	}
	updatedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{updatedEntry},
		Total:   1,
	}

	// Mock updated group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(updatedSearchResult, nil).Once()

	// Execute test
	group, err := gm.UpdateGroup(testGUID, updateReq)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, newSAMAccountName, group.SAMAccountName)

	mockClient.AssertExpectations(t)
}

func TestUpdateGroupNameRename(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	oldName := "OldGroupName"
	newName := "NewGroupName"
	oldDN := "CN=OldGroupName,CN=Users,DC=test,DC=local"
	newDN := "CN=NewGroupName,CN=Users,DC=test,DC=local"

	// Create initial group state
	initialEntry := createMockGroupEntry(oldName, testGUID, oldDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(initialSearchResult, nil).Once()

	// Mock ModifyDN for rename operation
	updateReq := &UpdateGroupRequest{
		Name: &newName,
	}

	mockClient.On("ModifyDN", mock.Anything, mock.MatchedBy(func(modifyDNReq *ModifyDNRequest) bool {
		return modifyDNReq.DN == oldDN &&
			modifyDNReq.NewRDN == "cn=NewGroupName" &&
			modifyDNReq.DeleteOldRDN == true &&
			modifyDNReq.NewSuperior == "" // No container change
	})).Return(nil)

	// Create renamed group state
	renamedEntry := createMockGroupEntry(newName, testGUID, newDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	renamedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{renamedEntry},
		Total:   1,
	}

	// Mock renamed group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(renamedSearchResult, nil).Once()

	// Execute test
	group, err := gm.UpdateGroup(testGUID, updateReq)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, newName, group.Name)
	assert.Equal(t, newDN, group.DistinguishedName)

	mockClient.AssertExpectations(t)
}

func TestUpdateGroupRenameAndMove(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)

	testGUID := "12345678-1234-1234-1234-123456789012"
	oldName := "OldGroupName"
	newName := "NewGroupName"
	oldDN := "CN=OldGroupName,CN=Users,DC=test,DC=local"
	newContainerDN := "OU=NewOU,DC=test,DC=local"
	newDN := "CN=NewGroupName,OU=NewOU,DC=test,DC=local"

	// Create initial group state
	initialEntry := createMockGroupEntry(oldName, testGUID, oldDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(initialSearchResult, nil).Once()

	// Mock ModifyDN for combined rename and move operation
	updateReq := &UpdateGroupRequest{
		Name:      &newName,
		Container: &newContainerDN,
	}

	mockClient.On("ModifyDN", mock.Anything, mock.MatchedBy(func(modifyDNReq *ModifyDNRequest) bool {
		return modifyDNReq.DN == oldDN &&
			modifyDNReq.NewRDN == "cn=NewGroupName" &&
			modifyDNReq.DeleteOldRDN == true &&
			modifyDNReq.NewSuperior == newContainerDN
	})).Return(nil)

	// Create renamed and moved group state
	renamedMovedEntry := createMockGroupEntry(newName, testGUID, newDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	renamedMovedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{renamedMovedEntry},
		Total:   1,
	}

	// Mock renamed/moved group retrieval
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(renamedMovedSearchResult, nil).Once()

	// Execute test
	group, err := gm.UpdateGroup(testGUID, updateReq)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, newName, group.Name)
	assert.Equal(t, newDN, group.DistinguishedName)
	assert.Equal(t, "ou=NewOU,dc=test,dc=local", group.Container)

	mockClient.AssertExpectations(t)
}
