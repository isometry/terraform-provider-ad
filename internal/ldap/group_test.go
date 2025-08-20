package ldap

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockGroupClient implements the Client interface for testing group operations
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
	return args.Get(0).(*SearchResult), args.Error(1)
}

func (m *MockGroupClient) Add(ctx context.Context, req *AddRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockGroupClient) Modify(ctx context.Context, req *ModifyRequest) error {
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
	return args.Get(0).(PoolStats)
}

func (m *MockGroupClient) SearchWithPaging(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*SearchResult), args.Error(1)
}

func (m *MockGroupClient) GetBaseDN(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

// Helper function to create a mock LDAP entry for a group
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

// Helper function to create a test GroupManager with mock client
func createTestGroupManager() (*GroupManager, *MockGroupClient) {
	mockClient := &MockGroupClient{}
	baseDN := "DC=test,DC=local"
	gm := NewGroupManager(mockClient, baseDN)
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

func TestValidateGroupRequest(t *testing.T) {
	gm, _ := createTestGroupManager()

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
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

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
	mockClient.On("Add", ctx, mock.MatchedBy(func(addReq *AddRequest) bool {
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

	mockClient.On("Search", ctx, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == testDN && searchReq.Scope == ScopeBaseObject
	})).Return(searchResult, nil)

	// Execute test
	group, err := gm.CreateGroup(ctx, req)

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
	gm, _ := createTestGroupManager()
	ctx := context.Background()

	// Test with invalid request
	req := &CreateGroupRequest{
		Name:           "", // Invalid: empty name
		SAMAccountName: "TestGroup",
		Container:      "CN=Users,DC=test,DC=local",
		Scope:          GroupScopeGlobal,
		Category:       GroupCategorySecurity,
	}

	group, err := gm.CreateGroup(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "group name is required")
}

func TestGetGroup(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Create mock search result
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	// Mock GUID-based search
	mockClient.On("Search", ctx, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" &&
			searchReq.Scope == ScopeWholeSubtree &&
			searchReq.SizeLimit == 1
	})).Return(searchResult, nil)

	// Execute test
	group, err := gm.GetGroup(ctx, testGUID)

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
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

	testGUID := "12345678-1234-1234-1234-123456789012"

	// Mock empty search result
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}

	mockClient.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Execute test
	group, err := gm.GetGroup(ctx, testGUID)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "not found")

	mockClient.AssertExpectations(t)
}

func TestGetGroupInvalidGUID(t *testing.T) {
	gm, _ := createTestGroupManager()
	ctx := context.Background()

	// Test with invalid GUID
	group, err := gm.GetGroup(ctx, "invalid-guid")

	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "invalid GUID format")
}

func TestUpdateGroup(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Create initial group state
	initialEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval
	mockClient.On("Search", ctx, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(initialSearchResult, nil).Once()

	// Mock modification
	newDescription := "Updated description"
	updateReq := &UpdateGroupRequest{
		Description: &newDescription,
	}

	mockClient.On("Modify", ctx, mock.MatchedBy(func(modReq *ModifyRequest) bool {
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
	mockClient.On("Search", ctx, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" && searchReq.Scope == ScopeWholeSubtree
	})).Return(updatedSearchResult, nil).Once()

	// Execute test
	group, err := gm.UpdateGroup(ctx, testGUID, updateReq)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)
	assert.Equal(t, newDescription, group.Description)

	mockClient.AssertExpectations(t)
}

func TestUpdateGroupNoChanges(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Create initial group state
	initialEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	initialSearchResult := &SearchResult{
		Entries: []*ldap.Entry{initialEntry},
		Total:   1,
	}

	// Mock initial group retrieval
	mockClient.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(initialSearchResult, nil)

	// Empty update request (no changes)
	updateReq := &UpdateGroupRequest{}

	// Execute test
	group, err := gm.UpdateGroup(ctx, testGUID, updateReq)

	// Assertions - should return current group without modifications
	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, testGUID, group.ObjectGUID)

	// Verify no Modify call was made
	mockClient.AssertNotCalled(t, "Modify", mock.Anything, mock.Anything)
	mockClient.AssertExpectations(t)
}

func TestDeleteGroup(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Mock group retrieval for deletion
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	mockClient.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Mock deletion
	mockClient.On("Delete", ctx, testDN).Return(nil)

	// Execute test
	err := gm.DeleteGroup(ctx, testGUID)

	// Assertions
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestDeleteGroupNotFound(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

	testGUID := "12345678-1234-1234-1234-123456789012"

	// Mock empty search result (group not found)
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}

	mockClient.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Execute test - should return without error if group doesn't exist
	err := gm.DeleteGroup(ctx, testGUID)

	// Assertions - deletion of non-existent group should succeed
	assert.NoError(t, err)
	mockClient.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	mockClient.AssertExpectations(t)
}

func TestAddMembers(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Mock group retrieval
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	mockClient.On("Search", ctx, mock.MatchedBy(func(searchReq *SearchRequest) bool {
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
	mockClient.On("Modify", ctx, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return modReq.DN == testDN &&
			len(modReq.AddAttributes["member"]) == 1 &&
			modReq.AddAttributes["member"][0] == memberDN
	})).Return(nil)

	// Execute test
	err := gm.AddMembers(ctx, testGUID, []string{memberDN})

	// Assertions
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestRemoveMembers(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

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

	mockClient.On("Search", ctx, mock.MatchedBy(func(searchReq *SearchRequest) bool {
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
	mockClient.On("Modify", ctx, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return modReq.DN == testDN &&
			len(modReq.DeleteAttributes) == 1 &&
			modReq.DeleteAttributes[0] == "member"
	})).Return(nil)

	// Execute test
	err := gm.RemoveMembers(ctx, testGUID, []string{memberDN})

	// Assertions
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestGetMembers(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

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

	mockClient.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Execute test
	members, err := gm.GetMembers(ctx, testGUID)

	// Assertions
	require.NoError(t, err)
	assert.Len(t, members, 2)
	assert.Contains(t, members, member1DN)
	assert.Contains(t, members, member2DN)

	mockClient.AssertExpectations(t)
}

func TestSearchGroups(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

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

	mockClient.On("SearchWithPaging", ctx, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.BaseDN == "DC=test,DC=local" &&
			searchReq.Scope == ScopeWholeSubtree &&
			searchReq.Filter == "(&(objectClass=group)(cn=Group*))"
	})).Return(searchResult, nil)

	// Execute test
	groups, err := gm.SearchGroups(ctx, "(cn=Group*)", nil)

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
	gm, _ := createTestGroupManager()

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
	gm, _ := createTestGroupManager()

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
			errorMsg:     "direct conversion from Global to DomainLocal is not allowed",
		},
		{
			name:         "Domain Local to Global (invalid)",
			currentScope: GroupScopeDomainLocal,
			newScope:     GroupScopeGlobal,
			expectError:  true,
			errorMsg:     "direct conversion from DomainLocal to Global is not allowed",
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
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

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

	mockClient.On("SearchWithPaging", ctx, mock.MatchedBy(func(searchReq *SearchRequest) bool {
		return searchReq.Filter == "(objectClass=group)" &&
			searchReq.BaseDN == "DC=test,DC=local" &&
			searchReq.Scope == ScopeWholeSubtree
	})).Return(searchResult, nil)

	// Execute test
	stats, err := gm.GetGroupStats(ctx)

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
	assert.Equal(t, "Global", GroupScopeGlobal.String())
	assert.Equal(t, "Universal", GroupScopeUniversal.String())
	assert.Equal(t, "DomainLocal", GroupScopeDomainLocal.String())

	// Test GroupCategory String method
	assert.Equal(t, "Security", GroupCategorySecurity.String())
	assert.Equal(t, "Distribution", GroupCategoryDistribution.String())
}

func TestSetTimeout(t *testing.T) {
	gm, _ := createTestGroupManager()

	newTimeout := 60 * time.Second
	gm.SetTimeout(newTimeout)

	assert.Equal(t, newTimeout, gm.timeout)
	assert.Equal(t, newTimeout, gm.normalizer.timeout)
}

// Test error scenarios
func TestCreateGroupLDAPError(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

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

	mockClient.On("Add", ctx, mock.AnythingOfType("*ldap.AddRequest")).Return(ldapErr)

	// Execute test
	group, err := gm.CreateGroup(ctx, req)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "create_group")

	mockClient.AssertExpectations(t)
}

func TestAddMembersConflictHandling(t *testing.T) {
	gm, mockClient := createTestGroupManager()
	ctx := context.Background()

	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"

	// Mock group retrieval
	groupEntry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{groupEntry},
		Total:   1,
	}

	mockClient.On("Search", ctx, mock.MatchedBy(func(searchReq *SearchRequest) bool {
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

	mockClient.On("Modify", ctx, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return len(modReq.AddAttributes["member"]) > 0
	})).Return(conflictErr).Once()

	// Mock individual member add (should succeed)
	mockClient.On("Modify", ctx, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return len(modReq.AddAttributes["member"]) == 1 &&
			modReq.AddAttributes["member"][0] == memberDN
	})).Return(conflictErr) // Still conflict, but this is handled gracefully

	// Execute test
	err := gm.AddMembers(ctx, testGUID, []string{memberDN})

	// Assertions - should succeed even with conflicts (member already exists)
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}
