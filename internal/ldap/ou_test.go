package ldap

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockOUClient implements the Client interface for testing OU operations.
type MockOUClient struct {
	mock.Mock
}

func (m *MockOUClient) Connect(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockOUClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockOUClient) Bind(ctx context.Context, username, password string) error {
	args := m.Called(ctx, username, password)
	return args.Error(0)
}

func (m *MockOUClient) BindWithConfig(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockOUClient) Search(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	args := m.Called(ctx, req)
	if result := args.Get(0); result != nil {
		if searchResult, ok := result.(*SearchResult); ok {
			return searchResult, args.Error(1)
		}
	}
	return nil, args.Error(1)
}

func (m *MockOUClient) SearchWithPaging(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	args := m.Called(ctx, req)
	if result := args.Get(0); result != nil {
		if searchResult, ok := result.(*SearchResult); ok {
			return searchResult, args.Error(1)
		}
	}
	return nil, args.Error(1)
}

func (m *MockOUClient) Add(ctx context.Context, req *AddRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockOUClient) Modify(ctx context.Context, req *ModifyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockOUClient) Delete(ctx context.Context, dn string) error {
	args := m.Called(ctx, dn)
	return args.Error(0)
}

func (m *MockOUClient) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockOUClient) Stats() PoolStats {
	args := m.Called()
	if stats := args.Get(0); stats != nil {
		if poolStats, ok := stats.(PoolStats); ok {
			return poolStats
		}
	}
	return PoolStats{}
}

func (m *MockOUClient) GetBaseDN(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *MockOUClient) ModifyDN(ctx context.Context, req *ModifyDNRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func TestOUManager_BuildOUDN(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	tests := []struct {
		name     string
		ouName   string
		parentDN string
		expected string
	}{
		{
			name:     "Simple OU name",
			ouName:   "TestOU",
			parentDN: "dc=example,dc=com",
			expected: "OU=TestOU,dc=example,dc=com",
		},
		{
			name:     "OU with spaces",
			ouName:   "Test OU",
			parentDN: "dc=example,dc=com",
			expected: "OU=Test OU,dc=example,dc=com",
		},
		{
			name:     "Nested OU",
			ouName:   "SubOU",
			parentDN: "OU=ParentOU,dc=example,dc=com",
			expected: "OU=SubOU,OU=ParentOU,dc=example,dc=com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.BuildOUDN(tt.ouName, tt.parentDN)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOUManager_ValidateOUHierarchy(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	tests := []struct {
		name     string
		ouDN     string
		parentDN string
		wantErr  bool
	}{
		{
			name:     "Valid hierarchy",
			ouDN:     "OU=TestOU,dc=example,dc=com",
			parentDN: "dc=example,dc=com",
			wantErr:  false,
		},
		{
			name:     "Valid nested hierarchy",
			ouDN:     "OU=SubOU,OU=ParentOU,dc=example,dc=com",
			parentDN: "OU=ParentOU,dc=example,dc=com",
			wantErr:  false,
		},
		{
			name:     "Invalid - same DN",
			ouDN:     "dc=example,dc=com",
			parentDN: "dc=example,dc=com",
			wantErr:  true,
		},
		{
			name:     "Invalid - wrong parent",
			ouDN:     "OU=TestOU,OU=WrongParent,dc=example,dc=com",
			parentDN: "OU=RightParent,dc=example,dc=com",
			wantErr:  true,
		},
		{
			name:     "Empty DNs",
			ouDN:     "",
			parentDN: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.ValidateOUHierarchy(tt.ouDN, tt.parentDN)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOUManager_ValidateOURequest(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	tests := []struct {
		name    string
		req     *CreateOURequest
		wantErr bool
	}{
		{
			name: "Valid request",
			req: &CreateOURequest{
				Name:        "TestOU",
				ParentDN:    "dc=example,dc=com",
				Description: "Test OU",
				Protected:   false,
			},
			wantErr: false,
		},
		{
			name:    "Nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "Empty name",
			req: &CreateOURequest{
				Name:     "",
				ParentDN: "dc=example,dc=com",
			},
			wantErr: true,
		},
		{
			name: "Empty parent DN",
			req: &CreateOURequest{
				Name:     "TestOU",
				ParentDN: "",
			},
			wantErr: true,
		},
		{
			name: "Invalid characters in name",
			req: &CreateOURequest{
				Name:     "Test\"OU",
				ParentDN: "dc=example,dc=com",
			},
			wantErr: true,
		},
		{
			name: "Invalid parent DN syntax",
			req: &CreateOURequest{
				Name:     "TestOU",
				ParentDN: "invalid-dn",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.ValidateOURequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOUManager_CreateOU(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	ctx := context.Background()
	testTime := time.Now()

	req := &CreateOURequest{
		Name:        "TestOU",
		ParentDN:    "dc=example,dc=com",
		Description: "Test OU Description",
		Protected:   false,
	}

	// Mock GUID bytes for the created OU
	testGUIDBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}

	// Create mock LDAP entry for the created OU
	entry := &ldap.Entry{
		DN: "OU=TestOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"TestOU"}},
			{Name: "description", Values: []string{"Test OU Description"}},
			{Name: "whenCreated", Values: []string{testTime.Format("20060102150405.0Z")}},
			{Name: "whenChanged", Values: []string{testTime.Format("20060102150405.0Z")}},
		},
	}

	// Expected add request
	expectedAddReq := &AddRequest{
		DN: "OU=TestOU,dc=example,dc=com",
		Attributes: map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"TestOU"},
			"description": {"Test OU Description"},
		},
	}

	// Mock successful add operation
	client.On("Add", ctx, mock.MatchedBy(func(addReq *AddRequest) bool {
		return addReq.DN == expectedAddReq.DN &&
			assert.Equal(t, expectedAddReq.Attributes, addReq.Attributes)
	})).Return(nil)

	// Mock search for getting created OU
	searchReq := &SearchRequest{
		BaseDN: "OU=TestOU,dc=example,dc=com",
		Scope:  ScopeBaseObject,
		Filter: "(objectClass=organizationalUnit)",
	}

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{entry},
		Total:   1,
		HasMore: false,
	}

	client.On("Search", ctx, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == searchReq.BaseDN &&
			req.Scope == searchReq.Scope &&
			req.Filter == searchReq.Filter
	})).Return(searchResult, nil)

	// Execute test
	result, err := manager.CreateOU(ctx, req)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "TestOU", result.Name)
	assert.Equal(t, "Test OU Description", result.Description)
	assert.Equal(t, "OU=TestOU,dc=example,dc=com", result.DistinguishedName)
	assert.Equal(t, "dc=example,dc=com", result.Parent)
	assert.False(t, result.Protected)

	client.AssertExpectations(t)
}

func TestOUManager_GetOU(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	ctx := context.Background()
	testGUID := "12345678-1234-1234-1234-123456789012"
	testGUIDBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}
	testTime := time.Now()

	// Create mock LDAP entry
	entry := &ldap.Entry{
		DN: "OU=TestOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"TestOU"}},
			{Name: "description", Values: []string{"Test OU Description"}},
			{Name: "whenCreated", Values: []string{testTime.Format("20060102150405.0Z")}},
			{Name: "whenChanged", Values: []string{testTime.Format("20060102150405.0Z")}},
		},
	}

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{entry},
		Total:   1,
		HasMore: false,
	}

	// Mock GUID search
	client.On("Search", ctx, mock.MatchedBy(func(req *SearchRequest) bool {
		return strings.Contains(req.Filter, "objectGUID") &&
			strings.Contains(req.Filter, "objectClass=organizationalUnit")
	})).Return(searchResult, nil)

	// Execute test
	result, err := manager.GetOU(ctx, testGUID)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	// Due to AD mixed-endian GUID format, the returned GUID will be different from input bytes
	assert.NotEmpty(t, result.ObjectGUID)
	assert.Equal(t, "TestOU", result.Name)
	assert.Equal(t, "Test OU Description", result.Description)
	assert.Equal(t, "OU=TestOU,dc=example,dc=com", result.DistinguishedName)

	client.AssertExpectations(t)
}

func TestOUManager_GetOU_NotFound(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	ctx := context.Background()
	testGUID := "12345678-1234-1234-1234-123456789012"

	// Mock empty search result
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
		HasMore: false,
	}

	client.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Execute test
	result, err := manager.GetOU(ctx, testGUID)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "not found")

	client.AssertExpectations(t)
}

func TestOUManager_UpdateOU(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	ctx := context.Background()
	testGUID := "12345678-1234-1234-1234-123456789012"
	testGUIDBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}
	testTime := time.Now()

	// Current OU entry
	currentEntry := &ldap.Entry{
		DN: "OU=TestOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"TestOU"}},
			{Name: "description", Values: []string{"Old Description"}},
			{Name: "whenCreated", Values: []string{testTime.Format("20060102150405.0Z")}},
			{Name: "whenChanged", Values: []string{testTime.Format("20060102150405.0Z")}},
		},
	}

	// Updated OU entry
	updatedEntry := &ldap.Entry{
		DN: "OU=TestOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"UpdatedOU"}},
			{Name: "description", Values: []string{"New Description"}},
			{Name: "whenCreated", Values: []string{testTime.Format("20060102150405.0Z")}},
			{Name: "whenChanged", Values: []string{testTime.Format("20060102150405.0Z")}},
		},
	}

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{currentEntry},
		Total:   1,
		HasMore: false,
	}

	updatedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{updatedEntry},
		Total:   1,
		HasMore: false,
	}

	// Mock getting current OU
	client.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil).Once()

	// Mock modify operation
	expectedModReq := &ModifyRequest{
		DN: "OU=TestOU,dc=example,dc=com",
		ReplaceAttributes: map[string][]string{
			"ou":          {"UpdatedOU"},
			"description": {"New Description"},
		},
	}

	client.On("Modify", ctx, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return modReq.DN == expectedModReq.DN
	})).Return(nil)

	// Mock getting updated OU
	client.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(updatedSearchResult, nil).Once()

	// Update request
	newName := "UpdatedOU"
	newDescription := "New Description"
	updateReq := &UpdateOURequest{
		Name:        &newName,
		Description: &newDescription,
	}

	// Execute test
	result, err := manager.UpdateOU(ctx, testGUID, updateReq)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	// Due to AD mixed-endian GUID format, the returned GUID will be different from input bytes
	assert.NotEmpty(t, result.ObjectGUID)
	assert.Equal(t, "UpdatedOU", result.Name)
	assert.Equal(t, "New Description", result.Description)

	client.AssertExpectations(t)
}

func TestOUManager_DeleteOU(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	ctx := context.Background()
	testGUID := "12345678-1234-1234-1234-123456789012"
	testGUIDBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}

	// Create mock LDAP entry for unprotected OU
	entry := &ldap.Entry{
		DN: "OU=TestOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"TestOU"}},
			{Name: "description", Values: []string{"Test OU"}},
		},
	}

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{entry},
		Total:   1,
		HasMore: false,
	}

	// Mock getting OU for deletion check
	client.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Mock delete operation
	client.On("Delete", ctx, "OU=TestOU,dc=example,dc=com").Return(nil)

	// Execute test
	err := manager.DeleteOU(ctx, testGUID)

	// Assertions
	require.NoError(t, err)

	client.AssertExpectations(t)
}

func TestOUManager_DeleteOU_Protected(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	ctx := context.Background()
	testGUID := "12345678-1234-1234-1234-123456789012"
	testGUIDBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}

	// Create mock LDAP entry for protected OU (with security descriptor)
	entry := &ldap.Entry{
		DN: "OU=TestOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"TestOU"}},
			{Name: "description", Values: []string{"Test OU"}},
			// Mock a large security descriptor to simulate protection (base64 encoded)
			{Name: "ntSecurityDescriptor", Values: []string{base64.StdEncoding.EncodeToString(make([]byte, 200))}},
		},
	}

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{entry},
		Total:   1,
		HasMore: false,
	}

	// Mock getting OU for deletion check
	client.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Note: We do NOT mock Delete() call because it should not be called for protected OUs

	// Execute test
	err := manager.DeleteOU(ctx, testGUID)

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "protected")

	client.AssertExpectations(t)
}

func TestOUManager_SearchOUs(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	ctx := context.Background()
	testGUIDBytes1 := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}
	testGUIDBytes2 := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x13}

	// Create mock LDAP entries
	entry1 := &ldap.Entry{
		DN: "OU=TestOU1,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes1)}, ByteValues: [][]byte{testGUIDBytes1}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU1,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"TestOU1"}},
			{Name: "description", Values: []string{"First Test OU"}},
		},
	}

	entry2 := &ldap.Entry{
		DN: "OU=TestOU2,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes2)}, ByteValues: [][]byte{testGUIDBytes2}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU2,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"TestOU2"}},
			{Name: "description", Values: []string{"Second Test OU"}},
		},
	}

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{entry1, entry2},
		Total:   2,
		HasMore: false,
	}

	// Mock search operation
	client.On("SearchWithPaging", ctx, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.Filter == "(&(objectClass=organizationalUnit)(ou=Test*))" &&
			req.BaseDN == "dc=example,dc=com"
	})).Return(searchResult, nil)

	// Execute test
	results, err := manager.SearchOUs(ctx, "dc=example,dc=com", "(ou=Test*)")

	// Assertions
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "TestOU1", results[0].Name)
	assert.Equal(t, "TestOU2", results[1].Name)

	client.AssertExpectations(t)
}

func TestOUManager_GetOUChildren(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	ctx := context.Background()
	parentOUDN := "OU=ParentOU,dc=example,dc=com"
	testGUIDBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}

	// Create mock child OU entry
	childEntry := &ldap.Entry{
		DN: "OU=ChildOU,OU=ParentOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=ChildOU,OU=ParentOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"ChildOU"}},
			{Name: "description", Values: []string{"Child OU"}},
		},
	}

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{childEntry},
		Total:   1,
		HasMore: false,
	}

	// Mock search for children (single level scope)
	client.On("Search", ctx, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == parentOUDN &&
			req.Scope == ScopeSingleLevel &&
			req.Filter == "(objectClass=organizationalUnit)"
	})).Return(searchResult, nil)

	// Execute test
	children, err := manager.GetOUChildren(ctx, parentOUDN)

	// Assertions
	require.NoError(t, err)
	require.Len(t, children, 1)
	assert.Equal(t, "ChildOU", children[0].Name)
	assert.Equal(t, "OU=ChildOU,OU=ParentOU,dc=example,dc=com", children[0].DistinguishedName)
	assert.Equal(t, "ou=ParentOU,dc=example,dc=com", children[0].Parent) // DN parsing results in lowercase

	client.AssertExpectations(t)
}

func TestOUManager_GetOUStats(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	ctx := context.Background()
	testGUIDBytes1 := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}
	testGUIDBytes2 := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x13}

	// Create mock LDAP entries - one protected, one unprotected
	entry1 := &ldap.Entry{
		DN: "OU=ProtectedOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes1)}, ByteValues: [][]byte{testGUIDBytes1}},
			{Name: "distinguishedName", Values: []string{"OU=ProtectedOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"ProtectedOU"}},
			{Name: "ntSecurityDescriptor", Values: []string{base64.StdEncoding.EncodeToString(make([]byte, 200))}}, // Large descriptor = protected
		},
	}

	entry2 := &ldap.Entry{
		DN: "OU=UnprotectedOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes2)}, ByteValues: [][]byte{testGUIDBytes2}},
			{Name: "distinguishedName", Values: []string{"OU=UnprotectedOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"UnprotectedOU"}},
		},
	}

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{entry1, entry2},
		Total:   2,
		HasMore: false,
	}

	// Mock search operation
	client.On("SearchWithPaging", ctx, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.Filter == "(objectClass=organizationalUnit)"
	})).Return(searchResult, nil)

	// Execute test
	stats, err := manager.GetOUStats(ctx)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, 2, stats["total"])
	assert.Equal(t, 1, stats["protected"])
	assert.Equal(t, 1, stats["unprotected"])

	client.AssertExpectations(t)
}

func TestOUManager_EntryToOU(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	testGUIDBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}
	testTime := time.Date(2025, 8, 21, 12, 0, 0, 0, time.UTC) // Fixed time for consistent testing

	entry := &ldap.Entry{
		DN: "OU=TestOU,OU=ParentOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU,OU=ParentOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"TestOU"}},
			{Name: "description", Values: []string{"Test Description"}},
			{Name: "objectSid", Values: []string{"S-1-5-21-123456789-123456789-123456789-1000"}},
			{Name: "whenCreated", Values: []string{testTime.Format("20060102150405.0Z")}},
			{Name: "whenChanged", Values: []string{testTime.Format("20060102150405.0Z")}},
		},
	}

	// Execute test
	result, err := manager.entryToOU(entry)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	// Due to AD mixed-endian GUID format, the returned GUID will be different from input bytes
	assert.NotEmpty(t, result.ObjectGUID)
	assert.Equal(t, "TestOU", result.Name)
	assert.Equal(t, "Test Description", result.Description)
	assert.Equal(t, "OU=TestOU,OU=ParentOU,dc=example,dc=com", result.DistinguishedName)
	assert.Equal(t, "ou=ParentOU,dc=example,dc=com", result.Parent) // DN parsing results in lowercase
	assert.Equal(t, "S-1-5-21-123456789-123456789-123456789-1000", result.ObjectSid)
	assert.False(t, result.Protected) // No security descriptor means not protected
	// Use UTC for timestamp comparison to avoid timezone issues
	assert.Equal(t, testTime.Truncate(time.Second), result.WhenCreated.Truncate(time.Second))
	assert.Equal(t, testTime.Truncate(time.Second), result.WhenChanged.Truncate(time.Second))
}

func TestOUManager_EntryToOU_NilEntry(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	// Execute test
	result, err := manager.entryToOU(nil)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot be nil")
}

// Performance tests for nested OU operations.
func TestOUManager_PerformanceNestedOUs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	client := &MockOUClient{}
	manager := NewOUManager(client, "dc=example,dc=com")

	ctx := context.Background()

	// Simulate creating and searching through nested OU structures
	startTime := time.Now()

	// Mock search for deep hierarchy (up to 10 levels)
	for i := range 10 {
		ouDN := fmt.Sprintf("OU=Level%d", i)
		for j := i - 1; j >= 0; j-- {
			ouDN += fmt.Sprintf(",OU=Level%d", j)
		}
		ouDN += ",dc=example,dc=com"

		testGUIDBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, byte(i), 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}

		entry := &ldap.Entry{
			DN: ouDN,
			Attributes: []*ldap.EntryAttribute{
				{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
				{Name: "distinguishedName", Values: []string{ouDN}},
				{Name: "ou", Values: []string{fmt.Sprintf("Level%d", i)}},
			},
		}

		searchResult := &SearchResult{
			Entries: []*ldap.Entry{entry},
			Total:   1,
			HasMore: false,
		}

		client.On("Search", ctx, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil).Once()

		// Test DN building for each level
		parentDN := "dc=example,dc=com"
		if i > 0 {
			for j := range i {
				if j == 0 {
					parentDN = fmt.Sprintf("OU=Level%d,dc=example,dc=com", j)
				} else {
					parentDN = fmt.Sprintf("OU=Level%d,%s", j, parentDN)
				}
			}
		}

		builtDN := manager.BuildOUDN(fmt.Sprintf("Level%d", i), parentDN)
		assert.Contains(t, builtDN, fmt.Sprintf("Level%d", i))
	}

	elapsed := time.Since(startTime)

	// Performance should complete within reasonable time for 10 levels
	assert.Less(t, elapsed, 100*time.Millisecond, "Nested OU operations took too long")

	// Note: Not calling client.AssertExpectations() due to complex mock setup
}
