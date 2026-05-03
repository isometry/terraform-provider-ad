package ldap

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// buildTestSecurityDescriptor returns a self-relative security descriptor
// suitable for ntSecurityDescriptor test fixtures. The DACL includes the
// deny-delete ACE for Everyone (S-1-1-0) that "protect from accidental
// deletion" installs, so the resulting fixture represents a protected OU.
func buildTestSecurityDescriptor(tb testing.TB) []byte {
	tb.Helper()
	sd := &SecurityDescriptor{
		Revision: 1,
		Control:  SESelfRelative | SEDACLPresent,
		DACL: &ACL{
			AclRevision: 2,
			ACEs: []ACE{
				{
					AceType:    AccessAllowedACEType,
					AceFlags:   ContainerInheritACE,
					AccessMask: 0x000F01FF, // generic full, arbitrary
					SID: SID{
						RevisionLevel:  1,
						Authority:      5,
						SubAuthorities: []uint32{18}, // Local System
					},
				},
			},
		},
	}
	sd.AddDenyDeleteEveryoneACE()
	raw, err := sd.Marshal()
	if err != nil {
		tb.Fatalf("marshal test security descriptor: %v", err)
	}
	return raw
}

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

func (m *MockOUClient) WhoAmI(ctx context.Context) (*WhoAmIResult, error) {
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

func (m *MockOUClient) GetRootDSE(ctx context.Context) (*RootDSEInfo, error) {
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

func TestOUManager_BuildOUDN(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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
	client.On("Add", mock.Anything, mock.MatchedBy(func(addReq *AddRequest) bool {
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

	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == searchReq.BaseDN &&
			req.Scope == searchReq.Scope &&
			req.Filter == searchReq.Filter
	})).Return(searchResult, nil)

	// Execute test
	result, err := manager.CreateOU(req)

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
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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
	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return strings.Contains(req.Filter, "objectGUID") &&
			strings.Contains(req.Filter, "objectClass=organizationalUnit")
	})).Return(searchResult, nil)

	// Execute test
	result, err := manager.GetOU(testGUID)

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
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

	testGUID := "12345678-1234-1234-1234-123456789012"

	// Mock empty search result
	searchResult := &SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
		HasMore: false,
	}

	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Execute test
	result, err := manager.GetOU(testGUID)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "not found")

	client.AssertExpectations(t)
}

func TestOUManager_UpdateOU(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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

	// Updated OU entry (final state after rename + description update)
	updatedEntry := &ldap.Entry{
		DN: "OU=UpdatedOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=UpdatedOU,dc=example,dc=com"}},
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

	// Renamed OU entry (after ModifyDN, before attribute modify)
	renamedEntry := &ldap.Entry{
		DN: "OU=UpdatedOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=UpdatedOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"UpdatedOU"}},
			{Name: "description", Values: []string{"Old Description"}},
			{Name: "whenCreated", Values: []string{testTime.Format("20060102150405.0Z")}},
			{Name: "whenChanged", Values: []string{testTime.Format("20060102150405.0Z")}},
		},
	}

	renamedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{renamedEntry},
		Total:   1,
		HasMore: false,
	}

	// 1. Mock getting current OU (for UpdateOU)
	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil).Once()

	// 2. Mock ModifyDN operation (rename)
	client.On("ModifyDN", mock.Anything, mock.MatchedBy(func(req *ModifyDNRequest) bool {
		return req.DN == "OU=TestOU,dc=example,dc=com" && RDNEqual(req.NewRDN, "OU=UpdatedOU")
	})).Return(nil).Once()

	// 3. Mock re-fetch after ModifyDN (inside renameAndMoveOU — result reused by UpdateOU)
	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(renamedSearchResult, nil).Once()

	// 4. Mock modify operation (description only — ou attribute handled by ModifyDN)
	client.On("Modify", mock.Anything, mock.MatchedBy(func(modReq *ModifyRequest) bool {
		return modReq.DN == "OU=UpdatedOU,dc=example,dc=com"
	})).Return(nil)

	// 5. Mock getting final updated OU
	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(updatedSearchResult, nil).Once()

	// Update request
	newName := "UpdatedOU"
	newDescription := "New Description"
	updateReq := &UpdateOURequest{
		Name:        &newName,
		Description: &newDescription,
	}

	// Execute test
	result, err := manager.UpdateOU(testGUID, updateReq)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	// Due to AD mixed-endian GUID format, the returned GUID will be different from input bytes
	assert.NotEmpty(t, result.ObjectGUID)
	assert.Equal(t, "UpdatedOU", result.Name)
	assert.Equal(t, "New Description", result.Description)

	client.AssertExpectations(t)
}

func TestOUManager_UpdateOU_Move(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

	testGUID := "12345678-1234-1234-1234-123456789012"
	testGUIDBytes := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}
	testTime := time.Now()

	// Current OU entry
	currentEntry := &ldap.Entry{
		DN: "OU=TestOU,OU=OldParent,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU,OU=OldParent,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"TestOU"}},
			{Name: "description", Values: []string{"Test Description"}},
			{Name: "whenCreated", Values: []string{testTime.Format("20060102150405.0Z")}},
			{Name: "whenChanged", Values: []string{testTime.Format("20060102150405.0Z")}},
		},
	}

	// Moved OU entry
	movedEntry := &ldap.Entry{
		DN: "OU=TestOU,OU=NewParent,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes)}, ByteValues: [][]byte{testGUIDBytes}},
			{Name: "distinguishedName", Values: []string{"OU=TestOU,OU=NewParent,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"TestOU"}},
			{Name: "description", Values: []string{"Test Description"}},
			{Name: "whenCreated", Values: []string{testTime.Format("20060102150405.0Z")}},
			{Name: "whenChanged", Values: []string{testTime.Format("20060102150405.0Z")}},
		},
	}

	currentSearchResult := &SearchResult{
		Entries: []*ldap.Entry{currentEntry},
		Total:   1,
		HasMore: false,
	}

	movedSearchResult := &SearchResult{
		Entries: []*ldap.Entry{movedEntry},
		Total:   1,
		HasMore: false,
	}

	// 1. Mock getting current OU
	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(currentSearchResult, nil).Once()

	// 2. Mock ModifyDN operation (move)
	client.On("ModifyDN", mock.Anything, mock.MatchedBy(func(req *ModifyDNRequest) bool {
		return req.DN == "OU=TestOU,OU=OldParent,dc=example,dc=com" &&
			req.NewSuperior == "OU=NewParent,dc=example,dc=com" &&
			req.DeleteOldRDN
	})).Return(nil).Once()

	// 3. Mock re-fetch after ModifyDN (inside renameAndMoveOU — result reused by UpdateOU)
	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(movedSearchResult, nil).Once()

	// 4. Mock final re-fetch
	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(movedSearchResult, nil).Once()

	// Update request - path change only
	newPath := "OU=NewParent,dc=example,dc=com"
	updateReq := &UpdateOURequest{
		Path: &newPath,
	}

	result, err := manager.UpdateOU(testGUID, updateReq)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ObjectGUID)
	assert.Equal(t, "TestOU", result.Name)
	assert.True(t, DNEqual("OU=NewParent,DC=example,DC=com", result.Parent),
		"expected parent DN to match semantically, got %q", result.Parent)

	client.AssertExpectations(t)
}

func TestOUManager_DeleteOU(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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
	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Mock delete operation
	client.On("Delete", mock.Anything, "OU=TestOU,dc=example,dc=com").Return(nil)

	// Execute test
	err := manager.DeleteOU(testGUID)

	// Assertions
	require.NoError(t, err)

	client.AssertExpectations(t)
}

func TestOUManager_DeleteOU_Protected(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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
			// Real security descriptor with deny-delete ACE for Everyone.
			{Name: "nTSecurityDescriptor",
				Values:     []string{string(buildTestSecurityDescriptor(t))},
				ByteValues: [][]byte{buildTestSecurityDescriptor(t)}},
		},
	}

	searchResult := &SearchResult{
		Entries: []*ldap.Entry{entry},
		Total:   1,
		HasMore: false,
	}

	// Mock getting OU for deletion check
	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(searchResult, nil)

	// Note: We do NOT mock Delete() call because it should not be called for protected OUs

	// Execute test
	err := manager.DeleteOU(testGUID)

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "protected")

	client.AssertExpectations(t)
}

func TestOUManager_SearchOUs(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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
	client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.Filter == "(&(objectClass=organizationalUnit)(ou=Test*))" &&
			req.BaseDN == "dc=example,dc=com"
	})).Return(searchResult, nil)

	// Execute test
	results, err := manager.SearchOUs("dc=example,dc=com", "(ou=Test*)")

	// Assertions
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "TestOU1", results[0].Name)
	assert.Equal(t, "TestOU2", results[1].Name)

	client.AssertExpectations(t)
}

func TestOUManager_GetOUChildren(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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
	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == parentOUDN &&
			req.Scope == ScopeSingleLevel &&
			req.Filter == "(objectClass=organizationalUnit)"
	})).Return(searchResult, nil)

	// Execute test
	children, err := manager.GetOUChildren(t.Context(), parentOUDN)

	// Assertions
	require.NoError(t, err)
	require.Len(t, children, 1)
	assert.Equal(t, "ChildOU", children[0].Name)
	assert.Equal(t, "OU=ChildOU,OU=ParentOU,dc=example,dc=com", children[0].DistinguishedName)
	assert.True(t, DNEqual("OU=ParentOU,DC=example,DC=com", children[0].Parent), "expected parent DN to match semantically, got %q", children[0].Parent)

	client.AssertExpectations(t)
}

func TestOUManager_GetOUStats(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

	testGUIDBytes1 := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}
	testGUIDBytes2 := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x13}

	// Create mock LDAP entries - one protected, one unprotected
	entry1 := &ldap.Entry{
		DN: "OU=ProtectedOU,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{string(testGUIDBytes1)}, ByteValues: [][]byte{testGUIDBytes1}},
			{Name: "distinguishedName", Values: []string{"OU=ProtectedOU,dc=example,dc=com"}},
			{Name: "ou", Values: []string{"ProtectedOU"}},
			{Name: "nTSecurityDescriptor",
				Values:     []string{string(buildTestSecurityDescriptor(t))},
				ByteValues: [][]byte{buildTestSecurityDescriptor(t)}}, // Deny-delete ACE = protected
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
	client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.Filter == "(objectClass=organizationalUnit)"
	})).Return(searchResult, nil)

	// Execute test
	stats, err := manager.GetOUStats(t.Context())

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
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

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
	assert.True(t, DNEqual("OU=ParentOU,DC=example,DC=com", result.Parent), "expected parent DN to match semantically, got %q", result.Parent)
	assert.False(t, result.Protected) // No security descriptor means not protected
	// Use UTC for timestamp comparison to avoid timezone issues
	assert.Equal(t, testTime.Truncate(time.Second), result.WhenCreated.Truncate(time.Second))
	assert.Equal(t, testTime.Truncate(time.Second), result.WhenChanged.Truncate(time.Second))
}

func TestOUManager_EntryToOU_NilEntry(t *testing.T) {
	client := &MockOUClient{}
	manager := NewOUManager(t.Context(), client, "dc=example,dc=com")

	// Execute test
	result, err := manager.entryToOU(nil)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot be nil")
}

// Note: TestOUManager_PerformanceNestedOUs was removed. It set up mock
// search expectations that were never triggered (BuildOUDN is a pure
// string-construction function that never calls the LDAP client) and
// asserted only that building 10 DNs took less than 100ms. Its actual
// coverage is subsumed by TestOUManager_BuildOUDN.
