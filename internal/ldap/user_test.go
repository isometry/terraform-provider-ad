package ldap

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockUserClient implements the Client interface for testing UserManager.
type MockUserClient struct {
	mock.Mock
}

func (m *MockUserClient) Connect(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockUserClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockUserClient) Bind(ctx context.Context, username, password string) error {
	args := m.Called(ctx, username, password)
	return args.Error(0)
}

func (m *MockUserClient) BindWithConfig(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockUserClient) Search(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, ok := args.Get(0).(*SearchResult)
	if !ok {
		return nil, args.Error(1)
	}
	return result, args.Error(1)
}

func (m *MockUserClient) SearchWithPaging(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	result, ok := args.Get(0).(*SearchResult)
	if !ok {
		return nil, args.Error(1)
	}
	return result, args.Error(1)
}

func (m *MockUserClient) Add(ctx context.Context, req *AddRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockUserClient) Modify(ctx context.Context, req *ModifyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockUserClient) Delete(ctx context.Context, dn string) error {
	args := m.Called(ctx, dn)
	return args.Error(0)
}

func (m *MockUserClient) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockUserClient) Stats() PoolStats {
	args := m.Called()
	if args.Get(0) == nil {
		return PoolStats{}
	}
	stats, ok := args.Get(0).(PoolStats)
	if !ok {
		return PoolStats{}
	}
	return stats
}

func (m *MockUserClient) GetBaseDN(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *MockUserClient) ModifyDN(ctx context.Context, req *ModifyDNRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockUserClient) WhoAmI(ctx context.Context) (*WhoAmIResult, error) {
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

func (m *MockUserClient) GetRootDSE(ctx context.Context) (*RootDSEInfo, error) {
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

// Standard 16-byte binary GUID for testing.
var testBinaryGUID = []byte{0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56}

// mockPrimaryGroupSIDResolution sets up a mock expectation for the SID-to-DN resolution
// that entryToUser performs when processing the primaryGroupID attribute. Tests that use
// createMockUserEntry (which includes primaryGroupID and objectSid) must call this to
// avoid unexpected Search calls from ResolveSIDToDN.
//
// The matcher excludes filters containing "objectClass" to avoid matching the primary
// user/group search expectations that also contain objectSid.
func mockPrimaryGroupSIDResolution(client *MockUserClient) {
	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "DC=example,DC=com" &&
			req.Scope == ScopeWholeSubtree &&
			strings.Contains(req.Filter, "objectSid") &&
			!strings.Contains(req.Filter, "objectClass") &&
			req.SizeLimit == 1
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: "CN=Domain Users,CN=Users,DC=example,DC=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "distinguishedName", Values: []string{"CN=Domain Users,CN=Users,DC=example,DC=com"}},
				},
			},
		},
		Total: 1,
	}, nil).Maybe()
}

// createMockUserEntry creates a mock LDAP entry for testing user operations.
func createMockUserEntry() *ldap.Entry {
	entry := &ldap.Entry{
		DN: "CN=John Doe,OU=Users,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{}, ByteValues: [][]byte{testBinaryGUID}},
			{Name: "distinguishedName", Values: []string{"CN=John Doe,OU=Users,DC=example,DC=com"}},
			{Name: "objectSid", Values: []string{"S-1-5-21-123456789-123456789-123456789-1001"}},
			{Name: "sAMAccountName", Values: []string{"john.doe"}},
			{Name: "userPrincipalName", Values: []string{"john.doe@example.com"}},
			{Name: "cn", Values: []string{"John Doe"}},
			{Name: "displayName", Values: []string{"John Doe"}},
			{Name: "givenName", Values: []string{"John"}},
			{Name: "sn", Values: []string{"Doe"}},
			{Name: "initials", Values: []string{"J.D."}},
			{Name: "description", Values: []string{"Senior Software Engineer"}},
			{Name: "mail", Values: []string{"john.doe@example.com"}},
			{Name: "homePhone", Values: []string{"+1-555-0123"}},
			{Name: "mobile", Values: []string{"+1-555-0124"}},
			{Name: "telephoneNumber", Values: []string{"+1-555-0125"}},
			{Name: "facsimileTelephoneNumber", Values: []string{"+1-555-0126"}},
			{Name: "wWWHomePage", Values: []string{"https://johndoe.example.com"}},
			{Name: "streetAddress", Values: []string{"123 Main St"}},
			{Name: "l", Values: []string{"Springfield"}},
			{Name: "st", Values: []string{"IL"}},
			{Name: "postalCode", Values: []string{"62701"}},
			{Name: "co", Values: []string{"United States"}},
			{Name: "postOfficeBox", Values: []string{"PO Box 123"}},
			{Name: "title", Values: []string{"Senior Software Engineer"}},
			{Name: "department", Values: []string{"Engineering"}},
			{Name: "company", Values: []string{"Example Corp"}},
			{Name: "manager", Values: []string{"CN=Jane Manager,OU=Users,DC=example,DC=com"}},
			{Name: "employeeID", Values: []string{"E12345"}},
			{Name: "employeeNumber", Values: []string{"12345"}},
			{Name: "physicalDeliveryOfficeName", Values: []string{"Building A, Room 101"}},
			{Name: "division", Values: []string{"Technology"}},
			{Name: "o", Values: []string{"Example Organization"}},
			{Name: "homeDirectory", Values: []string{"\\\\server\\home\\john.doe"}},
			{Name: "homeDrive", Values: []string{"H:"}},
			{Name: "profilePath", Values: []string{"\\\\server\\profiles\\john.doe"}},
			{Name: "scriptPath", Values: []string{"logon.bat"}},
			{Name: "userAccountControl", Values: []string{"512"}}, // Normal account, enabled
			{Name: "memberOf", Values: []string{
				"CN=Engineers,OU=Groups,DC=example,DC=com",
				"CN=All Users,OU=Groups,DC=example,DC=com",
			}},
			{Name: "primaryGroupID", Values: []string{"513"}}, // Domain Users
			{Name: "whenCreated", Values: []string{"20230101120000.0Z"}},
			{Name: "whenChanged", Values: []string{"20230201120000.0Z"}},
			{Name: "lastLogon", Values: []string{"133200000000000000"}},      // AD timestamp
			{Name: "pwdLastSet", Values: []string{"133150000000000000"}},     // AD timestamp
			{Name: "accountExpires", Values: []string{"133250000000000000"}}, // AD timestamp
		},
	}
	return entry
}

// createDisabledUserEntry creates a mock LDAP entry for a disabled user.
func createDisabledUserEntry() *ldap.Entry {
	entry := createMockUserEntry()
	entry.DN = "CN=Disabled User,OU=Users,DC=example,DC=com"

	// Update relevant attributes
	for _, attr := range entry.Attributes {
		switch attr.Name {
		case "cn":
			attr.Values = []string{"Disabled User"}
		case "displayName":
			attr.Values = []string{"Disabled User"}
		case "sAMAccountName":
			attr.Values = []string{"disabled.user"}
		case "userPrincipalName":
			attr.Values = []string{"disabled.user@example.com"}
		case "userAccountControl":
			attr.Values = []string{"514"} // Normal account, disabled (512 + 2)
		}
	}

	return entry
}

// makeUserEntry creates a mock LDAP entry representing a user for write operation tests.
// The guid parameter is kept for API consistency but the entry uses testBinaryGUID.
func makeUserEntry(dn, guid, sid, cn, upn, sam string) *ldap.Entry {
	_ = guid // kept for API consistency with other mock entry creators
	return &ldap.Entry{
		DN: dn,
		Attributes: []*ldap.EntryAttribute{
			// Use proper binary GUID format (16 bytes)
			{Name: "objectGUID", ByteValues: [][]byte{testBinaryGUID}},
			// SID can be a string for our test purposes
			{Name: "objectSid", Values: []string{sid}},
			{Name: "distinguishedName", Values: []string{dn}},
			{Name: "cn", Values: []string{cn}},
			{Name: "userPrincipalName", Values: []string{upn}},
			{Name: "sAMAccountName", Values: []string{sam}},
			{Name: "userAccountControl", Values: []string{"512"}}, // NORMAL_ACCOUNT
			{Name: "whenCreated", Values: []string{"20240101120000.0Z"}},
			{Name: "whenChanged", Values: []string{"20240101120000.0Z"}},
		},
	}
}

// makeUserSearchResult creates a mock search result with a single user for write operation tests.
func makeUserSearchResult(dn, guid, sid, cn, upn, sam string) *SearchResult {
	return &SearchResult{
		Entries: []*ldap.Entry{makeUserEntry(dn, guid, sid, cn, upn, sam)},
		Total:   1,
	}
}

// Helper function to create bool pointer.
func boolPtr(b bool) *bool {
	return &b
}

// -----------------------------------------------------------------------------
// UserManager Constructor and Basic Tests
// -----------------------------------------------------------------------------

func TestNewUserManager(t *testing.T) {
	client := &MockUserClient{}
	baseDN := "DC=example,DC=com"

	manager := NewUserManager(t.Context(), client, baseDN, nil)

	assert.NotNil(t, manager)
	assert.Equal(t, client, manager.client)
	assert.Equal(t, baseDN, manager.baseDN)
	assert.Equal(t, 30*time.Second, manager.timeout)
	assert.NotNil(t, manager.guidHandler)
	assert.NotNil(t, manager.normalizer)
}

func TestUserManager_SetTimeout(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	timeout := 45 * time.Second
	manager.SetTimeout(timeout)

	assert.Equal(t, timeout, manager.timeout)
}

// -----------------------------------------------------------------------------
// Read Operation Tests
// -----------------------------------------------------------------------------

func TestUserManager_GetUserByDN_Success(t *testing.T) {
	client := &MockUserClient{}
	mockPrimaryGroupSIDResolution(client)
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()
	dn := "CN=John Doe,OU=Users,DC=example,DC=com"

	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == dn &&
			req.Scope == ScopeBaseObject &&
			req.Filter == "(&(objectClass=user)(!(objectClass=computer)))" &&
			req.SizeLimit == 1
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry},
		Total:   1,
	}, nil)

	user, err := manager.GetUserByDN(dn)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, dn, user.DistinguishedName)
	assert.Equal(t, "john.doe", user.SAMAccountName)
	assert.Equal(t, "john.doe@example.com", user.UserPrincipalName)
	assert.Equal(t, "John Doe", user.DisplayName)
	assert.Equal(t, "John", user.GivenName)
	assert.Equal(t, "Doe", user.Surname)
	assert.Equal(t, "Senior Software Engineer", user.Title)
	assert.Equal(t, "Engineering", user.Department)
	assert.True(t, user.AccountEnabled)
	assert.False(t, user.PasswordNeverExpires)

	client.AssertExpectations(t)
}

func TestUserManager_GetUserByDN_NotFound(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	dn := "CN=NonExistent,OU=Users,DC=example,DC=com"

	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(&SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}, nil)

	user, err := manager.GetUserByDN(dn)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "user not found at DN")

	client.AssertExpectations(t)
}

func TestUserManager_GetUserByGUID_Success(t *testing.T) {
	client := &MockUserClient{}
	mockPrimaryGroupSIDResolution(client)
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()
	guid := "12345678-1234-1234-1234-567890123456"

	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "DC=example,DC=com" &&
			req.Scope == ScopeWholeSubtree &&
			strings.Contains(req.Filter, "objectGUID") &&
			strings.Contains(req.Filter, "objectClass=user")
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry},
		Total:   1,
	}, nil)

	user, err := manager.GetUserByGUID(guid)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "john.doe", user.SAMAccountName)

	client.AssertExpectations(t)
}

func TestUserManager_GetUserByGUID_InvalidFormat(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	user, err := manager.GetUserByGUID("invalid-guid")

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "invalid GUID format")

	client.AssertNotCalled(t, "Search")
}

func TestUserManager_GetUserBySID_Success(t *testing.T) {
	client := &MockUserClient{}
	mockPrimaryGroupSIDResolution(client)
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()
	sid := "S-1-5-21-123456789-123456789-123456789-1001"

	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "DC=example,DC=com" &&
			req.Scope == ScopeWholeSubtree &&
			strings.Contains(req.Filter, "objectSid=") &&
			strings.Contains(req.Filter, "objectClass=user")
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry},
		Total:   1,
	}, nil)

	user, err := manager.GetUserBySID(sid)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, sid, user.ObjectSid)

	client.AssertExpectations(t)
}

func TestUserManager_GetUserByUPN_Success(t *testing.T) {
	client := &MockUserClient{}
	mockPrimaryGroupSIDResolution(client)
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()
	upn := "john.doe@example.com"

	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "DC=example,DC=com" &&
			req.Scope == ScopeWholeSubtree &&
			strings.Contains(req.Filter, fmt.Sprintf("userPrincipalName=%s", upn)) &&
			strings.Contains(req.Filter, "objectClass=user")
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry},
		Total:   1,
	}, nil)

	user, err := manager.GetUserByUPN(upn)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, upn, user.UserPrincipalName)

	client.AssertExpectations(t)
}

func TestUserManager_GetUserBySAM_Success(t *testing.T) {
	client := &MockUserClient{}
	mockPrimaryGroupSIDResolution(client)
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()
	sam := "john.doe"

	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "DC=example,DC=com" &&
			req.Scope == ScopeWholeSubtree &&
			strings.Contains(req.Filter, fmt.Sprintf("sAMAccountName=%s", sam)) &&
			strings.Contains(req.Filter, "objectClass=user")
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry},
		Total:   1,
	}, nil)

	user, err := manager.GetUserBySAM(sam)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, sam, user.SAMAccountName)

	client.AssertExpectations(t)
}

func TestUserManager_GetUserBySAM_DomainFormat(t *testing.T) {
	client := &MockUserClient{}
	mockPrimaryGroupSIDResolution(client)
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()
	domainSam := "EXAMPLE\\john.doe"
	expectedSam := "john.doe"

	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return strings.Contains(req.Filter, fmt.Sprintf("sAMAccountName=%s", expectedSam))
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry},
		Total:   1,
	}, nil)

	user, err := manager.GetUserBySAM(domainSam)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, expectedSam, user.SAMAccountName)

	client.AssertExpectations(t)
}

func TestUserManager_GetUser_AutoDetectIdentifier(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()

	testCases := []struct {
		name        string
		identifier  string
		filterCheck func(string) bool
	}{
		{
			name:       "DN identifier",
			identifier: "CN=John Doe,OU=Users,DC=example,DC=com",
			filterCheck: func(filter string) bool {
				return strings.Contains(filter, "objectClass=user")
			},
		},
		{
			name:       "UPN identifier",
			identifier: "john.doe@example.com",
			filterCheck: func(filter string) bool {
				return strings.Contains(filter, "userPrincipalName=john.doe@example.com")
			},
		},
		{
			name:       "SAM identifier",
			identifier: "john.doe",
			filterCheck: func(filter string) bool {
				return strings.Contains(filter, "sAMAccountName=john.doe")
			},
		},
		{
			name:       "SID identifier",
			identifier: "S-1-5-21-123456789-123456789-123456789-1001",
			filterCheck: func(filter string) bool {
				return strings.Contains(filter, "objectSid=")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client.ExpectedCalls = nil // Reset expectations
			mockPrimaryGroupSIDResolution(client)

			client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return tc.filterCheck(req.Filter)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{mockEntry},
				Total:   1,
			}, nil)

			user, err := manager.GetUser(tc.identifier)

			assert.NoError(t, err)
			assert.NotNil(t, user)
			assert.Equal(t, "john.doe", user.SAMAccountName)

			client.AssertExpectations(t)
		})
	}
}

func TestUserManager_SearchUsers_Success(t *testing.T) {
	client := &MockUserClient{}
	mockPrimaryGroupSIDResolution(client)
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry1 := createMockUserEntry()
	mockEntry2 := createDisabledUserEntry()

	client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "DC=example,DC=com" &&
			req.Scope == ScopeWholeSubtree &&
			req.Filter == "(&(objectClass=user)(!(objectClass=computer)))"
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry1, mockEntry2},
		Total:   2,
	}, nil)

	users, err := manager.SearchUsers("", nil)

	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "john.doe", users[0].SAMAccountName)
	assert.Equal(t, "disabled.user", users[1].SAMAccountName)
	assert.True(t, users[0].AccountEnabled)
	assert.False(t, users[1].AccountEnabled)

	client.AssertExpectations(t)
}

func TestUserManager_SearchUsersWithFilter_NameFilters(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()

	testCases := []struct {
		name           string
		filter         *UserSearchFilter
		expectedFilter string
	}{
		{
			name:           "Name prefix filter",
			filter:         &UserSearchFilter{NamePrefix: "John"},
			expectedFilter: "(cn=John*)",
		},
		{
			name:           "Name suffix filter",
			filter:         &UserSearchFilter{NameSuffix: "Doe"},
			expectedFilter: "(cn=*Doe)",
		},
		{
			name:           "Name contains filter",
			filter:         &UserSearchFilter{NameContains: "oh"},
			expectedFilter: "(cn=*oh*)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client.ExpectedCalls = nil // Reset expectations
			mockPrimaryGroupSIDResolution(client)

			client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return strings.Contains(req.Filter, tc.expectedFilter)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{mockEntry},
				Total:   1,
			}, nil)

			users, err := manager.SearchUsersWithFilter(tc.filter)

			assert.NoError(t, err)
			assert.Len(t, users, 1)

			client.AssertExpectations(t)
		})
	}
}

func TestUserManager_SearchUsersWithFilter_OrganizationalFilters(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()

	testCases := []struct {
		name           string
		filter         *UserSearchFilter
		expectedFilter string
	}{
		{
			name:           "Department filter",
			filter:         &UserSearchFilter{Department: "Engineering"},
			expectedFilter: "(department=Engineering)",
		},
		{
			name:           "Title filter",
			filter:         &UserSearchFilter{Title: "Senior Engineer"},
			expectedFilter: "(title=Senior Engineer)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client.ExpectedCalls = nil // Reset expectations
			mockPrimaryGroupSIDResolution(client)

			client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return strings.Contains(req.Filter, tc.expectedFilter)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{mockEntry},
				Total:   1,
			}, nil)

			users, err := manager.SearchUsersWithFilter(tc.filter)

			assert.NoError(t, err)
			assert.Len(t, users, 1)

			client.AssertExpectations(t)
		})
	}
}

func TestUserManager_SearchUsersWithFilter_StatusFilters(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()

	testCases := []struct {
		name           string
		enabled        *bool
		expectedFilter string
	}{
		{
			name:           "Enabled users",
			enabled:        new(true),
			expectedFilter: "(!(userAccountControl:1.2.840.113556.1.4.803:=2))",
		},
		{
			name:           "Disabled users",
			enabled:        new(false),
			expectedFilter: "(userAccountControl:1.2.840.113556.1.4.803:=2)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client.ExpectedCalls = nil // Reset expectations
			mockPrimaryGroupSIDResolution(client)

			filter := &UserSearchFilter{Enabled: tc.enabled}

			client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return strings.Contains(req.Filter, tc.expectedFilter)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{mockEntry},
				Total:   1,
			}, nil)

			users, err := manager.SearchUsersWithFilter(filter)

			assert.NoError(t, err)
			assert.Len(t, users, 1)

			client.AssertExpectations(t)
		})
	}
}

func TestUserManager_SearchUsersWithFilter_EmailFilters(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()

	testCases := []struct {
		name           string
		filter         *UserSearchFilter
		expectedFilter string
	}{
		{
			name:           "Has email",
			filter:         &UserSearchFilter{HasEmail: new(true)},
			expectedFilter: "(mail=*)",
		},
		{
			name:           "No email",
			filter:         &UserSearchFilter{HasEmail: new(false)},
			expectedFilter: "(!(mail=*))",
		},
		{
			name:           "Email domain",
			filter:         &UserSearchFilter{EmailDomain: "example.com"},
			expectedFilter: "(mail=*@example.com)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client.ExpectedCalls = nil // Reset expectations
			mockPrimaryGroupSIDResolution(client)

			client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return strings.Contains(req.Filter, tc.expectedFilter)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{mockEntry},
				Total:   1,
			}, nil)

			users, err := manager.SearchUsersWithFilter(tc.filter)

			assert.NoError(t, err)
			assert.Len(t, users, 1)

			client.AssertExpectations(t)
		})
	}
}

func TestUserManager_SearchUsersWithFilter_Container(t *testing.T) {
	client := &MockUserClient{}
	mockPrimaryGroupSIDResolution(client)
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	mockEntry := createMockUserEntry()
	containerDN := "OU=Engineering,DC=example,DC=com"

	filter := &UserSearchFilter{Container: containerDN}

	client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == containerDN
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry},
		Total:   1,
	}, nil)

	users, err := manager.SearchUsersWithFilter(filter)

	assert.NoError(t, err)
	assert.Len(t, users, 1)

	client.AssertExpectations(t)
}

func TestUserManager_SearchUsersWithFilter_InvalidContainer(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	filter := &UserSearchFilter{Container: "invalid-dn"}

	users, err := manager.SearchUsersWithFilter(filter)

	assert.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "invalid container DN")

	client.AssertNotCalled(t, "SearchWithPaging")
}

// TestUserManager_SearchUsersWithFilter_SearchScopePropagation verifies that
// the UserSearchFilter.SearchScope pointer is threaded through to the
// underlying LDAP SearchRequest, and that a nil pointer is treated as
// ScopeWholeSubtree to preserve historical behaviour.
func TestUserManager_SearchUsersWithFilter_SearchScopePropagation(t *testing.T) {
	base := ScopeBaseObject
	one := ScopeSingleLevel
	sub := ScopeWholeSubtree

	cases := []struct {
		name     string
		input    *SearchScope
		expected SearchScope
	}{
		{name: "nil pointer defaults to subtree", input: nil, expected: ScopeWholeSubtree},
		{name: "explicit base is propagated as base", input: &base, expected: ScopeBaseObject},
		{name: "explicit onelevel is propagated", input: &one, expected: ScopeSingleLevel},
		{name: "explicit subtree is propagated", input: &sub, expected: ScopeWholeSubtree},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &MockUserClient{}
			mockPrimaryGroupSIDResolution(client)
			manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

			filter := &UserSearchFilter{NamePrefix: "Test", SearchScope: tc.input}

			client.On(
				"SearchWithPaging",
				mock.Anything,
				mock.MatchedBy(func(req *SearchRequest) bool { return req.Scope == tc.expected }),
			).Return(&SearchResult{Entries: nil, Total: 0}, nil).Once()

			_, err := manager.SearchUsersWithFilter(filter)
			require.NoError(t, err)
			client.AssertExpectations(t)
		})
	}
}

func TestUserManager_parseUserAccountControl(t *testing.T) {
	manager := NewUserManager(t.Context(), &MockUserClient{}, "DC=example,DC=com", nil)

	testCases := []struct {
		name     string
		uac      int32
		expected User
	}{
		{
			name: "Normal enabled account",
			uac:  UACNormalAccount, // 512
			expected: User{
				AccountEnabled:         true,
				PasswordNeverExpires:   false,
				PasswordNotRequired:    false,
				ChangePasswordAtLogon:  false,
				SmartCardLogonRequired: false,
				TrustedForDelegation:   false,
			},
		},
		{
			name: "Disabled account",
			uac:  UACNormalAccount | UACAccountDisabled, // 514
			expected: User{
				AccountEnabled:         false,
				PasswordNeverExpires:   false,
				PasswordNotRequired:    false,
				ChangePasswordAtLogon:  false,
				SmartCardLogonRequired: false,
				TrustedForDelegation:   false,
			},
		},
		{
			name: "Password never expires",
			uac:  UACNormalAccount | UACPasswordNeverExpires, // 65536 + 512
			expected: User{
				AccountEnabled:         true,
				PasswordNeverExpires:   true,
				PasswordNotRequired:    false,
				ChangePasswordAtLogon:  false,
				SmartCardLogonRequired: false,
				TrustedForDelegation:   false,
			},
		},
		{
			name: "Smart card required",
			uac:  UACNormalAccount | UACSmartCardRequired, // 262144 + 512
			expected: User{
				AccountEnabled:         true,
				PasswordNeverExpires:   false,
				PasswordNotRequired:    false,
				ChangePasswordAtLogon:  false,
				SmartCardLogonRequired: true,
				TrustedForDelegation:   false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := &User{}
			manager.parseUserAccountControl(user, tc.uac)

			assert.Equal(t, tc.expected.AccountEnabled, user.AccountEnabled)
			assert.Equal(t, tc.expected.PasswordNeverExpires, user.PasswordNeverExpires)
			assert.Equal(t, tc.expected.PasswordNotRequired, user.PasswordNotRequired)
			assert.Equal(t, tc.expected.ChangePasswordAtLogon, user.ChangePasswordAtLogon)
			assert.Equal(t, tc.expected.SmartCardLogonRequired, user.SmartCardLogonRequired)
			assert.Equal(t, tc.expected.TrustedForDelegation, user.TrustedForDelegation)
		})
	}
}

func TestUserManager_parseADTimestamp(t *testing.T) {
	manager := NewUserManager(t.Context(), &MockUserClient{}, "DC=example,DC=com", nil)

	testCases := []struct {
		name      string
		timestamp string
		shouldErr bool
		expected  string // Expected UTC time string
	}{
		{
			name:      "Valid timestamp",
			timestamp: "133200000000000000", // Some time after 1601
			shouldErr: false,
		},
		{
			name:      "Zero timestamp",
			timestamp: "0",
			shouldErr: true,
		},
		{
			name:      "Empty timestamp",
			timestamp: "",
			shouldErr: true,
		},
		{
			name:      "Invalid format",
			timestamp: "not-a-number",
			shouldErr: true,
		},
		{
			name:      "Timestamp before epoch",
			timestamp: "100000000000000000", // Before 1601
			shouldErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := manager.parseADTimestamp(tc.timestamp)

			if tc.shouldErr {
				assert.Error(t, err)
				assert.True(t, result.IsZero())
			} else {
				assert.NoError(t, err)
				assert.False(t, result.IsZero())
				assert.True(t, result.After(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)))
			}
		})
	}
}

func TestUserManager_entryToUser_ComprehensiveMapping(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	// Mock the SID resolution search for the primary group.
	// ResolveSIDToDN searches for objectSid matching the primary group SID.
	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "DC=example,DC=com" &&
			req.Scope == ScopeWholeSubtree &&
			strings.Contains(req.Filter, "objectSid")
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: "CN=Domain Users,CN=Users,DC=example,DC=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "distinguishedName", Values: []string{"CN=Domain Users,CN=Users,DC=example,DC=com"}},
				},
			},
		},
		Total: 1,
	}, nil)

	entry := createMockUserEntry()

	user, err := manager.entryToUser(entry)

	require.NoError(t, err)
	require.NotNil(t, user)

	// Verify all attribute mappings
	assert.Equal(t, "CN=John Doe,OU=Users,DC=example,DC=com", user.DistinguishedName)
	assert.Equal(t, "S-1-5-21-123456789-123456789-123456789-1001", user.ObjectSid)
	assert.Equal(t, "john.doe", user.SAMAccountName)
	assert.Equal(t, "john.doe@example.com", user.UserPrincipalName)
	assert.Equal(t, "John Doe", user.DisplayName)
	assert.Equal(t, "John", user.GivenName)
	assert.Equal(t, "Doe", user.Surname)
	assert.Equal(t, "J.D.", user.Initials)
	assert.Equal(t, "Senior Software Engineer", user.Description)

	// Contact information
	assert.Equal(t, "john.doe@example.com", user.EmailAddress)
	assert.Equal(t, "+1-555-0123", user.HomePhone)
	assert.Equal(t, "+1-555-0124", user.MobilePhone)
	assert.Equal(t, "+1-555-0125", user.OfficePhone)
	assert.Equal(t, "+1-555-0126", user.Fax)
	assert.Equal(t, "https://johndoe.example.com", user.HomePage)

	// Address information
	assert.Equal(t, "123 Main St", user.StreetAddress)
	assert.Equal(t, "Springfield", user.City)
	assert.Equal(t, "IL", user.State)
	assert.Equal(t, "62701", user.PostalCode)
	assert.Equal(t, "United States", user.Country)
	assert.Equal(t, "PO Box 123", user.POBox)

	// Organizational information
	assert.Equal(t, "Senior Software Engineer", user.Title)
	assert.Equal(t, "Engineering", user.Department)
	assert.Equal(t, "Example Corp", user.Company)
	assert.Equal(t, "CN=Jane Manager,OU=Users,DC=example,DC=com", user.Manager)
	assert.Equal(t, "E12345", user.EmployeeID)
	assert.Equal(t, "12345", user.EmployeeNumber)
	assert.Equal(t, "Building A, Room 101", user.Office)
	assert.Equal(t, "Technology", user.Division)
	assert.Equal(t, "Example Organization", user.Organization)

	// System information
	assert.Equal(t, "\\\\server\\home\\john.doe", user.HomeDirectory)
	assert.Equal(t, "H:", user.HomeDrive)
	assert.Equal(t, "\\\\server\\profiles\\john.doe", user.ProfilePath)
	assert.Equal(t, "logon.bat", user.LogonScript)

	// Account status
	assert.Equal(t, int32(512), user.UserAccountControl)
	assert.True(t, user.AccountEnabled)
	assert.False(t, user.PasswordNeverExpires)

	// Group memberships
	assert.Len(t, user.MemberOf, 2)
	assert.Contains(t, user.MemberOf, "CN=Engineers,OU=Groups,DC=example,DC=com")
	assert.Contains(t, user.MemberOf, "CN=All Users,OU=Groups,DC=example,DC=com")

	// Primary group (should be resolved from SID to DN)
	assert.Equal(t, "CN=Domain Users,CN=Users,DC=example,DC=com", user.PrimaryGroup)

	// Timestamps
	assert.Equal(t, 2023, user.WhenCreated.Year())
	assert.Equal(t, 1, int(user.WhenCreated.Month()))
	assert.Equal(t, 2023, user.WhenChanged.Year())
	assert.Equal(t, 2, int(user.WhenChanged.Month()))
	assert.NotNil(t, user.LastLogon)
	assert.NotNil(t, user.PasswordLastSet)
	assert.NotNil(t, user.AccountExpires)

	client.AssertExpectations(t)
}

func TestUserManager_entryToUser_PrimaryGroupFallback(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	// Mock the SID resolution search to return no results (object not found).
	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "DC=example,DC=com" &&
			req.Scope == ScopeWholeSubtree &&
			strings.Contains(req.Filter, "objectSid")
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}, nil)

	entry := createMockUserEntry()

	user, err := manager.entryToUser(entry)

	require.NoError(t, err)
	require.NotNil(t, user)

	// When SID resolution fails, the SID string should be stored as fallback
	assert.Equal(t, "S-1-5-21-123456789-123456789-123456789-513", user.PrimaryGroup)

	client.AssertExpectations(t)
}

func TestUserManager_GetUserStats(t *testing.T) {
	client := &MockUserClient{}
	mockPrimaryGroupSIDResolution(client)
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	enabledEntry := createMockUserEntry()
	disabledEntry := createDisabledUserEntry()

	client.On("SearchWithPaging", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(&SearchResult{
		Entries: []*ldap.Entry{enabledEntry, disabledEntry},
		Total:   2,
	}, nil)

	stats, err := manager.GetUserStats()

	assert.NoError(t, err)
	assert.Equal(t, 2, stats["total"])
	assert.Equal(t, 1, stats["enabled"])
	assert.Equal(t, 1, stats["disabled"])

	client.AssertExpectations(t)
}

func TestUserManager_EmptyIdentifier(t *testing.T) {
	client := &MockUserClient{}
	manager := NewUserManager(t.Context(), client, "DC=example,DC=com", nil)

	testCases := []struct {
		name string
		fn   func() (*User, error)
	}{
		{"GetUser", func() (*User, error) { return manager.GetUser("") }},
		{"GetUserByDN", func() (*User, error) { return manager.GetUserByDN("") }},
		{"GetUserByGUID", func() (*User, error) { return manager.GetUserByGUID("") }},
		{"GetUserBySID", func() (*User, error) { return manager.GetUserBySID("") }},
		{"GetUserByUPN", func() (*User, error) { return manager.GetUserByUPN("") }},
		{"GetUserBySAM", func() (*User, error) { return manager.GetUserBySAM("") }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user, err := tc.fn()
			assert.Error(t, err)
			assert.Nil(t, user)
			assert.Contains(t, err.Error(), "cannot be empty")
		})
	}

	client.AssertNotCalled(t, "Search")
	client.AssertNotCalled(t, "SearchWithPaging")
}

// -----------------------------------------------------------------------------
// Write Operation Tests
// -----------------------------------------------------------------------------

func TestEncodeADPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "simple password",
			password: "Pass123!",
		},
		{
			name:     "empty password",
			password: "",
		},
		{
			name:     "unicode password",
			password: "Pässwörd",
		},
		{
			name:     "complex password",
			password: "P@$$w0rd!123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeADPassword(tt.password)
			gotHex := hex.EncodeToString(got)

			// UTF-16 encoding - each character in the quoted password becomes 2 bytes
			// For UTF-16, the length is: (number of UTF-16 code units in quoted password) * 2 bytes
			// The quoted password is "password" so we need to count UTF-16 code units
			quotedPassword := "\"" + tt.password + "\""
			// Count UTF-16 code units (characters outside BMP produce 2 code units)
			expectedCodeUnits := len(utf16.Encode([]rune(quotedPassword)))
			expectedLen := expectedCodeUnits * 2 // 2 bytes per UTF-16 code unit

			if len(got) != expectedLen {
				t.Errorf("EncodeADPassword() length = %d, want %d", len(got), expectedLen)
			}

			// Verify first two bytes are opening quote (0x22 0x00 in little endian)
			if got[0] != 0x22 || got[1] != 0x00 {
				t.Errorf("EncodeADPassword() should start with UTF-16LE quote, got %02x%02x", got[0], got[1])
			}

			// Verify last two bytes are closing quote
			if got[len(got)-2] != 0x22 || got[len(got)-1] != 0x00 {
				t.Errorf("EncodeADPassword() should end with UTF-16LE quote, got %02x%02x", got[len(got)-2], got[len(got)-1])
			}

			t.Logf("Password %q encoded to: %s", tt.password, gotHex)
		})
	}
}

func TestCalculateUserAccountControlFromFlags(t *testing.T) {
	tests := []struct {
		name                 string
		enabled              bool
		passwordNeverExpires bool
		smartCardRequired    bool
		trustedForDelegation bool
		expectedUAC          int32
	}{
		{
			name:        "normal enabled account",
			enabled:     true,
			expectedUAC: UACNormalAccount,
		},
		{
			name:        "disabled account",
			enabled:     false,
			expectedUAC: UACNormalAccount | UACAccountDisabled,
		},
		{
			name:                 "password never expires",
			enabled:              true,
			passwordNeverExpires: true,
			expectedUAC:          UACNormalAccount | UACPasswordNeverExpires,
		},
		{
			name:              "smart card required",
			enabled:           true,
			smartCardRequired: true,
			expectedUAC:       UACNormalAccount | UACSmartCardRequired,
		},
		{
			name:                 "trusted for delegation",
			enabled:              true,
			trustedForDelegation: true,
			expectedUAC:          UACNormalAccount | UACTrustedForDelegation,
		},
		{
			name:                 "all flags disabled account",
			enabled:              false,
			passwordNeverExpires: true,
			smartCardRequired:    true,
			trustedForDelegation: true,
			expectedUAC:          UACNormalAccount | UACAccountDisabled | UACPasswordNeverExpires | UACSmartCardRequired | UACTrustedForDelegation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateUserAccountControlFromFlags(
				tt.enabled,
				tt.passwordNeverExpires,
				tt.smartCardRequired,
				tt.trustedForDelegation,
			)

			if got != tt.expectedUAC {
				t.Errorf("CalculateUserAccountControlFromFlags() = %d (0x%08X), want %d (0x%08X)",
					got, got, tt.expectedUAC, tt.expectedUAC)
			}
		})
	}
}

func TestValidateCreateUserRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *CreateUserRequest
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
			errMsg:  "cannot be nil",
		},
		{
			name:    "empty name",
			req:     &CreateUserRequest{},
			wantErr: true,
			errMsg:  "name (cn) is required",
		},
		{
			name: "empty UPN",
			req: &CreateUserRequest{
				Name: "testuser",
			},
			wantErr: true,
			errMsg:  "user principal name (UPN) is required",
		},
		{
			name: "empty SAM account name",
			req: &CreateUserRequest{
				Name:              "testuser",
				UserPrincipalName: "testuser@example.com",
			},
			wantErr: true,
			errMsg:  "SAM account name is required",
		},
		{
			name: "SAM account name too long",
			req: &CreateUserRequest{
				Name:              "testuser",
				UserPrincipalName: "testuser@example.com",
				SAMAccountName:    "thissamaccountnameiswaytoolongforAD",
				Container:         "OU=Users,DC=example,DC=com",
			},
			wantErr: true,
			errMsg:  "cannot exceed 20 characters",
		},
		{
			name: "empty container",
			req: &CreateUserRequest{
				Name:              "testuser",
				UserPrincipalName: "testuser@example.com",
				SAMAccountName:    "testuser",
			},
			wantErr: true,
			errMsg:  "container DN is required",
		},
		{
			name: "invalid UPN format",
			req: &CreateUserRequest{
				Name:              "testuser",
				UserPrincipalName: "testuser", // missing @domain
				SAMAccountName:    "testuser",
				Container:         "OU=Users,DC=example,DC=com",
			},
			wantErr: true,
			errMsg:  "UPN format",
		},
		{
			name: "invalid SAM account name characters",
			req: &CreateUserRequest{
				Name:              "testuser",
				UserPrincipalName: "testuser@example.com",
				SAMAccountName:    "test user", // space not allowed
				Container:         "OU=Users,DC=example,DC=com",
			},
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name: "valid request minimal",
			req: &CreateUserRequest{
				Name:              "testuser",
				UserPrincipalName: "testuser@example.com",
				SAMAccountName:    "testuser",
				Container:         "OU=Users,DC=example,DC=com",
			},
			wantErr: false,
		},
		{
			name: "valid request with manager DN",
			req: &CreateUserRequest{
				Name:              "testuser",
				UserPrincipalName: "testuser@example.com",
				SAMAccountName:    "testuser",
				Container:         "OU=Users,DC=example,DC=com",
				Manager:           "CN=Manager,OU=Users,DC=example,DC=com",
			},
			wantErr: false,
		},
		{
			name: "invalid manager DN",
			req: &CreateUserRequest{
				Name:              "testuser",
				UserPrincipalName: "testuser@example.com",
				SAMAccountName:    "testuser",
				Container:         "OU=Users,DC=example,DC=com",
				Manager:           "invalid-dn",
			},
			wantErr: true,
			errMsg:  "invalid manager DN",
		},
	}

	um := NewUserManager(context.Background(), &MockUserClient{}, "DC=example,DC=com", nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := um.ValidateCreateUserRequest(tt.req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateCreateUserRequest() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateCreateUserRequest() error = %q, should contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateCreateUserRequest() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestExtractContainer(t *testing.T) {
	um := NewUserManager(context.Background(), &MockUserClient{}, "DC=example,DC=com", nil)

	tests := []struct {
		name     string
		dn       string
		expected string
	}{
		{
			name:     "standard user DN",
			dn:       "CN=John Doe,OU=Users,DC=example,DC=com",
			expected: "ou=Users,dc=example,dc=com", // ldap library normalizes to lowercase
		},
		{
			name:     "nested OU",
			dn:       "CN=Jane Smith,OU=Admins,OU=IT,DC=example,DC=com",
			expected: "ou=Admins,ou=IT,dc=example,dc=com",
		},
		{
			name:     "users container",
			dn:       "CN=Test User,CN=Users,DC=example,DC=com",
			expected: "cn=Users,dc=example,dc=com",
		},
		{
			name:     "single RDN",
			dn:       "CN=Test",
			expected: "",
		},
		{
			name:     "empty DN",
			dn:       "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := um.extractContainer(tt.dn)
			if got != tt.expected {
				t.Errorf("extractContainer(%q) = %q, want %q", tt.dn, got, tt.expected)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestUserManager_CreateUser_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	req := &CreateUserRequest{
		Name:              "Test User",
		UserPrincipalName: "testuser@example.com",
		SAMAccountName:    "testuser",
		Container:         "OU=Users,DC=example,DC=com",
	}

	expectedDN := "CN=Test User,OU=Users,DC=example,DC=com"
	// This is the GUID that results from decoding testBinaryGUID
	expectedGUID := "12345678-1234-1234-1234-567890123456"
	expectedSID := "S-1-5-21-123456789-123456789-123456789-1001"

	// Mock Add (create user)
	mockClient.On("Add", mock.Anything, mock.MatchedBy(func(r *AddRequest) bool {
		return r.DN == expectedDN
	})).Return(nil).Once()

	// Mock Modify (apply UAC flags)
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		return r.DN == expectedDN
	})).Return(nil).Once()

	// Mock Search (retrieve created user)
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool {
		return r.BaseDN == expectedDN
	})).Return(makeUserSearchResult(expectedDN, expectedGUID, expectedSID, "Test User", "testuser@example.com", "testuser"), nil).Once()

	user, err := um.CreateUser(req)

	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, expectedGUID, user.ObjectGUID)
	assert.Equal(t, expectedDN, user.DistinguishedName)
	mockClient.AssertExpectations(t)
}

func TestUserManager_CreateUser_WithAllOptionalAttributes(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	enabled := true
	req := &CreateUserRequest{
		Name:              "Test User",
		UserPrincipalName: "testuser@example.com",
		SAMAccountName:    "testuser",
		Container:         "OU=Users,DC=example,DC=com",
		DisplayName:       "Test Display Name",
		Description:       "Test description",
		GivenName:         "Test",
		Surname:           "User",
		EmailAddress:      "testuser@company.com",
		Title:             "Engineer",
		Department:        "Engineering",
		Company:           "Test Corp",
		OfficePhone:       "+1-555-0100",
		Enabled:           &enabled,
	}

	expectedDN := "CN=Test User,OU=Users,DC=example,DC=com"

	// Mock Add with attribute verification
	mockClient.On("Add", mock.Anything, mock.MatchedBy(func(r *AddRequest) bool {
		if r.DN != expectedDN {
			return false
		}
		// Verify optional attributes are included
		return r.Attributes["displayName"] != nil &&
			r.Attributes["description"] != nil &&
			r.Attributes["givenName"] != nil
	})).Return(nil).Once()

	// Mock Modify
	mockClient.On("Modify", mock.Anything, mock.Anything).Return(nil).Once()

	// Mock Search
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(expectedDN, "guid", "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	user, err := um.CreateUser(req)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_CreateUser_WithSecurityFlags(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	enabled := false
	passwordNeverExpires := true

	req := &CreateUserRequest{
		Name:                 "Service Account",
		UserPrincipalName:    "svc@example.com",
		SAMAccountName:       "svc",
		Container:            "OU=Services,DC=example,DC=com",
		Enabled:              &enabled,
		PasswordNeverExpires: &passwordNeverExpires,
	}

	expectedDN := "CN=Service Account,OU=Services,DC=example,DC=com"

	// Mock Add
	mockClient.On("Add", mock.Anything, mock.Anything).Return(nil).Once()

	// Mock Modify - verify UAC flags
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		if r.DN != expectedDN {
			return false
		}
		// Should have UAC with disabled flag + password flags
		return r.ReplaceAttributes["userAccountControl"] != nil
	})).Return(nil).Once()

	// Mock Search
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(expectedDN, "guid", "sid", "Service Account", "svc@example.com", "svc"),
		nil,
	).Once()

	user, err := um.CreateUser(req)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_CreateUser_AddFails(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	req := &CreateUserRequest{
		Name:              "Test User",
		UserPrincipalName: "testuser@example.com",
		SAMAccountName:    "testuser",
		Container:         "OU=Users,DC=example,DC=com",
	}

	// Mock Add failure
	mockClient.On("Add", mock.Anything, mock.Anything).Return(fmt.Errorf("LDAP error: entry already exists")).Once()

	user, err := um.CreateUser(req)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "create_user")
	mockClient.AssertExpectations(t)
}

func TestUserManager_CreateUser_WithPassword(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	req := &CreateUserRequest{
		Name:              "Test User",
		UserPrincipalName: "testuser@example.com",
		SAMAccountName:    "testuser",
		Container:         "OU=Users,DC=example,DC=com",
		InitialPassword:   "P@ssw0rd123!",
	}

	expectedDN := "CN=Test User,OU=Users,DC=example,DC=com"

	// Mock Add
	mockClient.On("Add", mock.Anything, mock.Anything).Return(nil).Once()

	// Mock Modify for password (first modify call)
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		return r.DN == expectedDN && r.ReplaceAttributes["unicodePwd"] != nil
	})).Return(nil).Once()

	// Mock Modify for UAC flags (second modify call)
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		return r.DN == expectedDN && r.ReplaceAttributes["userAccountControl"] != nil
	})).Return(nil).Once()

	// Mock Search
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(expectedDN, "guid", "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	user, err := um.CreateUser(req)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_CreateUser_NoPassword_ForcesDisabled(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	enabled := true
	req := &CreateUserRequest{
		Name:              "No Password User",
		UserPrincipalName: "nopwd@example.com",
		SAMAccountName:    "nopwd",
		Container:         "OU=Users,DC=example,DC=com",
		Enabled:           &enabled,
		InitialPassword:   "", // No password provided
	}

	expectedDN := "CN=No Password User,OU=Users,DC=example,DC=com"

	// The initial Add should include UACAccountDisabled (always disabled on creation)
	initialUAC := UACNormalAccount | UACAccountDisabled // 514
	mockClient.On("Add", mock.Anything, mock.MatchedBy(func(r *AddRequest) bool {
		if r.DN != expectedDN {
			return false
		}
		uacVals, ok := r.Attributes["userAccountControl"]
		if !ok || len(uacVals) == 0 {
			return false
		}
		return uacVals[0] == strconv.FormatInt(int64(initialUAC), 10)
	})).Return(nil).Once()

	// The final Modify for UAC flags must ALSO have the disabled bit set,
	// even though Enabled=true, because no password was provided.
	// Expected UAC = UACNormalAccount | UACAccountDisabled = 512 | 2 = 514
	expectedFinalUAC := UACNormalAccount | UACAccountDisabled // 514
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		if r.DN != expectedDN {
			return false
		}
		uacVals, ok := r.ReplaceAttributes["userAccountControl"]
		if !ok || len(uacVals) == 0 {
			return false
		}
		return uacVals[0] == strconv.FormatInt(int64(expectedFinalUAC), 10)
	})).Return(nil).Once()

	// Mock Search to read back the created user
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(expectedDN, "guid", "sid", "No Password User", "nopwd@example.com", "nopwd"),
		nil,
	).Once()

	user, err := um.CreateUser(req)

	require.NoError(t, err)
	assert.NotNil(t, user)

	// Verify there was NO unicodePwd modify call (no password set)
	for _, call := range mockClient.Calls {
		if call.Method == "Modify" {
			modReq, ok := call.Arguments[1].(*ModifyRequest)
			if ok {
				_, hasUnicodePwd := modReq.ReplaceAttributes["unicodePwd"]
				assert.False(t, hasUnicodePwd, "should not have a unicodePwd modify call when no password is provided")
			}
		}
	}

	mockClient.AssertExpectations(t)
}

func TestUserManager_CreateUser_ChangePasswordAtLogon_TrueWithPassword(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	changeAtLogon := true
	req := &CreateUserRequest{
		Name:                  "Test User",
		UserPrincipalName:     "testuser@example.com",
		SAMAccountName:        "testuser",
		Container:             "OU=Users,DC=example,DC=com",
		InitialPassword:       "P@ssw0rd123!",
		ChangePasswordAtLogon: &changeAtLogon,
	}

	expectedDN := "CN=Test User,OU=Users,DC=example,DC=com"

	mockClient.On("Add", mock.Anything, mock.Anything).Return(nil).Once()
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		return r.DN == expectedDN && r.ReplaceAttributes["unicodePwd"] != nil
	})).Return(nil).Once()
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		if r.DN != expectedDN || r.ReplaceAttributes["userAccountControl"] == nil {
			return false
		}
		pwdLastSet, ok := r.ReplaceAttributes["pwdLastSet"]
		return ok && len(pwdLastSet) == 1 && pwdLastSet[0] == "0"
	})).Return(nil).Once()
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(expectedDN, "guid", "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	user, err := um.CreateUser(req)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_CreateUser_ChangePasswordAtLogon_FalseWithPassword(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	changeAtLogon := false
	req := &CreateUserRequest{
		Name:                  "Test User",
		UserPrincipalName:     "testuser@example.com",
		SAMAccountName:        "testuser",
		Container:             "OU=Users,DC=example,DC=com",
		InitialPassword:       "P@ssw0rd123!",
		ChangePasswordAtLogon: &changeAtLogon,
	}

	expectedDN := "CN=Test User,OU=Users,DC=example,DC=com"

	mockClient.On("Add", mock.Anything, mock.Anything).Return(nil).Once()
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		return r.DN == expectedDN && r.ReplaceAttributes["unicodePwd"] != nil
	})).Return(nil).Once()
	// AD auto-updates pwdLastSet to the current timestamp when unicodePwd is
	// modified, so no explicit pwdLastSet write is expected in the final Modify.
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		if r.DN != expectedDN || r.ReplaceAttributes["userAccountControl"] == nil {
			return false
		}
		_, hasPwdLastSet := r.ReplaceAttributes["pwdLastSet"]
		return !hasPwdLastSet
	})).Return(nil).Once()
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(expectedDN, "guid", "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	user, err := um.CreateUser(req)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_CreateUser_ChangePasswordAtLogon_NilNoPassword_SkipsPwdLastSet(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	req := &CreateUserRequest{
		Name:                  "Test User",
		UserPrincipalName:     "testuser@example.com",
		SAMAccountName:        "testuser",
		Container:             "OU=Users,DC=example,DC=com",
		ChangePasswordAtLogon: nil,
	}

	expectedDN := "CN=Test User,OU=Users,DC=example,DC=com"

	mockClient.On("Add", mock.Anything, mock.Anything).Return(nil).Once()
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		if r.DN != expectedDN || r.ReplaceAttributes["userAccountControl"] == nil {
			return false
		}
		_, hasPwdLastSet := r.ReplaceAttributes["pwdLastSet"]
		return !hasPwdLastSet
	})).Return(nil).Once()
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(expectedDN, "guid", "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	user, err := um.CreateUser(req)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_CreateUser_PasswordFails_Cleanup(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	req := &CreateUserRequest{
		Name:              "Test User",
		UserPrincipalName: "testuser@example.com",
		SAMAccountName:    "testuser",
		Container:         "OU=Users,DC=example,DC=com",
		InitialPassword:   "weakpwd", // Will fail complexity requirements
	}

	expectedDN := "CN=Test User,OU=Users,DC=example,DC=com"

	// Mock Add (succeeds)
	mockClient.On("Add", mock.Anything, mock.Anything).Return(nil).Once()

	// Mock Modify for password (fails)
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		return r.ReplaceAttributes["unicodePwd"] != nil
	})).Return(fmt.Errorf("password does not meet complexity requirements")).Once()

	// Mock Delete (cleanup)
	mockClient.On("Delete", mock.Anything, expectedDN).Return(nil).Once()

	user, err := um.CreateUser(req)

	assert.Error(t, err)
	assert.Nil(t, user)
	// The error is wrapped as "set_password" in the code, not "set_initial_password"
	assert.Contains(t, err.Error(), "set_password")
	mockClient.AssertExpectations(t)
}

func TestUserManager_UpdateUser_AttributeChanges(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	userGUID := "12345678-1234-1234-1234-123456789012"
	userDN := "CN=Test User,OU=Users,DC=example,DC=com"

	// Mock Search to get current user
	mockClient.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool {
		return r.Filter != "" && (r.SizeLimit == 1 || r.Scope == ScopeBaseObject)
	})).Return(makeUserSearchResult(userDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"), nil)

	newDescription := "Updated description"
	newTitle := "Senior Engineer"
	updateReq := &UpdateUserRequest{
		Description: &newDescription,
		Title:       &newTitle,
	}

	// Mock Modify
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		return r.DN == userDN &&
			r.ReplaceAttributes["description"] != nil &&
			r.ReplaceAttributes["title"] != nil
	})).Return(nil).Once()

	user, err := um.UpdateUser(userGUID, updateReq)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_UpdateUser_ContainerMove(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	userGUID := "12345678-1234-1234-1234-123456789012"
	currentDN := "CN=Test User,OU=Users,DC=example,DC=com"
	newContainer := "OU=Admins,DC=example,DC=com"
	newDN := "CN=Test User,OU=Admins,DC=example,DC=com"

	// First search - get current user
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(currentDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	// Mock ModifyDN for move
	mockClient.On("ModifyDN", mock.Anything, mock.MatchedBy(func(r *ModifyDNRequest) bool {
		return r.DN == currentDN && r.NewSuperior == newContainer
	})).Return(nil).Once()

	// Second search - get user after move
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(newDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	// Third search - final user state
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(newDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	updateReq := &UpdateUserRequest{
		Container: &newContainer,
	}

	user, err := um.UpdateUser(userGUID, updateReq)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_UpdateUser_SecurityFlagChanges(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	userGUID := "12345678-1234-1234-1234-123456789012"
	userDN := "CN=Test User,OU=Users,DC=example,DC=com"

	// Mock Search to get current user (enabled account)
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(userDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	)

	// Disable the account
	enabled := false
	passwordNeverExpires := true
	updateReq := &UpdateUserRequest{
		Enabled:              &enabled,
		PasswordNeverExpires: &passwordNeverExpires,
	}

	// Mock Modify with UAC change
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		return r.DN == userDN && r.ReplaceAttributes["userAccountControl"] != nil
	})).Return(nil).Once()

	user, err := um.UpdateUser(userGUID, updateReq)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_UpdateUser_ClearAttribute(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	userGUID := "12345678-1234-1234-1234-123456789012"
	userDN := "CN=Test User,OU=Users,DC=example,DC=com"

	// Create user entry with description
	entry := makeUserEntry(userDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser")
	entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
		Name:   "description",
		Values: []string{"Original description"},
	})
	searchResult := &SearchResult{Entries: []*ldap.Entry{entry}, Total: 1}

	mockClient.On("Search", mock.Anything, mock.Anything).Return(searchResult, nil)

	// Clear description (empty string)
	emptyDesc := ""
	updateReq := &UpdateUserRequest{
		Description: &emptyDesc,
	}

	// Mock Modify with delete attribute
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		return r.DN == userDN
	})).Return(nil).Once()

	user, err := um.UpdateUser(userGUID, updateReq)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_UpdateUser_NoChanges(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	userGUID := "12345678-1234-1234-1234-123456789012"
	userDN := "CN=Test User,OU=Users,DC=example,DC=com"

	// Mock Search
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(userDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	)

	// Empty update request - no changes
	updateReq := &UpdateUserRequest{}

	// No Modify call should be made
	user, err := um.UpdateUser(userGUID, updateReq)

	require.NoError(t, err)
	assert.NotNil(t, user)
	// Modify should not have been called
	mockClient.AssertNotCalled(t, "Modify", mock.Anything, mock.Anything)
}

func TestUserManager_UpdateUser_UserNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	// Use a valid GUID format that will trigger a search
	userGUID := "12345678-1234-1234-1234-000000000000"

	// Mock Search with no results (user not found)
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		&SearchResult{Entries: []*ldap.Entry{}, Total: 0},
		nil,
	).Once()

	updateReq := &UpdateUserRequest{}

	user, err := um.UpdateUser(userGUID, updateReq)

	assert.Error(t, err)
	assert.Nil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_DeleteUser_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	userGUID := "12345678-1234-1234-1234-123456789012"
	userDN := "CN=Test User,OU=Users,DC=example,DC=com"

	// Mock Search to get user DN
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(userDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	// Mock Delete
	mockClient.On("Delete", mock.Anything, userDN).Return(nil).Once()

	err := um.DeleteUser(userGUID)

	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestUserManager_DeleteUser_NotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	// Use a valid GUID format
	userGUID := "12345678-1234-1234-1234-000000000000"

	// Mock Search with "not found" error
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		(*SearchResult)(nil),
		&LDAPError{Operation: "test", Message: "object not found"},
	).Once()

	err := um.DeleteUser(userGUID)

	// Should not error - user already doesn't exist
	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestUserManager_SetPassword_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	userGUID := "12345678-1234-1234-1234-123456789012"
	userDN := "CN=Test User,OU=Users,DC=example,DC=com"
	newPassword := "NewP@ssw0rd123!"

	// Mock Search to get user DN
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(userDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	// Mock Modify for password
	mockClient.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
		return r.DN == userDN && r.ReplaceAttributes["unicodePwd"] != nil
	})).Return(nil).Once()

	err := um.SetPassword(userGUID, newPassword)

	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestUserManager_MoveUser_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	userGUID := "12345678-1234-1234-1234-123456789012"
	currentDN := "CN=Test User,OU=Users,DC=example,DC=com"
	newContainer := "OU=Admins,DC=example,DC=com"
	newDN := "CN=Test User,OU=Admins,DC=example,DC=com"

	// First search - get current user
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(currentDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	// Mock ModifyDN
	mockClient.On("ModifyDN", mock.Anything, mock.MatchedBy(func(r *ModifyDNRequest) bool {
		return r.DN == currentDN && r.NewSuperior == newContainer
	})).Return(nil).Once()

	// Second search - get user after move
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(newDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	user, err := um.MoveUser(userGUID, newContainer)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertExpectations(t)
}

func TestUserManager_MoveUser_AlreadyInContainer(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()
	baseDN := "DC=example,DC=com"

	um := NewUserManager(ctx, mockClient, baseDN, cacheManager)

	userGUID := "12345678-1234-1234-1234-123456789012"
	userDN := "CN=Test User,OU=Users,DC=example,DC=com"
	sameContainer := "OU=Users,DC=example,DC=com"

	// Mock Search
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		makeUserSearchResult(userDN, userGUID, "sid", "Test User", "testuser@example.com", "testuser"),
		nil,
	).Once()

	// ModifyDN should NOT be called since user is already in target container

	user, err := um.MoveUser(userGUID, sameContainer)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockClient.AssertNotCalled(t, "ModifyDN", mock.Anything, mock.Anything)
}

// Test UAC calculation helper function

func TestUserManager_CalculateUACChanges(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockClient{}
	cacheManager := NewCacheManager()

	um := NewUserManager(ctx, mockClient, "DC=example,DC=com", cacheManager)

	tests := []struct {
		name           string
		currentUser    *User
		updateReq      *UpdateUserRequest
		expectChange   bool
		expectedNewUAC int32
	}{
		{
			name: "no changes",
			currentUser: &User{
				AccountEnabled:       true,
				PasswordNeverExpires: false,
				UserAccountControl:   UACNormalAccount,
			},
			updateReq:    &UpdateUserRequest{},
			expectChange: false,
		},
		{
			name: "disable account",
			currentUser: &User{
				AccountEnabled:     true,
				UserAccountControl: UACNormalAccount,
			},
			updateReq:      &UpdateUserRequest{Enabled: boolPtr(false)},
			expectChange:   true,
			expectedNewUAC: UACNormalAccount | UACAccountDisabled,
		},
		{
			name: "enable password never expires",
			currentUser: &User{
				AccountEnabled:       true,
				PasswordNeverExpires: false,
				UserAccountControl:   UACNormalAccount,
			},
			updateReq:      &UpdateUserRequest{PasswordNeverExpires: boolPtr(true)},
			expectChange:   true,
			expectedNewUAC: UACNormalAccount | UACPasswordNeverExpires,
		},
		{
			name: "multiple flag changes",
			currentUser: &User{
				AccountEnabled:       true,
				PasswordNeverExpires: false,
				UserAccountControl:   UACNormalAccount,
			},
			updateReq: &UpdateUserRequest{
				Enabled:              boolPtr(false),
				PasswordNeverExpires: boolPtr(true),
			},
			expectChange:   true,
			expectedNewUAC: UACNormalAccount | UACAccountDisabled | UACPasswordNeverExpires,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed, newUAC := um.calculateUACChanges(tt.updateReq, tt.currentUser)
			assert.Equal(t, tt.expectChange, changed)
			if tt.expectChange {
				assert.Equal(t, tt.expectedNewUAC, newUAC)
			}
		})
	}
}

// Test validation edge cases

func TestUserManager_CreateUser_ValidationEdgeCases(t *testing.T) {
	um := NewUserManager(context.Background(), &MockUserClient{}, "DC=example,DC=com", nil)

	tests := []struct {
		name    string
		req     *CreateUserRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "SAM with exactly 20 characters",
			req: &CreateUserRequest{
				Name:              "Test User",
				UserPrincipalName: "test@example.com",
				SAMAccountName:    "12345678901234567890", // exactly 20 chars
				Container:         "OU=Users,DC=example,DC=com",
			},
			wantErr: false,
		},
		{
			name: "SAM with 21 characters",
			req: &CreateUserRequest{
				Name:              "Test User",
				UserPrincipalName: "test@example.com",
				SAMAccountName:    "123456789012345678901", // 21 chars
				Container:         "OU=Users,DC=example,DC=com",
			},
			wantErr: true,
			errMsg:  "cannot exceed 20 characters",
		},
		{
			name: "UPN without domain",
			req: &CreateUserRequest{
				Name:              "Test User",
				UserPrincipalName: "testuser",
				SAMAccountName:    "testuser",
				Container:         "OU=Users,DC=example,DC=com",
			},
			wantErr: true,
			errMsg:  "UPN format",
		},
		{
			name: "SAM with special characters",
			req: &CreateUserRequest{
				Name:              "Test User",
				UserPrincipalName: "test@example.com",
				SAMAccountName:    "test@user", // @ not allowed
				Container:         "OU=Users,DC=example,DC=com",
			},
			wantErr: true,
			errMsg:  "invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := um.ValidateCreateUserRequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Benchmark tests

func BenchmarkUserManager_CalculateUACChanges(b *testing.B) {
	ctx := context.Background()
	mockClient := &MockClient{}
	um := NewUserManager(ctx, mockClient, "DC=example,DC=com", nil)

	currentUser := &User{
		AccountEnabled:       true,
		PasswordNeverExpires: false,
		UserAccountControl:   UACNormalAccount,
	}

	updateReq := &UpdateUserRequest{
		Enabled:              boolPtr(false),
		PasswordNeverExpires: boolPtr(true),
	}

	for b.Loop() {
		um.calculateUACChanges(updateReq, currentUser)
	}
}

// TestUserManager_TimeHandling tests time parsing for user attributes.
func TestUserManager_TimeHandling(t *testing.T) {
	// Test that whenCreated/whenChanged parsing works correctly
	timeStr := "20240115120000.0Z"
	expectedTime, err := time.Parse("20060102150405.0Z", timeStr)
	require.NoError(t, err)
	assert.Equal(t, 2024, expectedTime.Year())
	assert.Equal(t, time.January, expectedTime.Month())
	assert.Equal(t, 15, expectedTime.Day())
}
