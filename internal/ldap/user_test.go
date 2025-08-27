package ldap

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockUserClient implements the Client interface for testing UserReader.
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

// createMockUserEntry creates a mock LDAP entry for testing user operations.
func createMockUserEntry() *ldap.Entry {
	entry := &ldap.Entry{
		DN: "CN=John Doe,OU=Users,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{}, ByteValues: [][]byte{{0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56}}},
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

func TestNewUserReader(t *testing.T) {
	client := &MockUserClient{}
	baseDN := "DC=example,DC=com"

	reader := NewUserReader(t.Context(), client, baseDN)

	assert.NotNil(t, reader)
	assert.Equal(t, client, reader.client)
	assert.Equal(t, baseDN, reader.baseDN)
	assert.Equal(t, 30*time.Second, reader.timeout)
	assert.NotNil(t, reader.guidHandler)
	assert.NotNil(t, reader.normalizer)
}

func TestUserReader_SetTimeout(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	timeout := 45 * time.Second
	reader.SetTimeout(timeout)

	assert.Equal(t, timeout, reader.timeout)
}

func TestUserReader_GetUserByDN_Success(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

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

	user, err := reader.GetUserByDN(dn)

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

func TestUserReader_GetUserByDN_NotFound(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	dn := "CN=NonExistent,OU=Users,DC=example,DC=com"

	client.On("Search", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(&SearchResult{
		Entries: []*ldap.Entry{},
		Total:   0,
	}, nil)

	user, err := reader.GetUserByDN(dn)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "user not found at DN")

	client.AssertExpectations(t)
}

func TestUserReader_GetUserByGUID_Success(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

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

	user, err := reader.GetUserByGUID(guid)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "john.doe", user.SAMAccountName)

	client.AssertExpectations(t)
}

func TestUserReader_GetUserByGUID_InvalidFormat(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	user, err := reader.GetUserByGUID("invalid-guid")

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "invalid GUID format")

	client.AssertNotCalled(t, "Search")
}

func TestUserReader_GetUserBySID_Success(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	mockEntry := createMockUserEntry()
	sid := "S-1-5-21-123456789-123456789-123456789-1001"

	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == "DC=example,DC=com" &&
			req.Scope == ScopeWholeSubtree &&
			strings.Contains(req.Filter, fmt.Sprintf("objectSid=%s", sid)) &&
			strings.Contains(req.Filter, "objectClass=user")
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry},
		Total:   1,
	}, nil)

	user, err := reader.GetUserBySID(sid)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, sid, user.ObjectSid)

	client.AssertExpectations(t)
}

func TestUserReader_GetUserByUPN_Success(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

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

	user, err := reader.GetUserByUPN(upn)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, upn, user.UserPrincipalName)

	client.AssertExpectations(t)
}

func TestUserReader_GetUserBySAM_Success(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

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

	user, err := reader.GetUserBySAM(sam)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, sam, user.SAMAccountName)

	client.AssertExpectations(t)
}

func TestUserReader_GetUserBySAM_DomainFormat(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	mockEntry := createMockUserEntry()
	domainSam := "EXAMPLE\\john.doe"
	expectedSam := "john.doe"

	client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return strings.Contains(req.Filter, fmt.Sprintf("sAMAccountName=%s", expectedSam))
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry},
		Total:   1,
	}, nil)

	user, err := reader.GetUserBySAM(domainSam)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, expectedSam, user.SAMAccountName)

	client.AssertExpectations(t)
}

func TestUserReader_GetUser_AutoDetectIdentifier(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

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
				return strings.Contains(filter, "objectSid=S-1-5-21-123456789-123456789-123456789-1001")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client.ExpectedCalls = nil // Reset expectations

			client.On("Search", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return tc.filterCheck(req.Filter)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{mockEntry},
				Total:   1,
			}, nil)

			user, err := reader.GetUser(tc.identifier)

			assert.NoError(t, err)
			assert.NotNil(t, user)
			assert.Equal(t, "john.doe", user.SAMAccountName)

			client.AssertExpectations(t)
		})
	}
}

func TestUserReader_SearchUsers_Success(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

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

	users, err := reader.SearchUsers("", nil)

	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "john.doe", users[0].SAMAccountName)
	assert.Equal(t, "disabled.user", users[1].SAMAccountName)
	assert.True(t, users[0].AccountEnabled)
	assert.False(t, users[1].AccountEnabled)

	client.AssertExpectations(t)
}

func TestUserReader_SearchUsersWithFilter_NameFilters(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

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

			client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return strings.Contains(req.Filter, tc.expectedFilter)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{mockEntry},
				Total:   1,
			}, nil)

			users, err := reader.SearchUsersWithFilter(tc.filter)

			assert.NoError(t, err)
			assert.Len(t, users, 1)

			client.AssertExpectations(t)
		})
	}
}

func TestUserReader_SearchUsersWithFilter_OrganizationalFilters(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

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

			client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return strings.Contains(req.Filter, tc.expectedFilter)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{mockEntry},
				Total:   1,
			}, nil)

			users, err := reader.SearchUsersWithFilter(tc.filter)

			assert.NoError(t, err)
			assert.Len(t, users, 1)

			client.AssertExpectations(t)
		})
	}
}

func TestUserReader_SearchUsersWithFilter_StatusFilters(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	mockEntry := createMockUserEntry()

	testCases := []struct {
		name           string
		enabled        *bool
		expectedFilter string
	}{
		{
			name:           "Enabled users",
			enabled:        boolPtr(true),
			expectedFilter: "(!(userAccountControl:1.2.840.113556.1.4.803:=2))",
		},
		{
			name:           "Disabled users",
			enabled:        boolPtr(false),
			expectedFilter: "(userAccountControl:1.2.840.113556.1.4.803:=2)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client.ExpectedCalls = nil // Reset expectations

			filter := &UserSearchFilter{Enabled: tc.enabled}

			client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return strings.Contains(req.Filter, tc.expectedFilter)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{mockEntry},
				Total:   1,
			}, nil)

			users, err := reader.SearchUsersWithFilter(filter)

			assert.NoError(t, err)
			assert.Len(t, users, 1)

			client.AssertExpectations(t)
		})
	}
}

func TestUserReader_SearchUsersWithFilter_EmailFilters(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	mockEntry := createMockUserEntry()

	testCases := []struct {
		name           string
		filter         *UserSearchFilter
		expectedFilter string
	}{
		{
			name:           "Has email",
			filter:         &UserSearchFilter{HasEmail: boolPtr(true)},
			expectedFilter: "(mail=*)",
		},
		{
			name:           "No email",
			filter:         &UserSearchFilter{HasEmail: boolPtr(false)},
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

			client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
				return strings.Contains(req.Filter, tc.expectedFilter)
			})).Return(&SearchResult{
				Entries: []*ldap.Entry{mockEntry},
				Total:   1,
			}, nil)

			users, err := reader.SearchUsersWithFilter(tc.filter)

			assert.NoError(t, err)
			assert.Len(t, users, 1)

			client.AssertExpectations(t)
		})
	}
}

func TestUserReader_SearchUsersWithFilter_Container(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	mockEntry := createMockUserEntry()
	containerDN := "OU=Engineering,DC=example,DC=com"

	filter := &UserSearchFilter{Container: containerDN}

	client.On("SearchWithPaging", mock.Anything, mock.MatchedBy(func(req *SearchRequest) bool {
		return req.BaseDN == containerDN
	})).Return(&SearchResult{
		Entries: []*ldap.Entry{mockEntry},
		Total:   1,
	}, nil)

	users, err := reader.SearchUsersWithFilter(filter)

	assert.NoError(t, err)
	assert.Len(t, users, 1)

	client.AssertExpectations(t)
}

func TestUserReader_SearchUsersWithFilter_InvalidContainer(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	filter := &UserSearchFilter{Container: "invalid-dn"}

	users, err := reader.SearchUsersWithFilter(filter)

	assert.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "invalid container DN")

	client.AssertNotCalled(t, "SearchWithPaging")
}

func TestUserReader_parseUserAccountControl(t *testing.T) {
	reader := NewUserReader(context.Background(), &MockUserClient{}, "DC=example,DC=com")

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
				CannotChangePassword:   false,
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
				CannotChangePassword:   false,
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
				CannotChangePassword:   false,
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
				CannotChangePassword:   false,
				SmartCardLogonRequired: true,
				TrustedForDelegation:   false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := &User{}
			reader.parseUserAccountControl(user, tc.uac)

			assert.Equal(t, tc.expected.AccountEnabled, user.AccountEnabled)
			assert.Equal(t, tc.expected.PasswordNeverExpires, user.PasswordNeverExpires)
			assert.Equal(t, tc.expected.PasswordNotRequired, user.PasswordNotRequired)
			assert.Equal(t, tc.expected.ChangePasswordAtLogon, user.ChangePasswordAtLogon)
			assert.Equal(t, tc.expected.CannotChangePassword, user.CannotChangePassword)
			assert.Equal(t, tc.expected.SmartCardLogonRequired, user.SmartCardLogonRequired)
			assert.Equal(t, tc.expected.TrustedForDelegation, user.TrustedForDelegation)
		})
	}
}

func TestUserReader_parseADTimestamp(t *testing.T) {
	reader := NewUserReader(context.Background(), &MockUserClient{}, "DC=example,DC=com")

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
			result, err := reader.parseADTimestamp(tc.timestamp)

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

func TestUserReader_entryToUser_ComprehensiveMapping(t *testing.T) {
	reader := NewUserReader(context.Background(), &MockUserClient{}, "DC=example,DC=com")
	entry := createMockUserEntry()

	user, err := reader.entryToUser(entry)

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

	// Primary group (should be constructed from SID + primaryGroupID)
	assert.Equal(t, "S-1-5-21-123456789-123456789-123456789-513", user.PrimaryGroup)

	// Timestamps
	assert.Equal(t, 2023, user.WhenCreated.Year())
	assert.Equal(t, 1, int(user.WhenCreated.Month()))
	assert.Equal(t, 2023, user.WhenChanged.Year())
	assert.Equal(t, 2, int(user.WhenChanged.Month()))
	assert.NotNil(t, user.LastLogon)
	assert.NotNil(t, user.PasswordLastSet)
	assert.NotNil(t, user.AccountExpires)
}

func TestUserReader_GetUserStats(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	enabledEntry := createMockUserEntry()
	disabledEntry := createDisabledUserEntry()

	client.On("SearchWithPaging", mock.Anything, mock.AnythingOfType("*ldap.SearchRequest")).Return(&SearchResult{
		Entries: []*ldap.Entry{enabledEntry, disabledEntry},
		Total:   2,
	}, nil)

	stats, err := reader.GetUserStats()

	assert.NoError(t, err)
	assert.Equal(t, 2, stats["total"])
	assert.Equal(t, 1, stats["enabled"])
	assert.Equal(t, 1, stats["disabled"])

	client.AssertExpectations(t)
}

func TestUserReader_EmptyIdentifier(t *testing.T) {
	client := &MockUserClient{}
	reader := NewUserReader(t.Context(), client, "DC=example,DC=com")

	testCases := []struct {
		name string
		fn   func() (*User, error)
	}{
		{"GetUser", func() (*User, error) { return reader.GetUser("") }},
		{"GetUserByDN", func() (*User, error) { return reader.GetUserByDN("") }},
		{"GetUserByGUID", func() (*User, error) { return reader.GetUserByGUID("") }},
		{"GetUserBySID", func() (*User, error) { return reader.GetUserBySID("") }},
		{"GetUserByUPN", func() (*User, error) { return reader.GetUserByUPN("") }},
		{"GetUserBySAM", func() (*User, error) { return reader.GetUserBySAM("") }},
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

// Helper function to create bool pointer.
func boolPtr(b bool) *bool {
	return &b
}
