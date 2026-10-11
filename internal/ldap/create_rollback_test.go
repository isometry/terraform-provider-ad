package ldap

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var errPostAdd = errors.New("deliberate post-add failure")

func TestRollbackCreate_UserFlagsFailureDeletesUser(t *testing.T) {
	mc := &MockClient{}
	um := NewUserManager(t.Context(), mc, "DC=example,DC=com", NewCacheManager())
	dn := "CN=Test User,OU=Users,DC=example,DC=com"

	mc.On("Add", mock.Anything, mock.Anything).Return(nil).Once()
	mc.On("Modify", mock.Anything, mock.Anything).Return(errPostAdd).Once()
	mc.On("Delete", mock.Anything, dn).Return(nil).Once()

	_, err := um.CreateUser(&CreateUserRequest{
		Name: "Test User", UserPrincipalName: "testuser@example.com",
		SAMAccountName: "testuser", Container: "OU=Users,DC=example,DC=com",
	})
	require.ErrorIs(t, err, errPostAdd)
	assert.Contains(t, err.Error(), "was deleted")
	mc.AssertExpectations(t)
}

func TestRollbackCreate_UserRetrieveFailureDeletesUser(t *testing.T) {
	mc := &MockClient{}
	um := NewUserManager(t.Context(), mc, "DC=example,DC=com", NewCacheManager())
	dn := "CN=Test User,OU=Users,DC=example,DC=com"

	mc.On("Add", mock.Anything, mock.Anything).Return(nil).Once()
	mc.On("Modify", mock.Anything, mock.Anything).Return(nil).Once()
	mc.On("Search", mock.Anything, mock.Anything).Return(nil, errPostAdd).Once()
	mc.On("Delete", mock.Anything, dn).Return(errors.New("delete refused")).Once()

	_, err := um.CreateUser(&CreateUserRequest{
		Name: "Test User", UserPrincipalName: "testuser@example.com",
		SAMAccountName: "testuser", Container: "OU=Users,DC=example,DC=com",
	})
	require.ErrorIs(t, err, errPostAdd, "original error must be returned even if cleanup fails")
	assert.Contains(t, err.Error(), "cleanup")
	mc.AssertExpectations(t)
}

func TestRollbackCreate_GroupRetrieveFailureDeletesGroup(t *testing.T) {
	gm, mc := createTestGroupManager(t)
	dn := "CN=TestGroup,CN=Users,DC=test,DC=local"

	mc.On("Add", mock.Anything, mock.Anything).Return(nil).Once()
	mc.On("Search", mock.Anything, mock.Anything).Return(nil, errPostAdd).Once()
	mc.On("Delete", mock.Anything, dn).Return(nil).Once()

	_, err := gm.CreateGroup(&CreateGroupRequest{
		Name: "TestGroup", SAMAccountName: "TestGroup", Container: "CN=Users,DC=test,DC=local",
		Scope: GroupScopeGlobal, Category: GroupCategorySecurity,
	})
	require.ErrorIs(t, err, errPostAdd)
	mc.AssertExpectations(t)
}

func TestRollbackCreate_OUUnprotectedRetrieveFailureJustDeletes(t *testing.T) {
	mc := &MockOUClient{}
	om := NewOUManager(t.Context(), mc, "dc=example,dc=com")
	dn := "OU=TestOU,dc=example,dc=com"

	mc.On("Add", mock.Anything, mock.Anything).Return(nil).Once()
	mc.On("Search", mock.Anything, mock.Anything).Return(nil, errPostAdd).Once()
	mc.On("Delete", mock.Anything, dn).Return(nil).Once()

	_, err := om.CreateOU(&CreateOURequest{Name: "TestOU", ParentDN: "dc=example,dc=com"})
	require.ErrorIs(t, err, errPostAdd)
	mc.AssertNotCalled(t, "Modify", mock.Anything, mock.Anything)
	mc.AssertExpectations(t)
}

// A protected OU whose post-protection refresh fails must have its deny-delete
// ACE removed before the Delete, or AD refuses the Delete.
func TestRollbackCreate_OUProtectedRemovesProtectionBeforeDelete(t *testing.T) {
	mc := &MockOUClient{}
	om := NewOUManager(t.Context(), mc, "dc=example,dc=com")
	dn := "OU=TestOU,dc=example,dc=com"

	unprotected := &SecurityDescriptor{Revision: 1, Control: SESelfRelative | SEDACLPresent, DACL: &ACL{AclRevision: 2}}
	rawUnprotected, err := unprotected.Marshal()
	require.NoError(t, err)
	sdResult := func(raw []byte) *SearchResult {
		return &SearchResult{Total: 1, Entries: []*ldap.Entry{{DN: dn, Attributes: []*ldap.EntryAttribute{
			{Name: "nTSecurityDescriptor", ByteValues: [][]byte{raw}},
		}}}}
	}
	guid := []byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12}
	ouEntry := &SearchResult{Total: 1, Entries: []*ldap.Entry{{DN: dn, Attributes: []*ldap.EntryAttribute{
		{Name: "objectGUID", Values: []string{string(guid)}, ByteValues: [][]byte{guid}},
		{Name: "distinguishedName", Values: []string{dn}},
		{Name: "ou", Values: []string{"TestOU"}},
	}}}}

	withSD := mock.MatchedBy(func(r *SearchRequest) bool { return len(r.Controls) > 0 })
	plain := mock.MatchedBy(func(r *SearchRequest) bool { return len(r.Controls) == 0 })

	var order []string
	mc.On("Add", mock.Anything, mock.Anything).Return(nil).Once()
	mc.On("Search", mock.Anything, plain).Return(ouEntry, nil).Once()                   // initial read
	mc.On("Search", mock.Anything, withSD).Return(sdResult(rawUnprotected), nil).Once() // protect: read SD
	mc.On("Modify", mock.Anything, mock.Anything).Return(nil).Run(func(mock.Arguments) { order = append(order, "protect") }).Once()
	mc.On("Search", mock.Anything, plain).Return(nil, errPostAdd).Once()                                // refresh fails
	mc.On("Search", mock.Anything, withSD).Return(sdResult(buildTestSecurityDescriptor(t)), nil).Once() // cleanup: read SD
	mc.On("Modify", mock.Anything, mock.Anything).Return(nil).Run(func(mock.Arguments) { order = append(order, "unprotect") }).Once()
	mc.On("Delete", mock.Anything, dn).Return(nil).Run(func(mock.Arguments) { order = append(order, "delete") }).Once()

	_, err = om.CreateOU(&CreateOURequest{Name: "TestOU", ParentDN: "dc=example,dc=com", Protected: true})
	require.ErrorIs(t, err, errPostAdd)
	assert.Equal(t, []string{"protect", "unprotect", "delete"}, order)
	mc.AssertExpectations(t)
}
