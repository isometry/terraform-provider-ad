package ldap

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// expectMemberRangeFollowUps mocks the two follow-up base-scope range reads of a
// group whose first page carried member;range=0-1; like AD it rejects extended-form bases.
func expectMemberRangeFollowUps(m *MockGroupClient, dn string) {
	m.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool { return strings.HasPrefix(r.BaseDN, "<") })).
		Return((*SearchResult)(nil), ldap.NewError(ldap.LDAPResultInvalidDNSyntax, errors.New("BAD_NAME"))).Maybe()
	m.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool {
		return r.BaseDN == dn && r.Scope == ScopeBaseObject && r.Attributes[0] == "member;range=2-*"
	})).Return(&SearchResult{Entries: []*ldap.Entry{rangeEntry(dn, "member;range=2-3", "CN=c,DC=t", "CN=d,DC=t")}}, nil).Once()
	m.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool {
		return r.BaseDN == dn && r.Scope == ScopeBaseObject && r.Attributes[0] == "member;range=4-*"
	})).Return(&SearchResult{Entries: []*ldap.Entry{rangeEntry(dn, "member;range=4-*", "CN=e,DC=t")}}, nil).Once()
}

func rangedGroupEntry(dn string) *ldap.Entry {
	e := createMockGroupEntry("G", "12345678-1234-1234-1234-123456789012", dn, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: "member;range=0-1", Values: []string{"CN=a,DC=t", "CN=b,DC=t"}})
	return e
}

func TestGetGroupByDN_FollowsMemberRanges(t *testing.T) {
	const dn = "CN=G,DC=t"
	m := &MockGroupClient{}
	gm := NewGroupManager(t.Context(), m, "DC=t", nil)
	m.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool {
		return r.Scope == ScopeBaseObject && r.Attributes[0] == "objectGUID"
	})).Return(&SearchResult{Entries: []*ldap.Entry{rangedGroupEntry(dn)}}, nil).Once()
	expectMemberRangeFollowUps(m, dn)

	g, err := gm.GetGroupByDN(dn)
	require.NoError(t, err)
	assert.Len(t, g.MemberDNs, 5)
	m.AssertExpectations(t)
}

func TestSearchGroups_FollowsMemberRanges(t *testing.T) {
	const dn = "CN=G,DC=t"
	searches := map[string]func(gm *GroupManager) ([]*Group, error){
		"SearchGroups": func(gm *GroupManager) ([]*Group, error) { return gm.SearchGroups("", nil) },
		"searchGroupsInContainer": func(gm *GroupManager) ([]*Group, error) {
			return gm.searchGroupsInContainer("OU=x,DC=t", "", nil, ScopeWholeSubtree)
		},
	}
	for name, search := range searches {
		t.Run(name, func(t *testing.T) {
			m := &MockGroupClient{}
			gm := NewGroupManager(t.Context(), m, "DC=t", nil)
			// Subtree entry carrying only the ranged attribute, DN in extended form.
			ext := "<GUID=85e1b9e0a1b2c3d4e5f60718293a4b5c>;<SID=010500000000000515000000>;" + dn
			m.On("SearchWithPaging", mock.Anything, mock.Anything).
				Return(&SearchResult{Entries: []*ldap.Entry{rangedGroupEntry(ext)}}, nil).Once()
			expectMemberRangeFollowUps(m, dn)

			groups, err := search(gm)
			require.NoError(t, err)
			require.Len(t, groups, 1)
			assert.Len(t, groups[0].MemberDNs, 5)
			m.AssertExpectations(t)
		})
	}
}

func TestUpdateGroup_ClearsOptionalAttributesIdempotently(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)
	testGUID := "12345678-1234-1234-1234-123456789012"
	testDN := "CN=TestGroup,CN=Users,DC=test,DC=local"
	entry := createMockGroupEntry("TestGroup", testGUID, testDN, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	mockClient.On("Search", mock.Anything, mock.Anything).Return(&SearchResult{Entries: []*ldap.Entry{entry}}, nil)

	empty := ""
	var got *ModifyRequest
	mockClient.On("Modify", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		got, _ = args.Get(1).(*ModifyRequest)
	}).Return(nil).Once()

	_, err := gm.UpdateGroup(testGUID, &UpdateGroupRequest{Description: &empty, Mail: &empty, MailNickname: &empty})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Empty(t, got.DeleteAttributes)
	for _, attr := range []string{"description", "mail", "mailNickname"} {
		v, ok := got.ReplaceAttributes[attr]
		assert.True(t, ok, attr)
		assert.Empty(t, v, attr)
	}
}

func TestDeleteGroup_NotFoundErrorWithDifferentMessage(t *testing.T) {
	gm, mockClient := createTestGroupManager(t)
	mockClient.On("Search", mock.Anything, mock.Anything).Return(
		(*SearchResult)(nil), NewNotFoundError("test", "object vanished")).Once()

	require.NoError(t, gm.DeleteGroup("12345678-1234-1234-1234-123456789012"))
	mockClient.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
}
