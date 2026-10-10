package ldap

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestClient_WritesAreNotRetried(t *testing.T) {
	timeout := errors.New("i/o timeout")
	cfg := DefaultConfig()
	cfg.MaxRetries = 3
	cfg.InitialBackoff = 1

	pool := &mockPool{}
	ops := &mockLDAPOps{}
	swapConnOps(t, ops)
	pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil)
	// .Once(): a retry would hit an unexpected-call panic/failure.
	ops.On("Add", mock.Anything).Return(timeout).Once()
	ops.On("Modify", mock.Anything).Return(timeout).Once()
	ops.On("ModifyDN", mock.Anything).Return(timeout).Once()
	ops.On("Del", mock.Anything).Return(timeout).Once()

	c := newTestClient(pool, cfg)
	assert.Error(t, c.Add(t.Context(), &AddRequest{DN: "cn=a,dc=x"}))
	assert.Error(t, c.Modify(t.Context(), &ModifyRequest{DN: "cn=a,dc=x"}))
	assert.Error(t, c.ModifyDN(t.Context(), &ModifyDNRequest{DN: "cn=a,dc=x", NewRDN: "cn=b"}))
	assert.Error(t, c.Delete(t.Context(), "cn=a,dc=x"))
	ops.AssertExpectations(t)
}

func TestClient_Modify_DeleteValues(t *testing.T) {
	pool := &mockPool{}
	ops := &mockLDAPOps{}
	swapConnOps(t, ops)
	pool.On("Get", mock.Anything).Return(&PooledConnection{}, nil)
	var got *ldap.ModifyRequest
	ops.On("Modify", mock.Anything).Run(captureArg(t, &got)).Return(nil).Once()

	c := newTestClient(pool, nil)
	require.NoError(t, c.Modify(t.Context(), &ModifyRequest{
		DN:           "cn=g,dc=x",
		DeleteValues: map[string][]string{"member": {"cn=a,dc=x"}},
	}))
	require.Len(t, got.Changes, 1)
	assert.Equal(t, uint(ldap.DeleteAttribute), got.Changes[0].Operation)
	assert.Equal(t, []string{"cn=a,dc=x"}, got.Changes[0].Modification.Vals)
}

func rangeEntry(dn, attr string, vals ...string) *ldap.Entry {
	return &ldap.Entry{DN: dn, Attributes: []*ldap.EntryAttribute{{Name: attr, Values: vals}}}
}

// serveRanges mocks the initial search plus two follow-up range requests.
func serveRanges(m *MockGroupClient, dn string, first *ldap.Entry, wantControls int) {
	m.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool { return r.Scope != ScopeBaseObject })).
		Return(&SearchResult{Entries: []*ldap.Entry{first}}, nil).Once()
	m.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool {
		return r.BaseDN == dn && r.Scope == ScopeBaseObject && r.Attributes[0] == "member;range=2-*" && len(r.Controls) == wantControls
	})).Return(&SearchResult{Entries: []*ldap.Entry{rangeEntry(dn, "member;range=2-3", "CN=c,DC=t", "CN=d,DC=t")}}, nil).Once()
	m.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool {
		return r.BaseDN == dn && r.Scope == ScopeBaseObject && r.Attributes[0] == "member;range=4-*" && len(r.Controls) == wantControls
	})).Return(&SearchResult{Entries: []*ldap.Entry{rangeEntry(dn, "member;range=4-*", "CN=e,DC=t")}}, nil).Once()
}

func TestGetCurrentMembers_FollowsRanges(t *testing.T) {
	const guid = "12345678-1234-1234-1234-123456789012"
	const dn = "CN=G,DC=t"
	m := &MockGroupClient{}
	gmm := NewGroupMembershipManager(t.Context(), m, "DC=t", nil)
	serveRanges(m, dn, rangeEntry(dn, "member;range=0-1", "CN=a,DC=t", "CN=b,DC=t"), 1)

	members, err := gmm.getCurrentMembersWithGUIDs(guid)
	require.NoError(t, err)
	assert.Len(t, members, 5)
	m.AssertExpectations(t)
}

func TestGetGroup_FollowsRanges(t *testing.T) {
	const guid = "12345678-1234-1234-1234-123456789012"
	const dn = "CN=G,DC=t"
	m := &MockGroupClient{}
	gm := NewGroupManager(t.Context(), m, "DC=t", nil)
	first := createMockGroupEntry("G", guid, dn, CalculateGroupType(GroupScopeGlobal, GroupCategorySecurity))
	first.Attributes = append(first.Attributes, &ldap.EntryAttribute{Name: "member;range=0-1", Values: []string{"CN=a,DC=t", "CN=b,DC=t"}})
	serveRanges(m, dn, first, 0)

	g, err := gm.GetGroup(guid)
	require.NoError(t, err)
	assert.Len(t, g.MemberDNs, 5)
	m.AssertExpectations(t)
}

func TestAddMembersIndividually_PartialFailureSurfaced(t *testing.T) {
	gmm, client := createTestMembershipManager(t)
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup("12345678-1234-1234-1234-123456789012", groupDN, "TestGroup", "testgroup")
	failing := &failSecondModify{MockGroupMembershipClient: client}
	gmm.client = failing
	err := gmm.addMembersIndividually(groupDN, []string{"CN=A,DC=x", "CN=B,DC=x"}, nil)
	require.Error(t, err)
}

// failSecondModify succeeds on the first Modify and fails every later one.
type failSecondModify struct {
	*MockGroupMembershipClient
	calls int
}

func (f *failSecondModify) Modify(ctx context.Context, req *ModifyRequest) error {
	f.calls++
	if f.calls == 1 {
		return nil
	}
	return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))
}

func TestRemoveGroupMembers_ValueLevelDeleteWithPermissiveControl(t *testing.T) {
	gmm, client := createTestMembershipManager(t)
	guid := "12345678-1234-1234-1234-123456789012"
	client.AddMockGroup(guid, "CN=TestGroup,OU=Groups,DC=example,DC=com", "TestGroup", "testgroup")
	client.groups[guid].Members = []string{"CN=U1,OU=Users,DC=example,DC=com", "CN=U2,OU=Users,DC=example,DC=com"}
	rec := &recordModify{MockGroupMembershipClient: client}
	gmm.client = rec

	require.NoError(t, gmm.RemoveGroupMembers(guid, []string{"CN=U1,OU=Users,DC=example,DC=com"}))
	require.NotNil(t, rec.last)
	assert.Empty(t, rec.last.ReplaceAttributes)
	assert.Equal(t, []string{"CN=U1,OU=Users,DC=example,DC=com"}, rec.last.DeleteValues["member"])
	require.Len(t, rec.last.Controls, 1)
	assert.Equal(t, ControlTypePermissiveModify, rec.last.Controls[0].GetControlType())
}

type recordModify struct {
	*MockGroupMembershipClient
	last *ModifyRequest
}

func (r *recordModify) Modify(ctx context.Context, req *ModifyRequest) error {
	r.last = req
	return r.MockGroupMembershipClient.Modify(ctx, req)
}
