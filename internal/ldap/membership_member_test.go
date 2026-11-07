package ldap

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	gmGroupGUID  = "12345678-1234-1234-1234-123456789012"
	gmMemberGUID = "abcdef01-2345-6789-abcd-ef0123456789"
)

var errNoSuchObject = fmt.Errorf("search failed: %w", ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("0000208D: NameErr")))

func TestIsDirectMember(t *testing.T) {
	tests := []struct {
		name     string
		result   *SearchResult
		err      error
		want     bool
		notFound bool
	}{
		{name: "member", result: &SearchResult{Entries: []*ldap.Entry{{DN: "CN=G,DC=t"}}}, want: true},
		{name: "non-member", result: &SearchResult{}},
		{name: "missing group", err: errNoSuchObject, notFound: true},
		{name: "other error", err: ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MockGroupClient{}
			gmm := NewGroupMembershipManager(t.Context(), m, "DC=t", nil)
			m.On("Search", mock.Anything, mock.MatchedBy(func(r *SearchRequest) bool {
				return r.BaseDN == "<GUID="+gmGroupGUID+">" &&
					r.Scope == ScopeBaseObject &&
					r.Filter == "(member=<GUID="+gmMemberGUID+">)" &&
					assert.ObjectsAreEqual([]string{"1.1"}, r.Attributes) &&
					len(r.Controls) == 0
			})).Return(tt.result, tt.err).Once()

			// An upper-case GUID is normalized in the alternative DN.
			got, err := gmm.IsDirectMember("12345678-1234-1234-1234-123456789012", "ABCDEF01-2345-6789-ABCD-EF0123456789")
			switch {
			case tt.notFound:
				require.Error(t, err)
				assert.True(t, IsNotFoundError(err))
				assert.Contains(t, err.Error(), "not found")
			case tt.err != nil:
				require.Error(t, err)
				assert.False(t, IsNotFoundError(err))
			default:
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
			m.AssertExpectations(t)
		})
	}
}

func TestRemoveGroupMemberByGUID(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		notFound bool
	}{
		{name: "removed or absent"},
		{name: "missing group", err: ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("0000208D: NameErr")), notFound: true},
		{name: "other error", err: ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MockGroupClient{}
			gmm := NewGroupMembershipManager(t.Context(), m, "DC=t", nil)
			m.On("Modify", mock.Anything, mock.MatchedBy(func(r *ModifyRequest) bool {
				return r.DN == "<GUID="+gmGroupGUID+">" &&
					assert.ObjectsAreEqual(map[string][]string{"member": {"<GUID=" + gmMemberGUID + ">"}}, r.DeleteValues) &&
					len(r.AddAttributes) == 0 && len(r.ReplaceAttributes) == 0 && len(r.DeleteAttributes) == 0 &&
					len(r.Controls) == 1 && r.Controls[0].GetControlType() == ControlTypePermissiveModify
			})).Return(tt.err).Once()

			// Compact input is normalized in both alternative DNs.
			err := gmm.RemoveGroupMemberByGUID("12345678123412341234123456789012", "abcdef0123456789abcdef0123456789")
			switch {
			case tt.notFound:
				require.Error(t, err)
				assert.True(t, IsNotFoundError(err))
				assert.Contains(t, err.Error(), "not found")
			case tt.err != nil:
				require.Error(t, err)
				assert.False(t, IsNotFoundError(err))
			default:
				require.NoError(t, err)
			}
			m.AssertExpectations(t)
		})
	}
}

func TestGroupMemberByGUID_InvalidGUID(t *testing.T) {
	for _, guids := range [][2]string{{"", gmMemberGUID}, {gmGroupGUID, "not-a-guid"}} {
		m := &MockGroupClient{}
		gmm := NewGroupMembershipManager(t.Context(), m, "DC=t", nil)

		_, err := gmm.IsDirectMember(guids[0], guids[1])
		require.Error(t, err)
		require.Error(t, gmm.RemoveGroupMemberByGUID(guids[0], guids[1]))
		m.AssertNotCalled(t, "Search", mock.Anything, mock.Anything)
		m.AssertNotCalled(t, "Modify", mock.Anything, mock.Anything)
	}
}
