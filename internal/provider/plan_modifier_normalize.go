package provider

import (
	"context"
	"fmt"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// getMembershipManager creates a GroupMembershipManager from the client.
func (r *GroupMembershipResource) getMembershipManager(ctx context.Context) (*ldapclient.GroupMembershipManager, error) {
	// Get base DN from client
	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get base DN from LDAP server: %w", err)
	}

	// Create and return GroupMembershipManager
	return ldapclient.NewGroupMembershipManager(r.client, baseDN), nil
}

// validateMemberIdentifiers validates that member identifiers are in supported formats.
func validateMemberIdentifiers(_ context.Context, membershipManager *ldapclient.GroupMembershipManager, members []string) error {
	if len(members) == 0 {
		return nil
	}

	// Use the membership manager's validation
	return membershipManager.ValidateMembers(members)
}
