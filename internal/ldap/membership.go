package ldap

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// MembershipDelta represents the changes needed to achieve desired membership state.
type MembershipDelta struct {
	ToAdd    []string // Members to add (normalized DNs)
	ToRemove []string // Members to remove (normalized DNs)
}

// GroupMembershipManager handles bulk Active Directory group membership operations
// with anti-drift prevention through identifier normalization.
type GroupMembershipManager struct {
	client       Client
	groupManager *GroupManager
	normalizer   *MemberNormalizer
	timeout      time.Duration
}

// NewGroupMembershipManager creates a new group membership manager instance.
func NewGroupMembershipManager(client Client, baseDN string) *GroupMembershipManager {
	return &GroupMembershipManager{
		client:       client,
		groupManager: NewGroupManager(client, baseDN),
		normalizer:   NewMemberNormalizer(client, baseDN),
		timeout:      30 * time.Second,
	}
}

// SetTimeout sets the LDAP operation timeout for all operations.
func (gmm *GroupMembershipManager) SetTimeout(timeout time.Duration) {
	gmm.timeout = timeout
	gmm.groupManager.SetTimeout(timeout)
	gmm.normalizer.SetTimeout(timeout)
}

// SetGroupMembers sets the complete membership of a group, replacing all existing members.
// This is the primary anti-drift operation - it ensures the group has exactly the specified members.
func (gmm *GroupMembershipManager) SetGroupMembers(ctx context.Context, groupGUID string, members []string) error {
	if groupGUID == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	// Calculate what changes are needed
	delta, err := gmm.CalculateMembershipDelta(ctx, groupGUID, members)
	if err != nil {
		return WrapError("calculate_membership_delta", err)
	}

	// If no changes needed, return early
	if len(delta.ToAdd) == 0 && len(delta.ToRemove) == 0 {
		return nil
	}

	// Apply changes: remove first, then add to avoid conflicts
	if len(delta.ToRemove) > 0 {
		if err := gmm.RemoveGroupMembers(ctx, groupGUID, delta.ToRemove); err != nil {
			return WrapError("remove_members_for_set", err)
		}
	}

	if len(delta.ToAdd) > 0 {
		if err := gmm.AddGroupMembers(ctx, groupGUID, delta.ToAdd); err != nil {
			return WrapError("add_members_for_set", err)
		}
	}

	return nil
}

// GetGroupMembers retrieves all members of a group as normalized DNs.
func (gmm *GroupMembershipManager) GetGroupMembers(ctx context.Context, groupGUID string) ([]string, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	// Use the existing GroupManager method which returns DNs
	memberDNs, err := gmm.groupManager.GetMembers(ctx, groupGUID)
	if err != nil {
		return nil, WrapError("get_group_members", err)
	}

	// Normalize all member DN cases to ensure uppercase attribute types
	normalizedDNs, err := NormalizeDNCaseBatch(memberDNs)
	if err != nil {
		return nil, WrapError("normalize_member_dns", err)
	}

	// Sort for consistent ordering
	sort.Strings(normalizedDNs)
	return normalizedDNs, nil
}

// AddGroupMembers adds new members to a group using batch operations.
// Handles Active Directory's ~1000 member per operation limit.
func (gmm *GroupMembershipManager) AddGroupMembers(ctx context.Context, groupGUID string, members []string) error {
	if groupGUID == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	if len(members) == 0 {
		return nil // Nothing to add
	}

	// Get group DN for operations
	group, err := gmm.groupManager.GetGroup(ctx, groupGUID)
	if err != nil {
		return WrapError("get_group_for_add_members", err)
	}

	// Normalize all member identifiers to DNs
	normalizedMembers, err := gmm.normalizer.NormalizeToDNBatch(members)
	if err != nil {
		return WrapError("normalize_member_identifiers", err)
	}

	// Extract unique DNs and sort for consistent processing
	uniqueDNs := gmm.extractUniqueDNs(normalizedMembers)
	if len(uniqueDNs) == 0 {
		return nil // No valid members to add
	}

	// Perform batch add operations respecting AD limits
	return gmm.batchAddMembers(ctx, group.DistinguishedName, uniqueDNs)
}

// RemoveGroupMembers removes members from a group using batch operations.
func (gmm *GroupMembershipManager) RemoveGroupMembers(ctx context.Context, groupGUID string, members []string) error {
	if groupGUID == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	if len(members) == 0 {
		return nil // Nothing to remove
	}

	// Get current group state
	group, err := gmm.groupManager.GetGroup(ctx, groupGUID)
	if err != nil {
		return WrapError("get_group_for_remove_members", err)
	}

	// Normalize member identifiers to DNs for comparison
	normalizedMembers, err := gmm.normalizer.NormalizeToDNBatch(members)
	if err != nil {
		return WrapError("normalize_member_identifiers", err)
	}

	// Extract unique DNs to remove
	toRemoveDNs := gmm.extractUniqueDNs(normalizedMembers)
	if len(toRemoveDNs) == 0 {
		return nil // No valid members to remove
	}

	// Calculate new membership by filtering out members to remove
	newMembers := gmm.calculateNewMembership(group.MemberDNs, toRemoveDNs)

	// Replace entire member list - more reliable than individual deletions
	return gmm.replaceMemberList(ctx, group.DistinguishedName, newMembers)
}

// CalculateMembershipDelta compares desired membership with current state
// and returns the changes needed to achieve the desired state.
func (gmm *GroupMembershipManager) CalculateMembershipDelta(ctx context.Context, groupGUID string, desiredMembers []string) (*MembershipDelta, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	// Get current members
	currentMembers, err := gmm.GetGroupMembers(ctx, groupGUID)
	if err != nil {
		return nil, WrapError("get_current_members", err)
	}

	// Normalize desired members to DNs for comparison
	normalizedDesired, err := gmm.normalizer.NormalizeToDNBatch(desiredMembers)
	if err != nil {
		return nil, WrapError("normalize_desired_members", err)
	}

	// Extract unique DNs and sort for comparison
	desiredDNs := gmm.extractUniqueDNs(normalizedDesired)

	// Sort both sets for efficient comparison
	sort.Strings(currentMembers)
	sort.Strings(desiredDNs)

	// Calculate set differences
	toAdd, toRemove := gmm.calculateSetDifferences(currentMembers, desiredDNs)

	return &MembershipDelta{
		ToAdd:    toAdd,
		ToRemove: toRemove,
	}, nil
}

// batchAddMembers adds members in batches to respect Active Directory limits.
func (gmm *GroupMembershipManager) batchAddMembers(ctx context.Context, groupDN string, memberDNs []string) error {
	const batchSize = 1000 // Active Directory recommended batch size

	for i := 0; i < len(memberDNs); i += batchSize {
		end := min(i+batchSize, len(memberDNs))

		batch := memberDNs[i:end]
		if err := gmm.addMembersBatch(ctx, groupDN, batch); err != nil {
			return fmt.Errorf("failed to add member batch %d-%d: %w", i+1, end, err)
		}
	}

	return nil
}

// addMembersBatch adds a single batch of members with conflict handling.
func (gmm *GroupMembershipManager) addMembersBatch(ctx context.Context, groupDN string, memberDNs []string) error {
	if len(memberDNs) == 0 {
		return nil
	}

	modReq := &ModifyRequest{
		DN:            groupDN,
		AddAttributes: map[string][]string{"member": memberDNs},
	}

	err := gmm.client.Modify(ctx, modReq)
	if err != nil {
		// Handle "member already exists" conflicts by adding individually
		if IsConflictError(err) {
			return gmm.addMembersIndividually(ctx, groupDN, memberDNs)
		}
		return err
	}

	return nil
}

// addMembersIndividually adds members one by one to handle conflicts gracefully.
func (gmm *GroupMembershipManager) addMembersIndividually(ctx context.Context, groupDN string, memberDNs []string) error {
	var lastNonConflictErr error
	successCount := 0

	for _, memberDN := range memberDNs {
		modReq := &ModifyRequest{
			DN:            groupDN,
			AddAttributes: map[string][]string{"member": {memberDN}},
		}

		if err := gmm.client.Modify(ctx, modReq); err != nil {
			if IsConflictError(err) {
				// Member already exists - this is expected in anti-drift scenarios
				continue
			}
			lastNonConflictErr = err
		} else {
			successCount++
		}
	}

	// Only return error if we had actual failures (not conflicts) and no successes
	if successCount == 0 && lastNonConflictErr != nil {
		return lastNonConflictErr
	}

	return nil
}

// replaceMemberList replaces the entire member list using a single LDAP operation.
func (gmm *GroupMembershipManager) replaceMemberList(ctx context.Context, groupDN string, newMembers []string) error {
	modReq := &ModifyRequest{
		DN:                groupDN,
		ReplaceAttributes: make(map[string][]string),
		DeleteAttributes:  make([]string, 0),
	}

	if len(newMembers) == 0 {
		// Remove all members by deleting the member attribute
		modReq.DeleteAttributes = append(modReq.DeleteAttributes, "member")
	} else {
		// Replace with new member list
		modReq.ReplaceAttributes["member"] = newMembers
	}

	return gmm.client.Modify(ctx, modReq)
}

// extractUniqueDNs extracts unique DNs from a normalization result map.
func (gmm *GroupMembershipManager) extractUniqueDNs(normalizedMap map[string]string) []string {
	uniqueDNs := make(map[string]bool)

	for _, dn := range normalizedMap {
		if dn != "" {
			// Use lowercase for deduplication while preserving original case
			uniqueDNs[dn] = true
		}
	}

	result := make([]string, 0, len(uniqueDNs))
	for dn := range uniqueDNs {
		result = append(result, dn)
	}

	sort.Strings(result)
	return result
}

// calculateNewMembership calculates the new membership after removing specified members.
func (gmm *GroupMembershipManager) calculateNewMembership(currentMembers, toRemove []string) []string {
	// Create a map of members to remove for efficient lookup (case-insensitive)
	removeMap := make(map[string]bool)
	for _, dn := range toRemove {
		removeMap[strings.ToLower(dn)] = true
	}

	// Filter out members to be removed
	newMembers := make([]string, 0, len(currentMembers))
	for _, member := range currentMembers {
		if !removeMap[strings.ToLower(member)] {
			newMembers = append(newMembers, member)
		}
	}

	return newMembers
}

// calculateSetDifferences calculates the differences between current and desired member sets.
func (gmm *GroupMembershipManager) calculateSetDifferences(current, desired []string) (toAdd, toRemove []string) {
	// Convert to maps for efficient lookup (case-insensitive comparison)
	currentMap := make(map[string]string) // lowercase -> original
	desiredMap := make(map[string]string) // lowercase -> original

	for _, dn := range current {
		currentMap[strings.ToLower(dn)] = dn
	}

	for _, dn := range desired {
		desiredMap[strings.ToLower(dn)] = dn
	}

	// Find members to add (in desired but not in current)
	for lowerDN, originalDN := range desiredMap {
		if _, exists := currentMap[lowerDN]; !exists {
			toAdd = append(toAdd, originalDN)
		}
	}

	// Find members to remove (in current but not in desired)
	for lowerDN, originalDN := range currentMap {
		if _, exists := desiredMap[lowerDN]; !exists {
			toRemove = append(toRemove, originalDN)
		}
	}

	// Sort for consistent ordering
	sort.Strings(toAdd)
	sort.Strings(toRemove)

	return toAdd, toRemove
}

// ValidateMembers validates that all member identifiers can be resolved.
// This is useful for pre-validation before applying membership changes.
func (gmm *GroupMembershipManager) ValidateMembers(members []string) error {
	if len(members) == 0 {
		return nil
	}

	// Validate each identifier format
	for _, member := range members {
		if err := gmm.normalizer.ValidateIdentifier(member); err != nil {
			return fmt.Errorf("invalid member identifier '%s': %w", member, err)
		}
	}

	return nil
}

// GetMembershipStats returns statistics about group membership operations.
func (gmm *GroupMembershipManager) GetMembershipStats(ctx context.Context, groupGUID string) (map[string]any, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	group, err := gmm.groupManager.GetGroup(ctx, groupGUID)
	if err != nil {
		return nil, WrapError("get_group_for_stats", err)
	}

	stats := map[string]any{
		"group_dn":     group.DistinguishedName,
		"group_name":   group.Name,
		"member_count": len(group.MemberDNs),
		"member_dns":   group.MemberDNs,
		"cache_stats":  gmm.normalizer.CacheStats(),
	}

	return stats, nil
}

// ClearNormalizationCache clears the member normalization cache.
// Useful for testing or when identifier mappings may have changed.
func (gmm *GroupMembershipManager) ClearNormalizationCache() {
	gmm.normalizer.ClearCache()
}

// GetSupportedIdentifierFormats returns the supported member identifier formats.
func (gmm *GroupMembershipManager) GetSupportedIdentifierFormats() []string {
	return gmm.normalizer.GetSupportedFormats()
}

// SetBaseDN updates the base DN used for searches.
func (gmm *GroupMembershipManager) SetBaseDN(baseDN string) {
	gmm.groupManager.baseDN = baseDN
	gmm.normalizer.SetBaseDN(baseDN)
}
