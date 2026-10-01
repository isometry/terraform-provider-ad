package ldap

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Active Directory membership operation limits.
const (
	// ADMemberBatchSize is the recommended batch size for Active Directory member operations.
	//
	// Active Directory has a practical limit of approximately 1000 members that can be
	// processed in a single LDAP modify operation. This limit exists to:
	//   - Prevent LDAP server resource exhaustion
	//   - Avoid transaction timeout issues
	//   - Maintain reasonable response times
	//   - Ensure reliable replication across domain controllers
	//
	// Operations exceeding this limit may fail with LDAP error codes like:
	//   - LDAP_ADMIN_LIMIT_EXCEEDED (11)
	//   - LDAP_SIZELIMIT_EXCEEDED (4)
	ADMemberBatchSize = 1000
)

// MembershipDelta represents the changes needed to achieve desired membership state.
type MembershipDelta struct {
	ToAdd    []string // Members to add (normalized DNs)
	ToRemove []string // Members to remove (normalized DNs)
}

// GroupMembershipManager handles bulk Active Directory group membership operations
// with DN-based membership management. All member parameters must be Distinguished Names.
type GroupMembershipManager struct {
	ctx          context.Context
	client       Client
	groupManager *GroupManager
	timeout      time.Duration
	cacheManager *CacheManager // Reference to shared cache
}

// NewGroupMembershipManager creates a new group membership manager instance.
func NewGroupMembershipManager(ctx context.Context, client Client, baseDN string, cacheManager *CacheManager) *GroupMembershipManager {
	return &GroupMembershipManager{
		ctx:          ctx,
		client:       client,
		groupManager: NewGroupManager(ctx, client, baseDN, cacheManager),
		timeout:      30 * time.Second,
		cacheManager: cacheManager,
	}
}

// SetTimeout sets the LDAP operation timeout for all operations.
func (gmm *GroupMembershipManager) SetTimeout(timeout time.Duration) {
	gmm.timeout = timeout
	gmm.groupManager.SetTimeout(timeout)
}

// SetGroupMembers sets the complete membership of a group, replacing all existing members.
// All members must be provided as Distinguished Names (DNs).
//
// memberGUIDs is optional — DN → canonical GUID for any desired member whose
// GUID is known. nil (or a map supplying no valid GUID for any desired DN)
// preserves the legacy DN-only behavior exactly. When it supplies a GUID for
// a desired DN, that GUID is used in two places:
//   - Delta: the member is compared to current membership by GUID identity
//     (see CalculateMembershipDeltaWithGUIDs), so a desired DN that is stale
//     because the object was renamed is recognised as already present and is
//     neither removed nor re-added.
//   - Add: the member is written using its rename-immune "<GUID=...>"
//     alternative-DN form.
//
// Removals always use AD's own current DNs, so they have no staleness to
// guard against.
func (gmm *GroupMembershipManager) SetGroupMembers(groupGUID string, memberDNs []string, memberGUIDs map[string]string) error {
	if groupGUID == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	// Validate that all members are DNs
	if err := gmm.ValidateMembers(memberDNs); err != nil {
		return WrapError("validate_member_dns", err)
	}

	// Calculate what changes are needed
	delta, err := gmm.CalculateMembershipDeltaWithGUIDs(groupGUID, memberDNs, memberGUIDs)
	if err != nil {
		return WrapError("calculate_membership_delta", err)
	}

	// If no changes needed, return early
	if len(delta.ToAdd) == 0 && len(delta.ToRemove) == 0 {
		return nil
	}

	// Apply changes: remove first, then add to avoid conflicts
	if len(delta.ToRemove) > 0 {
		if err := gmm.RemoveGroupMembers(groupGUID, delta.ToRemove); err != nil {
			return WrapError("remove_members_for_set", err)
		}
	}

	if len(delta.ToAdd) > 0 {
		if err := gmm.AddGroupMembers(groupGUID, delta.ToAdd, memberGUIDs); err != nil {
			return WrapError("add_members_for_set", err)
		}
	}

	return nil
}

// GetGroupMembers retrieves all members of a group as normalized DNs.
func (gmm *GroupMembershipManager) GetGroupMembers(groupGUID string) ([]string, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	// Use the existing GroupManager method which returns DNs
	memberDNs, err := gmm.groupManager.GetMembers(groupGUID)
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
// All members must be provided as Distinguished Names (DNs).
// Uses ADMemberBatchSize to respect Active Directory's member operation limits.
//
// memberGUIDs is optional (nil is valid and preserves today's literal-DN
// write behavior exactly) — DN → canonical GUID, for any member about to
// be added whose GUID is known. When present for a given DN, the member is
// written to AD using its rename-immune "<GUID=...>" alternative-DN form
// (see GUIDToAltDN) instead of the literal DN.
func (gmm *GroupMembershipManager) AddGroupMembers(groupGUID string, memberDNs []string, memberGUIDs map[string]string) error {
	if groupGUID == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	if len(memberDNs) == 0 {
		return nil // Nothing to add
	}

	// Validate that all members are DNs
	if err := gmm.ValidateMembers(memberDNs); err != nil {
		return WrapError("validate_member_dns", err)
	}

	// Get group DN for operations
	group, err := gmm.groupManager.GetGroup(groupGUID)
	if err != nil {
		return WrapError("get_group_for_add_members", err)
	}

	// Extract unique DNs and sort for consistent processing
	uniqueDNs := gmm.extractUniqueDNs(memberDNs)
	if len(uniqueDNs) == 0 {
		return nil // No valid members to add
	}

	// Perform batch add operations respecting AD limits
	return gmm.batchAddMembers(group.DistinguishedName, uniqueDNs, memberGUIDs)
}

// RemoveGroupMembers removes members from a group using batch operations.
// All members must be provided as Distinguished Names (DNs).
func (gmm *GroupMembershipManager) RemoveGroupMembers(groupGUID string, memberDNs []string) error {
	if groupGUID == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	if len(memberDNs) == 0 {
		return nil // Nothing to remove
	}

	// Validate that all members are DNs
	if err := gmm.ValidateMembers(memberDNs); err != nil {
		return WrapError("validate_member_dns", err)
	}

	// Get current group state
	group, err := gmm.groupManager.GetGroup(groupGUID)
	if err != nil {
		return WrapError("get_group_for_remove_members", err)
	}

	// Extract unique DNs to remove
	toRemoveDNs := gmm.extractUniqueDNs(memberDNs)
	if len(toRemoveDNs) == 0 {
		return nil // No valid members to remove
	}

	// Calculate new membership by filtering out members to remove
	newMembers := gmm.calculateNewMembership(group.MemberDNs, toRemoveDNs)

	// Replace entire member list - more reliable than individual deletions
	return gmm.replaceMemberList(group.DistinguishedName, newMembers)
}

// CalculateMembershipDelta compares desired membership with current state
// and returns the changes needed to achieve the desired state.
// All desired members must be provided as Distinguished Names (DNs).
func (gmm *GroupMembershipManager) CalculateMembershipDelta(groupGUID string, desiredMemberDNs []string) (*MembershipDelta, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	// Validate that all desired members are DNs
	if err := gmm.ValidateMembers(desiredMemberDNs); err != nil {
		return nil, WrapError("validate_desired_member_dns", err)
	}

	// Get current members
	currentMembers, err := gmm.GetGroupMembers(groupGUID)
	if err != nil {
		return nil, WrapError("get_current_members", err)
	}

	// Extract unique DNs and sort for comparison
	desiredDNs := gmm.extractUniqueDNs(desiredMemberDNs)

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

// CalculateMembershipDeltaWithGUIDs is CalculateMembershipDelta with
// GUID-identity comparison for desired members whose GUID is known.
//
// memberGUIDs maps desired DN (exact string, as passed in desiredMemberDNs)
// → GUID (any format accepted by NormalizeGUID; compared case-insensitively).
// Entries that are missing, empty or malformed are ignored, i.e. that member
// falls back to DN comparison. If no desired DN has a usable GUID (including
// memberGUIDs == nil), this delegates to CalculateMembershipDelta and the
// result is identical to it, with no extra LDAP traffic.
//
// Otherwise current membership is read in one search (a GUID-filtered
// subtree search under the manager's base DN, size limit 1, requesting only
// the member attribute) carrying LDAP_SERVER_EXTENDED_DN_OID, which yields
// every current member's GUID alongside its DN, and the delta is computed as
// follows (DN comparisons are case-insensitive, exactly as in
// CalculateMembershipDelta):
//   - A desired member with a GUID is present iff a current member has that
//     GUID - regardless of whether its desired DN is stale - or a current
//     member with no GUID in the extended DN has the same DN.
//   - A desired member without a GUID is present iff a current member has the
//     same DN.
//   - A current member is kept iff it matches a desired member by the same
//     rules; otherwise it is removed.
//
// ToAdd holds the desired DNs (as passed in, so memberGUIDs lookups in the
// Add path still resolve) of members not present, with at most one DN per
// GUID. ToRemove holds the DNs exactly as AD currently reports them for the
// current members not kept. Both are sorted.
//
// Degradation: if the server rejects the (critical) extended-DN control with
// unavailableCriticalExtension, a warning is logged and the result of
// CalculateMembershipDelta (DN-based comparison) is returned instead; ToAdd
// still carries the desired DNs, so the Add path still writes GUID forms.
// Every other failure (group not found, search error, malformed member
// value) is returned as an error.
func (gmm *GroupMembershipManager) CalculateMembershipDeltaWithGUIDs(groupGUID string, desiredMemberDNs []string, memberGUIDs map[string]string) (*MembershipDelta, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	desiredDNs := gmm.extractUniqueDNs(desiredMemberDNs)
	desiredGUIDs := usableMemberGUIDs(desiredDNs, memberGUIDs)
	if len(desiredGUIDs) == 0 {
		return gmm.CalculateMembershipDelta(groupGUID, desiredMemberDNs)
	}

	// Validate that all desired members are DNs
	if err := gmm.ValidateMembers(desiredMemberDNs); err != nil {
		return nil, WrapError("validate_desired_member_dns", err)
	}

	currentMembers, err := gmm.getCurrentMembersWithGUIDs(groupGUID)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailableCriticalExtension) {
			tflog.SubsystemWarn(gmm.ctx, "ldap", "Server does not support the extended DN control (unavailableCriticalExtension); falling back to DN-based membership comparison", map[string]any{
				"group_guid": groupGUID,
				"error":      err.Error(),
			})
			return gmm.CalculateMembershipDelta(groupGUID, desiredMemberDNs)
		}
		return nil, WrapError("get_current_members_with_guids", err)
	}

	toAdd, toRemove := calculateGUIDAwareSetDifferences(currentMembers, desiredDNs, desiredGUIDs)

	return &MembershipDelta{
		ToAdd:    toAdd,
		ToRemove: toRemove,
	}, nil
}

// usableMemberGUIDs returns desired DN → normalized GUID for every desired DN
// with a well-formed GUID in memberGUIDs.
func usableMemberGUIDs(desiredDNs []string, memberGUIDs map[string]string) map[string]string {
	if len(memberGUIDs) == 0 {
		return nil
	}

	handler := NewGUIDHandler()
	usable := make(map[string]string)
	for _, dn := range desiredDNs {
		guid, ok := memberGUIDs[dn]
		if !ok || guid == "" {
			continue
		}
		normalized, err := handler.NormalizeGUID(guid)
		if err != nil {
			continue
		}
		usable[dn] = normalized
	}

	return usable
}

// CurrentMember is one current member of a group, exactly as Active Directory
// reports it in the group's member attribute, together with the identity
// components of its extended DN. It is produced by GetCurrentMembers and
// consumed by MemberNormalizer.ResolveBatchAgainst.
type CurrentMember struct {
	// DN is the member's DN as AD reports it, with attribute types upper-cased
	// via NormalizeDNCase - the same form GetGroupMembers and
	// MemberNormalizer.ResolveBatch return.
	DN string
	// GUID is the member's objectGUID in canonical lower-case hyphenated
	// form, or "" if AD supplied no GUID component for the value.
	GUID string
	// SID is the member's objectSid in "S-1-..." string form, or "" if the
	// object has no objectSid (e.g. contacts) or the component was absent or
	// unparseable.
	SID string
}

// GetCurrentMembers returns the group's current members from a single
// search carrying LDAP_SERVER_EXTENDED_DN_OID, so every member's DN, GUID and
// SID are obtained without any per-member lookup. The search is a
// GUID-filtered subtree search under the manager's base DN (size limit 1,
// only the member attribute requested); a group outside the base DN is
// therefore reported as not found. Members are returned in the order AD
// reports them.
//
// This is the same reader SetGroupMembers uses for GUID-identity diffing (see
// CalculateMembershipDeltaWithGUIDs) and shares its range-retrieval
// limitation: for groups above AD's MaxValRange, AD returns only
// "member;range=0-N", which is not consumed, so the result is empty (a
// warning is logged). Callers must therefore treat the result as a possibly
// incomplete view: absence from it does not prove non-membership.
// MemberNormalizer.ResolveBatchAgainst is safe on such a view, since any
// identifier it cannot match simply falls back to normal resolution.
//
// Errors: an empty or malformed groupGUID, a failed search (including
// unavailableCriticalExtension from servers lacking the control), a missing
// group (IsNotFoundError) or a member value whose extended DN or DN cannot
// be parsed. A malformed SID component is not an error; that member's SID is
// left empty.
func (gmm *GroupMembershipManager) GetCurrentMembers(groupGUID string) ([]CurrentMember, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	members, err := gmm.getCurrentMembersWithGUIDs(groupGUID)
	if err != nil {
		return nil, WrapError("get_current_members", err)
	}

	out := make([]CurrentMember, len(members))
	for i, m := range members {
		out[i] = CurrentMember{DN: m.NormalizedDN, GUID: m.GUID, SID: m.SID}
	}
	return out, nil
}

// currentGroupMember is one value of a group's member attribute as AD
// currently reports it.
type currentGroupMember struct {
	// DN is the member's DN exactly as AD reported it (extended components removed).
	DN string
	// NormalizedDN is DN with uppercase attribute types (as GetGroupMembers returns).
	NormalizedDN string
	// GUID is the canonical lower-case objectGUID, or "" if AD supplied none.
	GUID string
	// SID is the "S-1-..." objectSid, or "" if AD supplied none (or it was malformed).
	SID string
}

// getCurrentMembersWithGUIDs reads the group's member attribute with the
// LDAP_SERVER_EXTENDED_DN_OID control so that each value carries the
// member's objectGUID and objectSid, avoiding a per-member lookup. It is the
// single reader behind both GetCurrentMembers and
// CalculateMembershipDeltaWithGUIDs.
//
// Range retrieval: like GroupManager.GetGroup (and therefore
// GetGroupMembers), only the plain "member" attribute is consumed. For groups
// above AD's MaxValRange the server returns "member;range=0-N" instead, which
// both readers treat as no current members; this keeps SetGroupMembers'
// large-group behavior identical to the legacy path (additions only, never
// removals - RemoveGroupMembers rewrites the member list from GetGroup and
// would otherwise truncate it).
func (gmm *GroupMembershipManager) getCurrentMembersWithGUIDs(groupGUID string) ([]currentGroupMember, error) {
	handler := NewGUIDHandler()
	if !handler.IsValidGUID(groupGUID) {
		return nil, fmt.Errorf("invalid GUID format: %s", groupGUID)
	}

	searchReq, err := handler.GenerateGUIDSearchRequest(gmm.groupManager.baseDN, groupGUID)
	if err != nil {
		return nil, WrapError("generate_guid_search", err)
	}
	searchReq.Attributes = []string{"member"}
	searchReq.TimeLimit = gmm.timeout
	searchReq.Controls = []ldap.Control{NewExtendedDNControl()}

	result, err := gmm.client.Search(gmm.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_group_members_extended_dn", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewNotFoundError("get_group_members_extended_dn", "group with GUID %s not found", groupGUID)
	}

	entry := result.Entries[0]
	for _, attr := range entry.Attributes {
		if strings.HasPrefix(strings.ToLower(attr.Name), "member;range=") {
			tflog.SubsystemWarn(gmm.ctx, "ldap", "Group member attribute was range-limited by the server; only the unranged member attribute is evaluated", map[string]any{
				"group_guid": groupGUID,
				"attribute":  attr.Name,
				"values":     len(attr.Values),
			})
		}
	}

	values := entry.GetAttributeValues("member")
	members := make([]currentGroupMember, 0, len(values))
	sidHandler := NewSIDHandler()
	withoutGUID := 0
	for _, value := range values {
		parsed, err := ParseExtendedDN(value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse member value of group %s: %w", groupGUID, err)
		}

		normalized, err := NormalizeDNCase(parsed.DN)
		if err != nil {
			return nil, fmt.Errorf("failed to normalize member DN %q of group %s: %w", parsed.DN, groupGUID, err)
		}

		if parsed.GUID == "" {
			withoutGUID++
		}

		// The SID is informational (identifier matching only); a malformed
		// one must not fail membership reads or writes, so it is dropped.
		var sid string
		if parsed.SID != "" {
			sid, err = sidHandler.ExtendedDNSIDToString(parsed.SID)
			if err != nil {
				tflog.SubsystemDebug(gmm.ctx, "ldap", "Ignoring unparseable SID component in member extended DN", map[string]any{
					"group_guid": groupGUID,
					"member_dn":  parsed.DN,
					"error":      err.Error(),
				})
				sid = ""
			}
		}

		members = append(members, currentGroupMember{
			DN:           parsed.DN,
			NormalizedDN: normalized,
			GUID:         parsed.GUID,
			SID:          sid,
		})
	}

	tflog.SubsystemDebug(gmm.ctx, "ldap", "Read current group members with extended DNs", map[string]any{
		"group_guid":           groupGUID,
		"member_count":         len(members),
		"members_without_guid": withoutGUID,
	})

	return members, nil
}

// desiredGroupMember is a deduplicated desired member for GUID-aware diffing.
type desiredGroupMember struct {
	dn   string // as passed by the caller
	guid string // normalized; "" means compare by DN
}

// calculateGUIDAwareSetDifferences implements the comparison rules documented
// on CalculateMembershipDeltaWithGUIDs. desiredGUIDs maps desired DN →
// normalized GUID for those desired DNs that have one.
func calculateGUIDAwareSetDifferences(current []currentGroupMember, desiredDNs []string, desiredGUIDs map[string]string) (toAdd, toRemove []string) {
	// Deduplicate desired members case-insensitively by DN; if case variants
	// disagree on having a GUID, keep the one that has it.
	desiredByDN := make(map[string]desiredGroupMember, len(desiredDNs))
	for _, dn := range desiredDNs {
		lower := strings.ToLower(dn)
		candidate := desiredGroupMember{dn: dn, guid: desiredGUIDs[dn]}
		if existing, ok := desiredByDN[lower]; ok && (existing.guid != "" || candidate.guid == "") {
			continue
		}
		desiredByDN[lower] = candidate
	}

	desiredGUIDSet := make(map[string]bool)
	desiredNoGUIDDNs := make(map[string]bool)
	for lower, d := range desiredByDN {
		if d.guid != "" {
			desiredGUIDSet[d.guid] = true
		} else {
			desiredNoGUIDDNs[lower] = true
		}
	}

	currentGUIDSet := make(map[string]bool)
	currentAllDNs := make(map[string]bool)
	currentNoGUIDDNs := make(map[string]bool)
	for _, c := range current {
		lower := strings.ToLower(c.NormalizedDN)
		currentAllDNs[lower] = true
		if c.GUID != "" {
			currentGUIDSet[c.GUID] = true
		} else {
			currentNoGUIDDNs[lower] = true
		}
	}

	// Desired members not present → add (at most one DN per GUID). Iterate
	// the sorted desired list rather than the map so the DN chosen for a GUID
	// shared by several desired DNs is deterministic (lexicographically first).
	addedGUIDs := make(map[string]bool)
	for _, dn := range desiredDNs {
		lower := strings.ToLower(dn)
		d := desiredByDN[lower]
		if d.dn != dn {
			continue // case-variant duplicate folded into another entry
		}
		var present bool
		if d.guid != "" {
			present = currentGUIDSet[d.guid] || currentNoGUIDDNs[lower]
		} else {
			present = currentAllDNs[lower]
		}
		if present {
			continue
		}
		if d.guid != "" {
			if addedGUIDs[d.guid] {
				continue
			}
			addedGUIDs[d.guid] = true
		}
		toAdd = append(toAdd, d.dn)
	}

	// Current members not desired → remove, using AD's own current DN.
	removedDNs := make(map[string]bool)
	for _, c := range current {
		lower := strings.ToLower(c.NormalizedDN)
		var kept bool
		if c.GUID != "" {
			kept = desiredGUIDSet[c.GUID] || desiredNoGUIDDNs[lower]
		} else {
			_, kept = desiredByDN[lower]
		}
		if kept || removedDNs[lower] {
			continue
		}
		removedDNs[lower] = true
		toRemove = append(toRemove, c.DN)
	}

	sort.Strings(toAdd)
	sort.Strings(toRemove)

	return toAdd, toRemove
}

// batchAddMembers adds members in batches to respect Active Directory limits.
func (gmm *GroupMembershipManager) batchAddMembers(groupDN string, memberDNs []string, memberGUIDs map[string]string) error {
	batchSize := ADMemberBatchSize

	for i := 0; i < len(memberDNs); i += batchSize {
		end := min(i+batchSize, len(memberDNs))

		batch := memberDNs[i:end]
		if err := gmm.addMembersBatch(groupDN, batch, memberGUIDs); err != nil {
			return fmt.Errorf("failed to add member batch %d-%d: %w", i+1, end, err)
		}
	}

	return nil
}

// memberWriteValue returns the value to write to AD's member attribute for
// the given DN: its "<GUID=...>" alternative-DN form when memberGUIDs
// supplies a GUID for it (falling back to the literal DN if the GUID turns
// out to be malformed), otherwise the literal DN unchanged.
func memberWriteValue(dn string, memberGUIDs map[string]string) string {
	if memberGUIDs == nil {
		return dn
	}
	guid, ok := memberGUIDs[dn]
	if !ok || guid == "" {
		return dn
	}
	altDN, err := GUIDToAltDN(guid)
	if err != nil {
		return dn
	}
	return altDN
}

// addMembersBatch adds a single batch of members with conflict handling.
func (gmm *GroupMembershipManager) addMembersBatch(groupDN string, memberDNs []string, memberGUIDs map[string]string) error {
	if len(memberDNs) == 0 {
		return nil
	}

	values := make([]string, len(memberDNs))
	for i, dn := range memberDNs {
		values[i] = memberWriteValue(dn, memberGUIDs)
	}

	modReq := &ModifyRequest{
		DN:            groupDN,
		AddAttributes: map[string][]string{"member": values},
	}

	err := gmm.client.Modify(gmm.ctx, modReq)
	if err != nil {
		// Handle "member already exists" conflicts by adding individually
		if IsConflictError(err) {
			return gmm.addMembersIndividually(groupDN, memberDNs, memberGUIDs)
		}
		return err
	}

	return nil
}

// addMembersIndividually adds members one by one to handle conflicts gracefully.
func (gmm *GroupMembershipManager) addMembersIndividually(groupDN string, memberDNs []string, memberGUIDs map[string]string) error {
	var lastNonConflictErr error
	successCount := 0

	for _, memberDN := range memberDNs {
		modReq := &ModifyRequest{
			DN:            groupDN,
			AddAttributes: map[string][]string{"member": {memberWriteValue(memberDN, memberGUIDs)}},
		}

		if err := gmm.client.Modify(gmm.ctx, modReq); err != nil {
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
func (gmm *GroupMembershipManager) replaceMemberList(groupDN string, newMembers []string) error {
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

	return gmm.client.Modify(gmm.ctx, modReq)
}

// extractUniqueDNs extracts unique DNs from a list of DN strings.
func (gmm *GroupMembershipManager) extractUniqueDNs(memberDNs []string) []string {
	uniqueDNs := make(map[string]bool)

	for _, dn := range memberDNs {
		if dn != "" {
			// Use original DN for deduplication
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

// ValidateMembers validates that all member identifiers are valid Distinguished Names.
// This is useful for pre-validation before applying membership changes.
func (gmm *GroupMembershipManager) ValidateMembers(memberDNs []string) error {
	if len(memberDNs) == 0 {
		return nil
	}

	// Validate each DN format
	for _, memberDN := range memberDNs {
		if err := ValidateDNSyntax(memberDN); err != nil {
			return fmt.Errorf("invalid member DN '%s': %w", memberDN, err)
		}
	}

	return nil
}

// GetMembershipStats returns statistics about group membership operations.
func (gmm *GroupMembershipManager) GetMembershipStats(groupGUID string) (map[string]any, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	group, err := gmm.groupManager.GetGroup(groupGUID)
	if err != nil {
		return nil, WrapError("get_group_for_stats", err)
	}

	stats := map[string]any{
		"group_dn":     group.DistinguishedName,
		"group_name":   group.Name,
		"member_count": len(group.MemberDNs),
		"member_dns":   group.MemberDNs,
	}

	return stats, nil
}

// ClearNormalizationCache is deprecated and no-op since normalization is handled externally.
// Kept for backward compatibility.
func (gmm *GroupMembershipManager) ClearNormalizationCache() {
	// No-op - normalization is now handled by the caller
}

// GetSupportedIdentifierFormats returns the supported member identifier formats.
// Only Distinguished Names (DNs) are supported by this manager.
func (gmm *GroupMembershipManager) GetSupportedIdentifierFormats() []string {
	return []string{"DN"}
}

// SetBaseDN updates the base DN used for searches.
func (gmm *GroupMembershipManager) SetBaseDN(baseDN string) {
	gmm.groupManager.baseDN = baseDN
}
