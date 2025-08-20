package ldap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// GroupScope represents the scope of an Active Directory group.
type GroupScope string

const (
	GroupScopeGlobal      GroupScope = "Global"      // Global groups can contain members from the same domain
	GroupScopeUniversal   GroupScope = "Universal"   // Universal groups can contain members from any domain in the forest
	GroupScopeDomainLocal GroupScope = "DomainLocal" // Domain Local groups can contain members from any domain
)

// String returns the string representation of the group scope.
func (gs GroupScope) String() string {
	return string(gs)
}

// GroupCategory represents the category of an Active Directory group.
type GroupCategory string

const (
	GroupCategorySecurity     GroupCategory = "Security"     // Security group for access control
	GroupCategoryDistribution GroupCategory = "Distribution" // Distribution group for email distribution lists
)

// String returns the string representation of the group category.
func (gc GroupCategory) String() string {
	return string(gc)
}

// Active Directory group type bit flags
const (
	// Group scope flags (mutually exclusive)
	GroupTypeFlagGlobal      int32 = 0x00000002 // ADS_GROUP_TYPE_GLOBAL_GROUP
	GroupTypeFlagDomainLocal int32 = 0x00000004 // ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP
	GroupTypeFlagUniversal   int32 = 0x00000008 // ADS_GROUP_TYPE_UNIVERSAL_GROUP

	// Group category flag
	GroupTypeFlagSecurity int32 = -2147483648 // ADS_GROUP_TYPE_SECURITY_ENABLED (0x80000000 as signed int32)
)

// Group represents an Active Directory group.
type Group struct {
	// Core identification
	ObjectGUID        string `json:"objectGUID"`
	DistinguishedName string `json:"distinguishedName"`
	ObjectSid         string `json:"objectSid,omitempty"`

	// Group attributes
	Name           string        `json:"name"`                   // cn
	SAMAccountName string        `json:"sAMAccountName"`         // Pre-Windows 2000 name
	Description    string        `json:"description"`            // Group description
	Scope          GroupScope    `json:"scope"`                  // Group scope
	Category       GroupCategory `json:"category"`               // Group category
	GroupType      int32         `json:"groupType"`              // Raw AD groupType value
	Mail           string        `json:"mail,omitempty"`         // Email address for distribution groups
	MailNickname   string        `json:"mailNickname,omitempty"` // Exchange mail nickname

	// Container information
	Container string `json:"container"` // Parent container DN

	// Membership information
	MemberDNs []string `json:"memberDNs,omitempty"` // Distinguished names of members
	MemberOf  []string `json:"memberOf,omitempty"`  // Groups this group is a member of

	// Timestamps
	WhenCreated time.Time `json:"whenCreated,omitempty"`
	WhenChanged time.Time `json:"whenChanged,omitempty"`
}

// CreateGroupRequest represents a request to create a new group.
type CreateGroupRequest struct {
	Name           string        `json:"name"`                   // Required: Group name (will be used for cn)
	SAMAccountName string        `json:"sAMAccountName"`         // Required: Pre-Windows 2000 name
	Container      string        `json:"container"`              // Required: Parent container DN
	Description    string        `json:"description"`            // Optional: Group description
	Scope          GroupScope    `json:"scope"`                  // Required: Group scope
	Category       GroupCategory `json:"category"`               // Required: Group category
	Mail           string        `json:"mail,omitempty"`         // Optional: Email for distribution groups
	MailNickname   string        `json:"mailNickname,omitempty"` // Optional: Exchange nickname
}

// UpdateGroupRequest represents a request to update an existing group.
type UpdateGroupRequest struct {
	Name         *string        `json:"name,omitempty"`         // Optional: New group name
	Description  *string        `json:"description,omitempty"`  // Optional: New description
	Mail         *string        `json:"mail,omitempty"`         // Optional: New email address
	MailNickname *string        `json:"mailNickname,omitempty"` // Optional: New mail nickname
	Scope        *GroupScope    `json:"scope,omitempty"`        // Optional: New scope (limited conversions)
	Category     *GroupCategory `json:"category,omitempty"`     // Optional: New category
}

// GroupManager handles Active Directory group operations.
type GroupManager struct {
	client      Client
	guidHandler *GUIDHandler
	normalizer  *MemberNormalizer
	baseDN      string
	timeout     time.Duration
}

// NewGroupManager creates a new group manager instance.
func NewGroupManager(client Client, baseDN string) *GroupManager {
	return &GroupManager{
		client:      client,
		guidHandler: NewGUIDHandler(),
		normalizer:  NewMemberNormalizer(client, baseDN),
		baseDN:      baseDN,
		timeout:     30 * time.Second,
	}
}

// SetTimeout sets the LDAP operation timeout.
func (gm *GroupManager) SetTimeout(timeout time.Duration) {
	gm.timeout = timeout
	gm.normalizer.SetTimeout(timeout)
}

// CalculateGroupType calculates the Active Directory groupType value from scope and category.
func CalculateGroupType(scope GroupScope, category GroupCategory) int32 {
	var groupType int32

	// Set scope flags (mutually exclusive)
	switch scope {
	case GroupScopeGlobal:
		groupType |= GroupTypeFlagGlobal
	case GroupScopeDomainLocal:
		groupType |= GroupTypeFlagDomainLocal
	case GroupScopeUniversal:
		groupType |= GroupTypeFlagUniversal
	default:
		// Default to Global if unrecognized
		groupType |= GroupTypeFlagGlobal
	}

	// Set category flag
	if category == GroupCategorySecurity {
		groupType |= GroupTypeFlagSecurity
	}
	// Distribution groups don't have the security flag set

	return groupType
}

// ParseGroupType extracts scope and category from an Active Directory groupType value.
func ParseGroupType(groupType int32) (GroupScope, GroupCategory) {
	var scope GroupScope
	var category GroupCategory

	// Determine scope
	switch {
	case groupType&GroupTypeFlagGlobal != 0:
		scope = GroupScopeGlobal
	case groupType&GroupTypeFlagDomainLocal != 0:
		scope = GroupScopeDomainLocal
	case groupType&GroupTypeFlagUniversal != 0:
		scope = GroupScopeUniversal
	default:
		scope = GroupScopeGlobal // Default fallback
	}

	// Determine category
	if groupType&GroupTypeFlagSecurity != 0 {
		category = GroupCategorySecurity
	} else {
		category = GroupCategoryDistribution
	}

	return scope, category
}

// ValidateGroupRequest validates a group creation request.
func (gm *GroupManager) ValidateGroupRequest(req *CreateGroupRequest) error {
	if req == nil {
		return fmt.Errorf("create group request cannot be nil")
	}

	if req.Name == "" {
		return fmt.Errorf("group name is required")
	}

	if req.SAMAccountName == "" {
		return fmt.Errorf("SAM account name is required")
	}

	if req.Container == "" {
		return fmt.Errorf("container DN is required")
	}

	// Validate scope
	switch req.Scope {
	case GroupScopeGlobal, GroupScopeDomainLocal, GroupScopeUniversal:
		// Valid scopes
	default:
		return fmt.Errorf("invalid group scope: %s (valid: Global, DomainLocal, Universal)", req.Scope)
	}

	// Validate category
	switch req.Category {
	case GroupCategorySecurity, GroupCategoryDistribution:
		// Valid categories
	default:
		return fmt.Errorf("invalid group category: %s (valid: Security, Distribution)", req.Category)
	}

	// Validate SAM account name format (no spaces, certain special characters)
	if strings.ContainsAny(req.SAMAccountName, " \t\n\r@\"#$%&'()*+,/:;<=>?[\\]^`{|}~") {
		return fmt.Errorf("SAM account name contains invalid characters: %s", req.SAMAccountName)
	}

	// For distribution groups, validate email if provided
	if req.Category == GroupCategoryDistribution && req.Mail != "" {
		if !strings.Contains(req.Mail, "@") || !strings.Contains(req.Mail, ".") {
			return fmt.Errorf("invalid email address format: %s", req.Mail)
		}
	}

	return nil
}

// CreateGroup creates a new Active Directory group.
func (gm *GroupManager) CreateGroup(ctx context.Context, req *CreateGroupRequest) (*Group, error) {
	if err := gm.ValidateGroupRequest(req); err != nil {
		return nil, WrapError("create_group_validation", err)
	}

	// Build the group DN
	groupDN := fmt.Sprintf("CN=%s,%s", ldap.EscapeFilter(req.Name), req.Container)

	// Calculate group type
	groupType := CalculateGroupType(req.Scope, req.Category)

	// Build attributes for group creation
	attributes := map[string][]string{
		"objectClass":    {"top", "group"},
		"cn":             {req.Name},
		"sAMAccountName": {req.SAMAccountName},
		"groupType":      {strconv.FormatInt(int64(groupType), 10)},
	}

	// Add optional attributes
	if req.Description != "" {
		attributes["description"] = []string{req.Description}
	}

	if req.Mail != "" {
		attributes["mail"] = []string{req.Mail}
	}

	if req.MailNickname != "" {
		attributes["mailNickname"] = []string{req.MailNickname}
	}

	// Create the group
	addReq := &AddRequest{
		DN:         groupDN,
		Attributes: attributes,
	}

	if err := gm.client.Add(ctx, addReq); err != nil {
		return nil, WrapError("create_group", err)
	}

	// Retrieve the created group to get its GUID and other computed attributes
	group, err := gm.getGroupByDN(ctx, groupDN)
	if err != nil {
		return nil, WrapError("retrieve_created_group", err)
	}

	return group, nil
}

// GetGroup retrieves a group by its objectGUID.
func (gm *GroupManager) GetGroup(ctx context.Context, guid string) (*Group, error) {
	if guid == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	// Validate GUID format
	if !gm.guidHandler.IsValidGUID(guid) {
		return nil, fmt.Errorf("invalid GUID format: %s", guid)
	}

	// Create GUID search request
	searchReq, err := gm.guidHandler.GenerateGUIDSearchRequest(gm.baseDN, guid)
	if err != nil {
		return nil, WrapError("generate_guid_search", err)
	}

	// Expand attributes to include all group-relevant fields
	searchReq.Attributes = []string{
		"objectGUID", "distinguishedName", "objectSid", "cn", "sAMAccountName",
		"description", "groupType", "mail", "mailNickname", "member", "memberOf",
		"whenCreated", "whenChanged",
	}
	searchReq.TimeLimit = gm.timeout

	result, err := gm.client.Search(ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_group_by_guid", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewLDAPError("get_group", fmt.Errorf("group with GUID %s not found", guid))
	}

	group, err := gm.entryToGroup(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_group_entry", err)
	}

	return group, nil
}

// GetGroupByDN retrieves a group by its distinguished name.
func (gm *GroupManager) GetGroupByDN(ctx context.Context, dn string) (*Group, error) {
	if dn == "" {
		return nil, fmt.Errorf("group DN cannot be empty")
	}

	return gm.getGroupByDN(ctx, dn)
}

// getGroupByDN is the internal implementation for DN-based group retrieval.
func (gm *GroupManager) getGroupByDN(ctx context.Context, dn string) (*Group, error) {
	searchReq := &SearchRequest{
		BaseDN: dn,
		Scope:  ScopeBaseObject,
		Filter: "(objectClass=group)",
		Attributes: []string{
			"objectGUID", "distinguishedName", "objectSid", "cn", "sAMAccountName",
			"description", "groupType", "mail", "mailNickname", "member", "memberOf",
			"whenCreated", "whenChanged",
		},
		SizeLimit: 1,
		TimeLimit: gm.timeout,
	}

	result, err := gm.client.Search(ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_group_by_dn", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewLDAPError("get_group_by_dn", fmt.Errorf("group not found at DN: %s", dn))
	}

	group, err := gm.entryToGroup(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_group_entry", err)
	}

	return group, nil
}

// UpdateGroup updates an existing group.
func (gm *GroupManager) UpdateGroup(ctx context.Context, guid string, req *UpdateGroupRequest) (*Group, error) {
	if guid == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	if req == nil {
		return nil, fmt.Errorf("update group request cannot be nil")
	}

	// Get current group to determine DN and validate changes
	currentGroup, err := gm.GetGroup(ctx, guid)
	if err != nil {
		return nil, WrapError("get_current_group", err)
	}

	// Build modification request
	modReq := &ModifyRequest{
		DN:                currentGroup.DistinguishedName,
		ReplaceAttributes: make(map[string][]string),
	}

	hasChanges := false

	// Handle name change (affects CN)
	if req.Name != nil && *req.Name != currentGroup.Name {
		modReq.ReplaceAttributes["cn"] = []string{*req.Name}
		hasChanges = true
	}

	// Handle description change
	if req.Description != nil {
		if *req.Description == "" {
			// Delete description if empty string provided
			modReq.DeleteAttributes = append(modReq.DeleteAttributes, "description")
		} else {
			modReq.ReplaceAttributes["description"] = []string{*req.Description}
		}
		hasChanges = true
	}

	// Handle mail change
	if req.Mail != nil {
		if *req.Mail == "" {
			// Delete mail if empty string provided
			modReq.DeleteAttributes = append(modReq.DeleteAttributes, "mail")
		} else {
			// Validate email format
			if !strings.Contains(*req.Mail, "@") || !strings.Contains(*req.Mail, ".") {
				return nil, fmt.Errorf("invalid email address format: %s", *req.Mail)
			}
			modReq.ReplaceAttributes["mail"] = []string{*req.Mail}
		}
		hasChanges = true
	}

	// Handle mail nickname change
	if req.MailNickname != nil {
		if *req.MailNickname == "" {
			modReq.DeleteAttributes = append(modReq.DeleteAttributes, "mailNickname")
		} else {
			modReq.ReplaceAttributes["mailNickname"] = []string{*req.MailNickname}
		}
		hasChanges = true
	}

	// Handle scope or category changes (requires groupType recalculation)
	if req.Scope != nil || req.Category != nil {
		newScope := currentGroup.Scope
		newCategory := currentGroup.Category

		if req.Scope != nil {
			newScope = *req.Scope
		}
		if req.Category != nil {
			newCategory = *req.Category
		}

		// Validate scope conversion
		if req.Scope != nil && *req.Scope != currentGroup.Scope {
			if err := gm.validateScopeChange(currentGroup.Scope, *req.Scope); err != nil {
				return nil, WrapError("validate_scope_change", err)
			}
		}

		newGroupType := CalculateGroupType(newScope, newCategory)
		if newGroupType != currentGroup.GroupType {
			modReq.ReplaceAttributes["groupType"] = []string{strconv.FormatInt(int64(newGroupType), 10)}
			hasChanges = true
		}
	}

	if !hasChanges {
		// No changes needed, return current group
		return currentGroup, nil
	}

	// Apply modifications
	if err := gm.client.Modify(ctx, modReq); err != nil {
		return nil, WrapError("modify_group", err)
	}

	// Retrieve updated group
	updatedGroup, err := gm.GetGroup(ctx, guid)
	if err != nil {
		return nil, WrapError("retrieve_updated_group", err)
	}

	return updatedGroup, nil
}

// DeleteGroup deletes a group by its objectGUID.
func (gm *GroupManager) DeleteGroup(ctx context.Context, guid string) error {
	if guid == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	// Get group to determine DN
	group, err := gm.GetGroup(ctx, guid)
	if err != nil {
		// Check if it's a "not found" error
		if ldapErr, ok := err.(*LDAPError); ok {
			if ldapErr.Message == fmt.Sprintf("group with GUID %s not found", guid) {
				// Group already doesn't exist
				return nil
			}
		}
		return WrapError("get_group_for_deletion", err)
	}

	// Delete the group
	if err := gm.client.Delete(ctx, group.DistinguishedName); err != nil {
		return WrapError("delete_group", err)
	}

	return nil
}

// AddMembers adds members to a group.
func (gm *GroupManager) AddMembers(ctx context.Context, groupGUID string, members []string) error {
	if groupGUID == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	if len(members) == 0 {
		return nil // Nothing to add
	}

	// Get group DN
	group, err := gm.GetGroup(ctx, groupGUID)
	if err != nil {
		return WrapError("get_group_for_add_members", err)
	}

	// Normalize member identifiers to DNs
	memberDNs, err := gm.normalizer.NormalizeToDNBatch(members)
	if err != nil {
		return WrapError("normalize_member_identifiers", err)
	}

	// Extract just the DN values
	dnList := make([]string, 0, len(memberDNs))
	for _, dn := range memberDNs {
		dnList = append(dnList, dn)
	}

	// Add members using LDAP modify operation
	modReq := &ModifyRequest{
		DN:            group.DistinguishedName,
		AddAttributes: map[string][]string{"member": dnList},
	}

	if err := gm.client.Modify(ctx, modReq); err != nil {
		// Handle case where some members might already exist
		if IsConflictError(err) {
			// Try adding members one by one to identify which ones fail
			return gm.addMembersIndividually(ctx, group.DistinguishedName, dnList)
		}
		return WrapError("add_members", err)
	}

	return nil
}

// RemoveMembers removes members from a group.
func (gm *GroupManager) RemoveMembers(ctx context.Context, groupGUID string, members []string) error {
	if groupGUID == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	if len(members) == 0 {
		return nil // Nothing to remove
	}

	// Get group DN
	group, err := gm.GetGroup(ctx, groupGUID)
	if err != nil {
		return WrapError("get_group_for_remove_members", err)
	}

	// Normalize member identifiers to DNs
	memberDNs, err := gm.normalizer.NormalizeToDNBatch(members)
	if err != nil {
		return WrapError("normalize_member_identifiers", err)
	}

	// Extract just the DN values
	dnList := make([]string, 0, len(memberDNs))
	for _, dn := range memberDNs {
		dnList = append(dnList, dn)
	}

	// Remove members using LDAP modify operation
	modReq := &ModifyRequest{
		DN:                group.DistinguishedName,
		ReplaceAttributes: make(map[string][]string), // Initialize empty map
	}

	// For member removal, we need to specify exact DNs to delete
	// We'll use a replace operation with the current members minus the ones to remove
	currentMembers := group.MemberDNs
	newMembers := make([]string, 0, len(currentMembers))

	// Create a map of members to remove for quick lookup
	toRemove := make(map[string]bool)
	for _, dn := range dnList {
		toRemove[strings.ToLower(dn)] = true
	}

	// Filter out members to be removed
	for _, member := range currentMembers {
		if !toRemove[strings.ToLower(member)] {
			newMembers = append(newMembers, member)
		}
	}

	// Replace member attribute with filtered list
	if len(newMembers) == 0 {
		// Remove all members by deleting the attribute
		modReq.DeleteAttributes = []string{"member"}
	} else {
		modReq.ReplaceAttributes["member"] = newMembers
	}

	if err := gm.client.Modify(ctx, modReq); err != nil {
		return WrapError("remove_members", err)
	}

	return nil
}

// GetMembers retrieves all members of a group.
func (gm *GroupManager) GetMembers(ctx context.Context, groupGUID string) ([]string, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	group, err := gm.GetGroup(ctx, groupGUID)
	if err != nil {
		return nil, WrapError("get_group_for_members", err)
	}

	return group.MemberDNs, nil
}

// SearchGroups searches for groups using various criteria.
func (gm *GroupManager) SearchGroups(ctx context.Context, filter string, attributes []string) ([]*Group, error) {
	if filter == "" {
		filter = "(objectClass=group)"
	} else {
		// Ensure we're only searching for groups
		filter = fmt.Sprintf("(&(objectClass=group)%s)", filter)
	}

	if len(attributes) == 0 {
		attributes = []string{
			"objectGUID", "distinguishedName", "objectSid", "cn", "sAMAccountName",
			"description", "groupType", "mail", "mailNickname", "whenCreated", "whenChanged",
		}
	}

	searchReq := &SearchRequest{
		BaseDN:     gm.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: attributes,
		TimeLimit:  gm.timeout,
	}

	result, err := gm.client.SearchWithPaging(ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_groups", err)
	}

	groups := make([]*Group, 0, len(result.Entries))
	for _, entry := range result.Entries {
		group, err := gm.entryToGroup(entry)
		if err != nil {
			// Log error but continue with other entries
			continue
		}
		groups = append(groups, group)
	}

	return groups, nil
}

// entryToGroup converts an LDAP entry to a Group struct.
func (gm *GroupManager) entryToGroup(entry *ldap.Entry) (*Group, error) {
	if entry == nil {
		return nil, fmt.Errorf("LDAP entry cannot be nil")
	}

	group := &Group{}

	// Extract GUID
	guid, err := gm.guidHandler.ExtractGUID(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to extract GUID: %w", err)
	}
	group.ObjectGUID = guid

	// Basic attributes
	group.DistinguishedName = entry.DN
	group.ObjectSid = entry.GetAttributeValue("objectSid")
	group.Name = entry.GetAttributeValue("cn")
	group.SAMAccountName = entry.GetAttributeValue("sAMAccountName")
	group.Description = entry.GetAttributeValue("description")
	group.Mail = entry.GetAttributeValue("mail")
	group.MailNickname = entry.GetAttributeValue("mailNickname")

	// Parse group type
	groupTypeStr := entry.GetAttributeValue("groupType")
	if groupTypeStr != "" {
		if groupTypeInt, err := strconv.ParseInt(groupTypeStr, 10, 32); err == nil {
			group.GroupType = int32(groupTypeInt)
			group.Scope, group.Category = ParseGroupType(group.GroupType)
		}
	}

	// Extract container from DN
	if group.DistinguishedName != "" {
		// Parse DN to get parent container
		if parsedDN, err := ldap.ParseDN(group.DistinguishedName); err == nil && len(parsedDN.RDNs) > 1 {
			// Reconstruct container DN from all RDNs except the first (which is the group's CN)
			containerRDNs := parsedDN.RDNs[1:]
			containerDN := &ldap.DN{RDNs: containerRDNs}
			group.Container = containerDN.String()
		}
	}

	// Extract members
	group.MemberDNs = entry.GetAttributeValues("member")

	// Extract member of
	group.MemberOf = entry.GetAttributeValues("memberOf")

	// Parse timestamps
	if whenCreated := entry.GetAttributeValue("whenCreated"); whenCreated != "" {
		if t, err := time.Parse("20060102150405.0Z", whenCreated); err == nil {
			group.WhenCreated = t
		}
	}

	if whenChanged := entry.GetAttributeValue("whenChanged"); whenChanged != "" {
		if t, err := time.Parse("20060102150405.0Z", whenChanged); err == nil {
			group.WhenChanged = t
		}
	}

	return group, nil
}

// addMembersIndividually adds members one by one to handle partial conflicts.
func (gm *GroupManager) addMembersIndividually(ctx context.Context, groupDN string, memberDNs []string) error {
	var lastNonConflictErr error
	successCount := 0
	conflictCount := 0

	for _, memberDN := range memberDNs {
		modReq := &ModifyRequest{
			DN:            groupDN,
			AddAttributes: map[string][]string{"member": {memberDN}},
		}

		if err := gm.client.Modify(ctx, modReq); err != nil {
			if IsConflictError(err) {
				// Member already exists, count as conflict but continue
				conflictCount++
				continue
			}
			lastNonConflictErr = err
		} else {
			successCount++
		}
	}

	// If we had actual non-conflict errors and no successes, return the error
	if successCount == 0 && lastNonConflictErr != nil {
		return lastNonConflictErr
	}

	// If we only had conflicts or successes, that's acceptable
	return nil
}

// validateScopeChange validates whether a group scope change is allowed.
func (gm *GroupManager) validateScopeChange(currentScope, newScope GroupScope) error {
	// Some scope changes are not allowed in Active Directory
	// Reference: https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups

	if currentScope == newScope {
		return nil // No change
	}

	// Global to Universal: Allowed if group is not a member of any other global group
	if currentScope == GroupScopeGlobal && newScope == GroupScopeUniversal {
		return nil // Will be validated by AD at modification time
	}

	// Universal to Global: Allowed if group has no universal group members
	if currentScope == GroupScopeUniversal && newScope == GroupScopeGlobal {
		return nil // Will be validated by AD at modification time
	}

	// Domain Local to Universal: Allowed if group has no other domain local groups as members
	if currentScope == GroupScopeDomainLocal && newScope == GroupScopeUniversal {
		return nil // Will be validated by AD at modification time
	}

	// Universal to Domain Local: Always allowed
	if currentScope == GroupScopeUniversal && newScope == GroupScopeDomainLocal {
		return nil
	}

	// Direct conversions between Global and Domain Local are not allowed
	if (currentScope == GroupScopeGlobal && newScope == GroupScopeDomainLocal) ||
		(currentScope == GroupScopeDomainLocal && newScope == GroupScopeGlobal) {
		return fmt.Errorf("direct conversion from %s to %s is not allowed - must convert via Universal scope first", currentScope, newScope)
	}

	return nil
}

// ListGroupsByContainer lists all groups in a specific container.
func (gm *GroupManager) ListGroupsByContainer(ctx context.Context, containerDN string) ([]*Group, error) {
	if containerDN == "" {
		containerDN = gm.baseDN
	}

	filter := "(objectClass=group)"
	return gm.SearchGroups(ctx, filter, nil)
}

// GetGroupStats returns statistics about groups in the directory.
func (gm *GroupManager) GetGroupStats(ctx context.Context) (map[string]int, error) {
	stats := make(map[string]int)

	// Count total groups
	allGroups, err := gm.SearchGroups(ctx, "", []string{"groupType"})
	if err != nil {
		return nil, WrapError("get_group_stats", err)
	}

	stats["total"] = len(allGroups)

	// Count by scope and category
	for _, group := range allGroups {
		stats[fmt.Sprintf("scope_%s", strings.ToLower(string(group.Scope)))]++
		stats[fmt.Sprintf("category_%s", strings.ToLower(string(group.Category)))]++
	}

	return stats, nil
}
