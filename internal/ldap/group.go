package ldap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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

// Active Directory group type bit flags.
const (
	// Group scope flags (mutually exclusive).
	GroupTypeFlagGlobal      int32 = 0x00000002 // ADS_GROUP_TYPE_GLOBAL_GROUP
	GroupTypeFlagDomainLocal int32 = 0x00000004 // ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP
	GroupTypeFlagUniversal   int32 = 0x00000008 // ADS_GROUP_TYPE_UNIVERSAL_GROUP

	// Group category flag.
	GroupTypeFlagSecurity int32 = -2147483648 // ADS_GROUP_TYPE_SECURITY_ENABLED (0x80000000 as signed int32)
)

// GroupSearchFilter represents user-friendly filter options for searching groups.
type GroupSearchFilter struct {
	// Name filters
	NamePrefix   string `json:"namePrefix,omitempty"`   // Groups whose name starts with this string
	NameSuffix   string `json:"nameSuffix,omitempty"`   // Groups whose name ends with this string
	NameContains string `json:"nameContains,omitempty"` // Groups whose name contains this string

	// Type filters
	Category string `json:"category,omitempty"` // "security", "distribution", or empty for both
	Scope    string `json:"scope,omitempty"`    // "global", "domainlocal", "universal", or empty for all

	// Location filter
	Container string `json:"container,omitempty"` // Specific OU to search, empty for base DN

	// Membership filter
	HasMembers *bool `json:"hasMembers,omitempty"` // true=groups with members, false=empty groups, nil=all

	// Group membership filters (supports nested groups via LDAP_MATCHING_RULE_IN_CHAIN)
	MemberOf  string `json:"memberOf,omitempty"`  // Filter groups that are members of specified group (DN)
	HasMember string `json:"hasMember,omitempty"` // Filter groups that contain specified member (DN)
}

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
	WhenCreated time.Time `json:"whenCreated"`
	WhenChanged time.Time `json:"whenChanged"`
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
	Name           *string        `json:"name,omitempty"`           // Optional: New group name
	SAMAccountName *string        `json:"samAccountName,omitempty"` // Optional: New SAM account name
	Description    *string        `json:"description,omitempty"`    // Optional: New description
	Mail           *string        `json:"mail,omitempty"`           // Optional: New email address
	MailNickname   *string        `json:"mailNickname,omitempty"`   // Optional: New mail nickname
	Scope          *GroupScope    `json:"scope,omitempty"`          // Optional: New scope (limited conversions)
	Category       *GroupCategory `json:"category,omitempty"`       // Optional: New category
	Container      *string        `json:"container,omitempty"`      // Optional: New container DN (triggers move)
}

// GroupManager handles Active Directory group operations.
type GroupManager struct {
	ctx          context.Context
	client       Client
	guidHandler  *GUIDHandler
	sidHandler   *SIDHandler
	normalizer   *MemberNormalizer
	baseDN       string
	timeout      time.Duration
	cacheManager *CacheManager // Reference to shared cache
}

// NewGroupManager creates a new group manager instance.
func NewGroupManager(ctx context.Context, client Client, baseDN string, cacheManager *CacheManager) *GroupManager {
	return &GroupManager{
		ctx:          ctx,
		client:       client,
		guidHandler:  NewGUIDHandler(),
		sidHandler:   NewSIDHandler(),
		normalizer:   NewMemberNormalizer(client, baseDN, cacheManager),
		baseDN:       baseDN,
		timeout:      30 * time.Second,
		cacheManager: cacheManager,
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
func (gm *GroupManager) CreateGroup(req *CreateGroupRequest) (*Group, error) {
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

	if err := gm.client.Add(gm.ctx, addReq); err != nil {
		return nil, WrapError("create_group", err)
	}

	// Retrieve the created group to get its GUID and other computed attributes
	group, err := gm.getGroupByDN(groupDN)
	if err != nil {
		return nil, WrapError("retrieve_created_group", err)
	}

	return group, nil
}

// GetGroup retrieves a group by its objectGUID.
func (gm *GroupManager) GetGroup(guid string) (*Group, error) {
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

	result, err := gm.client.Search(gm.ctx, searchReq)
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
func (gm *GroupManager) GetGroupByDN(dn string) (*Group, error) {
	if dn == "" {
		return nil, fmt.Errorf("group DN cannot be empty")
	}

	return gm.getGroupByDN(dn)
}

// getGroupByDN is the internal implementation for DN-based group retrieval.
func (gm *GroupManager) getGroupByDN(dn string) (*Group, error) {
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

	result, err := gm.client.Search(gm.ctx, searchReq)
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
func (gm *GroupManager) UpdateGroup(guid string, req *UpdateGroupRequest) (*Group, error) {
	if guid == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	if req == nil {
		return nil, fmt.Errorf("update group request cannot be nil")
	}

	// Get current group to determine DN and validate changes
	currentGroup, err := gm.GetGroup(guid)
	if err != nil {
		return nil, WrapError("get_current_group", err)
	}

	// Build modification request
	modReq := &ModifyRequest{
		DN:                currentGroup.DistinguishedName,
		ReplaceAttributes: make(map[string][]string),
	}

	// Handle name and/or container changes (both require ModifyDN)
	needsRename := req.Name != nil && *req.Name != currentGroup.Name
	needsMove := req.Container != nil && !strings.EqualFold(*req.Container, currentGroup.Container)

	var renamedOrMovedGroup *Group
	if needsRename || needsMove {
		// Determine the new RDN and container
		newName := currentGroup.Name
		if needsRename {
			newName = *req.Name
		}

		newContainer := currentGroup.Container
		if needsMove {
			newContainer = *req.Container
		}

		// Use ModifyDN to rename and/or move the group
		var err error
		renamedOrMovedGroup, err = gm.renameAndMoveGroup(currentGroup, newName, newContainer)
		if err != nil {
			return nil, WrapError("rename_or_move_group", err)
		}
	}

	// Track attribute changes separately (for LDAP Modify operation)
	hasAttributeChanges := false

	// Handle SAM account name change
	if req.SAMAccountName != nil && *req.SAMAccountName != currentGroup.SAMAccountName {
		modReq.ReplaceAttributes["sAMAccountName"] = []string{*req.SAMAccountName}
		hasAttributeChanges = true
	}

	// Handle description change
	if req.Description != nil {
		if *req.Description == "" {
			// Delete description if empty string provided
			modReq.DeleteAttributes = append(modReq.DeleteAttributes, "description")
		} else {
			modReq.ReplaceAttributes["description"] = []string{*req.Description}
		}
		hasAttributeChanges = true
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
		hasAttributeChanges = true
	}

	// Handle mail nickname change
	if req.MailNickname != nil {
		if *req.MailNickname == "" {
			modReq.DeleteAttributes = append(modReq.DeleteAttributes, "mailNickname")
		} else {
			modReq.ReplaceAttributes["mailNickname"] = []string{*req.MailNickname}
		}
		hasAttributeChanges = true
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
			hasAttributeChanges = true
		}
	}

	// Check if we have any changes at all
	if !hasAttributeChanges && renamedOrMovedGroup == nil {
		// No changes at all, return current group
		return currentGroup, nil
	}

	// If we only renamed/moved but have no attribute changes, return the renamed/moved group
	if !hasAttributeChanges && renamedOrMovedGroup != nil {
		return renamedOrMovedGroup, nil
	}

	// Apply attribute modifications if we have any
	if hasAttributeChanges {
		// Update the DN for the modify request if the group was renamed/moved
		if renamedOrMovedGroup != nil {
			// Update the DN for the modify request since the group was renamed/moved
			modReq.DN = renamedOrMovedGroup.DistinguishedName
		}

		// Apply modifications
		if err := gm.client.Modify(gm.ctx, modReq); err != nil {
			return nil, WrapError("modify_group", err)
		}
	}

	// Retrieve final updated group
	updatedGroup, err := gm.GetGroup(guid)
	if err != nil {
		return nil, WrapError("retrieve_updated_group", err)
	}

	return updatedGroup, nil
}

// renameAndMoveGroup handles renaming and/or moving a group using ModifyDN operation.
func (gm *GroupManager) renameAndMoveGroup(currentGroup *Group, newName, newContainer string) (*Group, error) {
	// Check if any actual change is needed
	if newName == currentGroup.Name && strings.EqualFold(newContainer, currentGroup.Container) {
		// No change needed
		return currentGroup, nil
	}

	// Parse the current DN to understand its structure
	parsedDN, err := ldap.ParseDN(currentGroup.DistinguishedName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse current DN: %w", err)
	}

	if len(parsedDN.RDNs) == 0 {
		return nil, fmt.Errorf("invalid DN structure")
	}

	// Create the new RDN
	var newRDN string
	if newName == currentGroup.Name {
		// Name didn't change, use existing RDN
		newRDN = parsedDN.RDNs[0].String()
	} else {
		// Name changed, create new RDN with escaped name
		newRDN = fmt.Sprintf("cn=%s", ldap.EscapeFilter(newName))
	}

	// Determine if we need to specify a new superior (container)
	var newSuperior string
	if !strings.EqualFold(newContainer, currentGroup.Container) {
		newSuperior = newContainer
	}

	// Create the ModifyDN request
	modifyDNReq := &ModifyDNRequest{
		DN:           currentGroup.DistinguishedName,
		NewRDN:       newRDN,
		DeleteOldRDN: true,
		NewSuperior:  newSuperior,
	}

	// Execute the ModifyDN operation
	if err := gm.client.ModifyDN(gm.ctx, modifyDNReq); err != nil {
		return nil, WrapError("modify_dn", err)
	}

	// Retrieve and return the updated group
	updatedGroup, err := gm.GetGroup(currentGroup.ObjectGUID)
	if err != nil {
		return nil, WrapError("retrieve_renamed_moved_group", err)
	}

	return updatedGroup, nil
}

// MoveGroup moves a group to a different organizational unit.
func (gm *GroupManager) MoveGroup(groupGUID string, newContainerDN string) (*Group, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	if newContainerDN == "" {
		return nil, fmt.Errorf("new container DN cannot be empty")
	}

	// Get the current group to obtain its DN and CN
	group, err := gm.GetGroup(groupGUID)
	if err != nil {
		return nil, WrapError("get_group_for_move", err)
	}

	// Check if already in the target container
	if strings.EqualFold(group.Container, newContainerDN) {
		// Already in the target location, no move needed
		return group, nil
	}

	// Parse the current DN to extract the RDN (CN=GroupName)
	parsedDN, err := ldap.ParseDN(group.DistinguishedName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse group DN: %w", err)
	}

	if len(parsedDN.RDNs) == 0 {
		return nil, fmt.Errorf("invalid DN structure")
	}

	// Get the RDN (first component, e.g., "CN=GroupName")
	rdn := parsedDN.RDNs[0].String()

	// Create the ModifyDN request
	modifyDNReq := &ModifyDNRequest{
		DN:           group.DistinguishedName,
		NewRDN:       rdn,
		DeleteOldRDN: true,
		NewSuperior:  newContainerDN,
	}

	// Execute the move operation
	if err := gm.client.ModifyDN(gm.ctx, modifyDNReq); err != nil {
		return nil, WrapError("move_group", err)
	}

	// Retrieve the group from its new location to get updated DN
	// The objectGUID remains the same, so we can still use it
	movedGroup, err := gm.GetGroup(groupGUID)
	if err != nil {
		return nil, WrapError("get_moved_group", err)
	}

	return movedGroup, nil
}

// DeleteGroup deletes a group by its objectGUID.
func (gm *GroupManager) DeleteGroup(guid string) error {
	if guid == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	// Get group to determine DN
	group, err := gm.GetGroup(guid)
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
	if err := gm.client.Delete(gm.ctx, group.DistinguishedName); err != nil {
		return WrapError("delete_group", err)
	}

	return nil
}

// AddMembers adds members to a group.
func (gm *GroupManager) AddMembers(groupGUID string, members []string) error {
	if groupGUID == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	if len(members) == 0 {
		return nil // Nothing to add
	}

	// Get group DN
	group, err := gm.GetGroup(groupGUID)
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

	if err := gm.client.Modify(gm.ctx, modReq); err != nil {
		// Handle case where some members might already exist
		if IsConflictError(err) {
			// Try adding members one by one to identify which ones fail
			return gm.addMembersIndividually(group.DistinguishedName, dnList)
		}
		return WrapError("add_members", err)
	}

	return nil
}

// RemoveMembers removes members from a group.
func (gm *GroupManager) RemoveMembers(groupGUID string, members []string) error {
	if groupGUID == "" {
		return fmt.Errorf("group GUID cannot be empty")
	}

	if len(members) == 0 {
		return nil // Nothing to remove
	}

	// Get group DN
	group, err := gm.GetGroup(groupGUID)
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

	if err := gm.client.Modify(gm.ctx, modReq); err != nil {
		return WrapError("remove_members", err)
	}

	return nil
}

// GetMembers retrieves all members of a group.
func (gm *GroupManager) GetMembers(groupGUID string) ([]string, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	group, err := gm.GetGroup(groupGUID)
	if err != nil {
		return nil, WrapError("get_group_for_members", err)
	}

	return group.MemberDNs, nil
}

// SearchGroupsWithFilter searches for groups using user-friendly filter criteria.
func (gm *GroupManager) SearchGroupsWithFilter(filter *GroupSearchFilter) ([]*Group, error) {
	start := time.Now()

	filterFields := map[string]any{
		"operation": "search_groups_with_filter",
	}

	if filter == nil {
		filterFields["filter_type"] = "empty"
		tflog.Debug(gm.ctx, "SearchGroupsWithFilter called with nil filter, using default search", filterFields)
		return gm.SearchGroups("", nil)
	}

	// Add filter details to logging fields
	if filter.Container != "" {
		filterFields["container"] = filter.Container
	}
	if filter.NamePrefix != "" {
		filterFields["name_prefix"] = filter.NamePrefix
	}
	if filter.NameSuffix != "" {
		filterFields["name_suffix"] = filter.NameSuffix
	}
	if filter.NameContains != "" {
		filterFields["name_contains"] = filter.NameContains
	}
	if filter.Category != "" {
		filterFields["category"] = filter.Category
	}
	if filter.Scope != "" {
		filterFields["scope"] = filter.Scope
	}
	if filter.HasMembers != nil {
		filterFields["has_members"] = *filter.HasMembers
	}

	tflog.Debug(gm.ctx, "Starting SearchGroupsWithFilter", filterFields)

	// Validate filter values
	if err := gm.validateSearchFilter(filter); err != nil {
		filterFields["operation"] = "validate_search_filter"
		filterFields["error"] = err.Error()
		filterFields["duration_ms"] = time.Since(start).Milliseconds()

		// Add LDAP-specific error information if available
		if ldapErr, ok := err.(*ldap.Error); ok {
			filterFields["ldap_result_code"] = ldapErr.ResultCode
			if ldapErr.MatchedDN != "" {
				filterFields["ldap_matched_dn"] = ldapErr.MatchedDN
			}
			if ldapErr.Err != nil {
				filterFields["ldap_diagnostic_message"] = ldapErr.Err.Error()
			}
		}

		tflog.Error(gm.ctx, "LDAP validate search filter operation failed", filterFields)
		return nil, WrapError("validate_search_filter", err)
	}

	// Convert user-friendly filter to LDAP filter
	ldapFilter := gm.buildLDAPFilter(filter)
	filterFields["ldap_filter"] = ldapFilter

	// Determine search base DN (container or baseDN)
	searchBaseDN := gm.baseDN
	if filter.Container != "" {
		searchBaseDN = filter.Container
	}
	filterFields["search_base_dn"] = searchBaseDN

	tflog.Debug(gm.ctx, "Filter validation complete, executing search", filterFields)

	// Perform search using existing SearchGroups method with custom base DN
	groups, err := gm.searchGroupsInContainer(searchBaseDN, ldapFilter, nil)

	duration := time.Since(start)
	filterFields["duration_ms"] = duration.Milliseconds()

	if err != nil {
		filterFields["operation"] = "search_groups_with_filter"
		filterFields["error"] = err.Error()

		// Add LDAP-specific error information if available
		if ldapErr, ok := err.(*ldap.Error); ok {
			filterFields["ldap_result_code"] = ldapErr.ResultCode
			if ldapErr.MatchedDN != "" {
				filterFields["ldap_matched_dn"] = ldapErr.MatchedDN
			}
			if ldapErr.Err != nil {
				filterFields["ldap_diagnostic_message"] = ldapErr.Err.Error()
			}
		}

		tflog.Error(gm.ctx, "LDAP search groups with filter operation failed", filterFields)
		return nil, err
	}

	filterFields["groups_found"] = len(groups)
	tflog.Info(gm.ctx, "SearchGroupsWithFilter completed", filterFields)

	return groups, nil
}

// SearchGroups searches for groups using various criteria.
func (gm *GroupManager) SearchGroups(filter string, attributes []string) ([]*Group, error) {
	start := time.Now()

	originalFilter := filter
	if filter == "" {
		filter = "(objectClass=group)"
	} else {
		// Ensure we're only searching for groups
		filter = fmt.Sprintf("(&(objectClass=group)%s)", filter)
	}

	searchFields := map[string]any{
		"operation":       "search_groups",
		"base_dn":         gm.baseDN,
		"original_filter": originalFilter,
		"final_filter":    filter,
		"attributes":      attributes,
		"timeout":         gm.timeout.String(),
	}

	tflog.Debug(gm.ctx, "Starting SearchGroups", searchFields)

	if len(attributes) == 0 {
		attributes = []string{
			"objectGUID", "distinguishedName", "objectSid", "cn", "sAMAccountName",
			"description", "groupType", "mail", "mailNickname", "whenCreated", "whenChanged",
		}
		searchFields["attributes"] = attributes
		tflog.Trace(gm.ctx, "Using default attributes for group search", searchFields)
	}

	searchReq := &SearchRequest{
		BaseDN:     gm.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: attributes,
		TimeLimit:  gm.timeout,
	}

	tflog.Debug(gm.ctx, "Executing paged search for groups", searchFields)

	result, err := gm.client.SearchWithPaging(gm.ctx, searchReq)
	if err != nil {
		searchFields["operation"] = "search_groups"
		searchFields["error"] = err.Error()
		searchFields["duration_ms"] = time.Since(start).Milliseconds()

		// Add LDAP-specific error information if available
		if ldapErr, ok := err.(*ldap.Error); ok {
			searchFields["ldap_result_code"] = ldapErr.ResultCode
			if ldapErr.MatchedDN != "" {
				searchFields["ldap_matched_dn"] = ldapErr.MatchedDN
			}
			if ldapErr.Err != nil {
				searchFields["ldap_diagnostic_message"] = ldapErr.Err.Error()
			}
		}

		tflog.Error(gm.ctx, "LDAP search groups operation failed", searchFields)
		return nil, WrapError("search_groups", err)
	}

	searchFields["raw_entries_found"] = len(result.Entries)
	tflog.Trace(gm.ctx, "Raw LDAP search completed, processing entries", searchFields)

	groups := make([]*Group, 0, len(result.Entries))
	processErrors := 0
	for i, entry := range result.Entries {
		group, err := gm.entryToGroup(entry)
		if err != nil {
			processErrors++
			errorFields := map[string]any{
				"operation":   "entry_to_group",
				"entry_index": i,
				"entry_dn":    entry.DN,
				"error":       err.Error(),
			}
			tflog.Warn(gm.ctx, "Failed to convert LDAP entry to group, skipping", errorFields)
			continue
		}
		groups = append(groups, group)
	}

	duration := time.Since(start)
	searchFields["duration_ms"] = duration.Milliseconds()
	searchFields["groups_processed"] = len(groups)
	searchFields["process_errors"] = processErrors
	searchFields["success_rate"] = float64(len(groups)) / float64(len(result.Entries)) * 100

	tflog.Info(gm.ctx, "SearchGroups completed", searchFields)

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
	group.ObjectSid = gm.sidHandler.ExtractSIDSafe(entry)
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
func (gm *GroupManager) addMembersIndividually(groupDN string, memberDNs []string) error {
	var lastNonConflictErr error
	successCount := 0
	conflictCount := 0

	for _, memberDN := range memberDNs {
		modReq := &ModifyRequest{
			DN:            groupDN,
			AddAttributes: map[string][]string{"member": {memberDN}},
		}

		if err := gm.client.Modify(gm.ctx, modReq); err != nil {
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
func (gm *GroupManager) ListGroupsByContainer(containerDN string) ([]*Group, error) {
	if containerDN == "" {
		containerDN = gm.baseDN
	}

	filter := "(objectClass=group)"
	attributes := []string{
		"objectGUID", "distinguishedName", "objectSid", "cn", "sAMAccountName",
		"description", "groupType", "member", "memberOf",
	}

	searchReq := &SearchRequest{
		BaseDN:     containerDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: attributes,
		TimeLimit:  gm.timeout,
	}

	result, err := gm.client.Search(gm.ctx, searchReq)
	if err != nil {
		return nil, WrapError("list_groups_by_container", err)
	}

	groups := make([]*Group, 0, len(result.Entries))
	for _, entry := range result.Entries {
		group, err := gm.entryToGroup(entry)
		if err != nil {
			continue // Skip malformed entries
		}
		groups = append(groups, group)
	}

	return groups, nil
}

// validateSearchFilter validates the user-provided search filter.
func (gm *GroupManager) validateSearchFilter(filter *GroupSearchFilter) error {
	if filter == nil {
		return nil
	}

	// Validate category
	if filter.Category != "" {
		switch strings.ToLower(filter.Category) {
		case "security", "distribution":
			// Valid categories
		default:
			return fmt.Errorf("invalid category '%s': must be 'security', 'distribution', or empty", filter.Category)
		}
	}

	// Validate scope
	if filter.Scope != "" {
		switch strings.ToLower(filter.Scope) {
		case "global", "domainlocal", "universal":
			// Valid scopes
		default:
			return fmt.Errorf("invalid scope '%s': must be 'global', 'domainlocal', 'universal', or empty", filter.Scope)
		}
	}

	// Validate container DN format if provided
	if filter.Container != "" {
		if _, err := ldap.ParseDN(filter.Container); err != nil {
			return fmt.Errorf("invalid container DN '%s': %w", filter.Container, err)
		}
	}

	// Empty filter is okay, will return all groups
	// All combinations of filter values are valid

	return nil
}

// buildLDAPFilter converts a user-friendly filter to an LDAP filter string.
func (gm *GroupManager) buildLDAPFilter(filter *GroupSearchFilter) string {
	if filter == nil {
		return ""
	}

	var filterParts []string

	// Name filters
	if filter.NamePrefix != "" {
		filterParts = append(filterParts, fmt.Sprintf("(cn=%s*)", ldap.EscapeFilter(filter.NamePrefix)))
	}
	if filter.NameSuffix != "" {
		filterParts = append(filterParts, fmt.Sprintf("(cn=*%s)", ldap.EscapeFilter(filter.NameSuffix)))
	}
	if filter.NameContains != "" {
		filterParts = append(filterParts, fmt.Sprintf("(cn=*%s*)", ldap.EscapeFilter(filter.NameContains)))
	}

	// Category filter
	if filter.Category != "" {
		switch strings.ToLower(filter.Category) {
		case "security":
			// Security groups have the security flag set (bit 31 = 0x80000000)
			filterParts = append(filterParts, "(groupType:1.2.840.113556.1.4.803:=2147483648)")
		case "distribution":
			// Distribution groups do NOT have the security flag set
			filterParts = append(filterParts, "(!(groupType:1.2.840.113556.1.4.803:=2147483648))")
		}
	}

	// Scope filter
	if filter.Scope != "" {
		switch strings.ToLower(filter.Scope) {
		case "global":
			// Global groups have bit 1 set (0x00000002)
			filterParts = append(filterParts, "(groupType:1.2.840.113556.1.4.803:=2)")
		case "domainlocal":
			// Domain Local groups have bit 2 set (0x00000004)
			filterParts = append(filterParts, "(groupType:1.2.840.113556.1.4.803:=4)")
		case "universal":
			// Universal groups have bit 3 set (0x00000008)
			filterParts = append(filterParts, "(groupType:1.2.840.113556.1.4.803:=8)")
		}
	}

	// Membership filter
	if filter.HasMembers != nil {
		if *filter.HasMembers {
			// Groups with members (has member attribute with at least one value)
			filterParts = append(filterParts, "(member=*)")
		} else {
			// Groups without members (no member attribute or empty)
			filterParts = append(filterParts, "(!(member=*))")
		}
	}

	// Group membership filters (supports nested groups via LDAP_MATCHING_RULE_IN_CHAIN)
	if filter.MemberOf != "" {
		// Groups that are members of the specified group (includes nested membership)
		filterParts = append(filterParts, fmt.Sprintf("(memberOf:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(filter.MemberOf)))
	}
	if filter.HasMember != "" {
		// Groups that contain the specified member (includes nested membership)
		filterParts = append(filterParts, fmt.Sprintf("(member:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(filter.HasMember)))
	}

	// Combine all filter parts
	if len(filterParts) == 0 {
		return ""
	} else if len(filterParts) == 1 {
		return filterParts[0]
	} else {
		return fmt.Sprintf("(&%s)", strings.Join(filterParts, ""))
	}
}

// searchGroupsInContainer searches for groups in a specific container using LDAP filter.
func (gm *GroupManager) searchGroupsInContainer(baseDN, filter string, attributes []string) ([]*Group, error) {
	start := time.Now()

	originalFilter := filter
	if filter == "" {
		filter = "(objectClass=group)"
	} else {
		// Ensure we're only searching for groups
		filter = fmt.Sprintf("(&(objectClass=group)%s)", filter)
	}

	searchFields := map[string]any{
		"operation":       "search_groups_in_container",
		"base_dn":         baseDN,
		"original_filter": originalFilter,
		"final_filter":    filter,
		"attributes":      attributes,
		"timeout":         gm.timeout.String(),
	}

	tflog.Debug(gm.ctx, "Starting searchGroupsInContainer", searchFields)

	if len(attributes) == 0 {
		attributes = []string{
			"objectGUID", "distinguishedName", "objectSid", "cn", "sAMAccountName",
			"description", "groupType", "mail", "mailNickname", "whenCreated", "whenChanged",
		}
		searchFields["attributes"] = attributes
		tflog.Trace(gm.ctx, "Using default attributes for container group search", searchFields)
	}

	searchReq := &SearchRequest{
		BaseDN:     baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: attributes,
		TimeLimit:  gm.timeout,
	}

	tflog.Debug(gm.ctx, "Executing paged search in container", searchFields)

	result, err := gm.client.SearchWithPaging(gm.ctx, searchReq)
	if err != nil {
		searchFields["operation"] = "search_groups_in_container"
		searchFields["error"] = err.Error()
		searchFields["duration_ms"] = time.Since(start).Milliseconds()

		// Add LDAP-specific error information if available
		if ldapErr, ok := err.(*ldap.Error); ok {
			searchFields["ldap_result_code"] = ldapErr.ResultCode
			if ldapErr.MatchedDN != "" {
				searchFields["ldap_matched_dn"] = ldapErr.MatchedDN
			}
			if ldapErr.Err != nil {
				searchFields["ldap_diagnostic_message"] = ldapErr.Err.Error()
			}
		}

		tflog.Error(gm.ctx, "LDAP search groups in container operation failed", searchFields)
		return nil, WrapError("search_groups_in_container", err)
	}

	searchFields["raw_entries_found"] = len(result.Entries)
	tflog.Trace(gm.ctx, "Container search completed, processing entries", searchFields)

	groups := make([]*Group, 0, len(result.Entries))
	processErrors := 0
	for i, entry := range result.Entries {
		group, err := gm.entryToGroup(entry)
		if err != nil {
			processErrors++
			errorFields := map[string]any{
				"operation":   "entry_to_group",
				"entry_index": i,
				"entry_dn":    entry.DN,
				"container":   baseDN,
				"error":       err.Error(),
			}
			tflog.Warn(gm.ctx, "Failed to convert LDAP entry to group in container search, skipping", errorFields)
			continue
		}
		groups = append(groups, group)
	}

	duration := time.Since(start)
	searchFields["duration_ms"] = duration.Milliseconds()
	searchFields["groups_processed"] = len(groups)
	searchFields["process_errors"] = processErrors
	if len(result.Entries) > 0 {
		searchFields["success_rate"] = float64(len(groups)) / float64(len(result.Entries)) * 100
	} else {
		searchFields["success_rate"] = 100.0
	}

	tflog.Info(gm.ctx, "searchGroupsInContainer completed", searchFields)

	return groups, nil
}

// GetGroupStats returns statistics about groups in the directory.
func (gm *GroupManager) GetGroupStats() (map[string]int, error) {
	stats := make(map[string]int)

	// Count total groups
	allGroups, err := gm.SearchGroups("", []string{"groupType"})
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

// GetFlattenedUserMembers returns a flattened list of user members from a group,
// recursively traversing nested groups to return only users (not groups).
func (gm *GroupManager) GetFlattenedUserMembers(groupGUID string) ([]string, error) {
	if groupGUID == "" {
		return nil, fmt.Errorf("group GUID cannot be empty")
	}

	// Use a set to track already processed groups to prevent infinite loops
	processedGroups := make(map[string]bool)
	// Use a set to collect unique user DNs
	userDNs := make(map[string]bool)

	// Start recursive traversal
	if err := gm.flattenGroupMembersRecursive(groupGUID, processedGroups, userDNs); err != nil {
		return nil, WrapError("flatten_group_members", err)
	}

	// Convert set to slice
	result := make([]string, 0, len(userDNs))
	for userDN := range userDNs {
		result = append(result, userDN)
	}

	return result, nil
}

// flattenGroupMembersRecursive recursively processes group members, adding users to the userDNs set
// and recursively processing nested groups.
func (gm *GroupManager) flattenGroupMembersRecursive(groupGUID string, processedGroups map[string]bool, userDNs map[string]bool) error {
	// Check if we've already processed this group (prevent infinite loops)
	if processedGroups[groupGUID] {
		return nil
	}
	processedGroups[groupGUID] = true

	// Get the group
	group, err := gm.GetGroup(groupGUID)
	if err != nil {
		return fmt.Errorf("failed to get group %s: %w", groupGUID, err)
	}

	// Process each member
	for _, memberDN := range group.MemberDNs {
		// Check if this member is a group or user by searching for it
		// First try to find it as a group
		groupFilter := fmt.Sprintf("(&(objectClass=group)(distinguishedName=%s))", ldap.EscapeFilter(memberDN))
		groupResults, err := gm.client.Search(gm.ctx, &SearchRequest{
			BaseDN:     gm.baseDN,
			Scope:      ScopeWholeSubtree,
			Filter:     groupFilter,
			Attributes: []string{"objectGUID"},
			SizeLimit:  1,
			TimeLimit:  gm.timeout,
		})
		if err != nil {
			// Log warning and continue with next member
			tflog.Warn(gm.ctx, "Failed to search for member as group", map[string]any{
				"member_dn": memberDN,
				"error":     err.Error(),
			})
			continue
		}

		if len(groupResults.Entries) > 0 {
			// This member is a group, recursively process its members
			memberGroupGUID, err := gm.guidHandler.ExtractGUID(groupResults.Entries[0])
			if err != nil {
				tflog.Warn(gm.ctx, "Failed to extract GUID from member group", map[string]any{
					"member_dn": memberDN,
					"error":     err.Error(),
				})
				continue
			}

			// Recursively process this group
			if err := gm.flattenGroupMembersRecursive(memberGroupGUID, processedGroups, userDNs); err != nil {
				tflog.Warn(gm.ctx, "Failed to recursively process member group", map[string]any{
					"member_group_guid": memberGroupGUID,
					"member_dn":         memberDN,
					"error":             err.Error(),
				})
				continue
			}
		} else {
			// This member is not a group, check if it's a user
			userFilter := fmt.Sprintf("(&(objectClass=user)(distinguishedName=%s))", ldap.EscapeFilter(memberDN))
			userResults, err := gm.client.Search(gm.ctx, &SearchRequest{
				BaseDN:     gm.baseDN,
				Scope:      ScopeWholeSubtree,
				Filter:     userFilter,
				Attributes: []string{"objectClass"},
				SizeLimit:  1,
				TimeLimit:  gm.timeout,
			})
			if err != nil {
				tflog.Warn(gm.ctx, "Failed to search for member as user", map[string]any{
					"member_dn": memberDN,
					"error":     err.Error(),
				})
				continue
			}

			if len(userResults.Entries) > 0 {
				// This is a user, add it to our set
				userDNs[memberDN] = true
			} else {
				// Neither group nor user, log and skip
				tflog.Debug(gm.ctx, "Member is neither group nor user, skipping", map[string]any{
					"member_dn": memberDN,
				})
			}
		}
	}

	return nil
}
