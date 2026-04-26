package ldap

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// OU represents an Active Directory Organizational Unit.
type OU struct {
	// Core identification
	ObjectGUID        string `json:"objectGUID"`
	DistinguishedName string `json:"distinguishedName"`

	// OU attributes
	Name        string `json:"name"`                // ou attribute value
	Description string `json:"description"`         // OU description
	Protected   bool   `json:"protected"`           // Protection flag (from ntSecurityDescriptor)
	ManagedBy   string `json:"managedBy,omitempty"` // DN of user/computer that manages this OU

	// Container information
	Parent string `json:"parent"` // Parent container DN

	// Child information
	Children []string `json:"children,omitempty"` // Child OU DNs

	// Timestamps
	WhenCreated time.Time `json:"whenCreated"`
	WhenChanged time.Time `json:"whenChanged"`
}

// CreateOURequest represents a request to create a new OU.
type CreateOURequest struct {
	Name        string `json:"name"`                // Required: OU name
	ParentDN    string `json:"parentDN"`            // Required: Parent container DN
	Description string `json:"description"`         // Optional: OU description
	Protected   bool   `json:"protected"`           // Optional: Enable OU protection
	ManagedBy   string `json:"managedBy,omitempty"` // Optional: DN of manager
}

// UpdateOURequest represents a request to update an existing OU.
type UpdateOURequest struct {
	Name        *string `json:"name,omitempty"`        // Optional: New OU name
	Description *string `json:"description,omitempty"` // Optional: New description
	Protected   *bool   `json:"protected,omitempty"`   // Optional: Change protection status
	ManagedBy   *string `json:"managedBy,omitempty"`   // Optional: DN of manager (nil = no change, empty string = clear)
	Path        *string `json:"path,omitempty"`        // Optional: New parent DN (triggers OU move)
}

// OUEntry represents a simplified OU entry for the interface.
type OUEntry struct {
	DN           string
	Name         string
	Description  string
	Protected    bool
	CreatedDate  time.Time
	ModifiedDate time.Time
	ObjectGUID   string
	Children     []string
}

// OUManager handles Active Directory organizational unit operations.
type OUManager struct {
	ctx         context.Context
	client      Client
	guidHandler *GUIDHandler
	baseDN      string
	timeout     time.Duration
}

// NewOUManager creates a new OU manager instance.
func NewOUManager(ctx context.Context, client Client, baseDN string) *OUManager {
	return &OUManager{
		ctx:         ctx,
		client:      client,
		guidHandler: NewGUIDHandler(),
		baseDN:      baseDN,
		timeout:     30 * time.Second,
	}
}

// SetTimeout sets the LDAP operation timeout.
func (om *OUManager) SetTimeout(timeout time.Duration) {
	om.timeout = timeout
}

// getAllOUAttributes returns the standard set of LDAP attributes to retrieve for OUs.
// This ensures consistency across all OU search and retrieval operations.
func (om *OUManager) getAllOUAttributes() []string {
	return []string{
		"objectGUID", "distinguishedName", "ou", "name",
		"description", "ntSecurityDescriptor", "managedBy",
		"whenCreated", "whenChanged",
	}
}

// BuildOUDN constructs a proper Distinguished Name for an OU.
func (om *OUManager) BuildOUDN(name, parentDN string) string {
	// Escape special characters in the OU name for LDAP
	escapedName := ldap.EscapeDN(name)
	return fmt.Sprintf("OU=%s,%s", escapedName, parentDN)
}

// ValidateOUHierarchy validates that an OU can be created or moved within the hierarchy.
func (om *OUManager) ValidateOUHierarchy(ouDN, parentDN string) error {
	if ouDN == "" || parentDN == "" {
		return fmt.Errorf("OU DN and parent DN cannot be empty")
	}

	// Parse both DNs to validate syntax
	parsedOU, err := ldap.ParseDN(ouDN)
	if err != nil {
		return fmt.Errorf("invalid OU DN syntax: %w", err)
	}

	parsedParent, err := ldap.ParseDN(parentDN)
	if err != nil {
		return fmt.Errorf("invalid parent DN syntax: %w", err)
	}

	// Verify that the parent portion of the OU DN matches the parent DN
	ouParentDN := &ldap.DN{RDNs: parsedOU.RDNs[1:]}
	if len(parsedOU.RDNs) <= len(parsedParent.RDNs) || !ouParentDN.EqualFold(parsedParent) {
		return fmt.Errorf("OU DN does not belong to the specified parent")
	}

	return nil
}

// ValidateOURequest validates an OU creation request.
func (om *OUManager) ValidateOURequest(req *CreateOURequest) error {
	if req == nil {
		return fmt.Errorf("create OU request cannot be nil")
	}

	if req.Name == "" {
		return fmt.Errorf("OU name is required")
	}

	if req.ParentDN == "" {
		return fmt.Errorf("parent DN is required")
	}

	// Validate OU name format (no certain special characters that cause issues)
	if strings.ContainsAny(req.Name, "\"\\/#+,;<=>\r\n") {
		return fmt.Errorf("OU name contains invalid characters: %s", req.Name)
	}

	// Validate parent DN syntax
	if _, err := ldap.ParseDN(req.ParentDN); err != nil {
		return fmt.Errorf("invalid parent DN syntax: %w", err)
	}

	return nil
}

// CreateOU creates a new Active Directory organizational unit.
func (om *OUManager) CreateOU(req *CreateOURequest) (*OU, error) {
	if err := om.ValidateOURequest(req); err != nil {
		return nil, WrapError("create_ou_validation", err)
	}

	// Build the OU DN
	ouDN := om.BuildOUDN(req.Name, req.ParentDN)

	// Build attributes for OU creation
	attributes := map[string][]string{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {req.Name},
	}

	// Add optional attributes
	if req.Description != "" {
		attributes["description"] = []string{req.Description}
	}

	if req.ManagedBy != "" {
		attributes["managedBy"] = []string{req.ManagedBy}
	}

	// Create the OU
	addReq := &AddRequest{
		DN:         ouDN,
		Attributes: attributes,
	}

	if err := om.client.Add(om.ctx, addReq); err != nil {
		return nil, WrapError("create_ou", err)
	}

	// Retrieve the created OU to get its GUID and other computed attributes
	ou, err := om.getOUByDN(ouDN)
	if err != nil {
		return nil, WrapError("retrieve_created_ou", err)
	}

	// Set protection if requested. Re-read so Protected reflects server state.
	if req.Protected {
		if err := om.SetOUProtection(ouDN, true); err != nil {
			return nil, WrapError("set_ou_protection", err)
		}
		refreshed, err := om.getOUByDN(ouDN)
		if err != nil {
			return nil, WrapError("refresh_ou_after_protection", err)
		}
		ou = refreshed
	}

	return ou, nil
}

// GetOU retrieves an OU by its objectGUID.
func (om *OUManager) GetOU(guid string) (*OU, error) {
	if guid == "" {
		return nil, fmt.Errorf("OU GUID cannot be empty")
	}

	// Validate GUID format
	if !om.guidHandler.IsValidGUID(guid) {
		return nil, fmt.Errorf("invalid GUID format: %s", guid)
	}

	// Create GUID search request
	searchReq, err := om.guidHandler.GenerateGUIDSearchRequest(om.baseDN, guid)
	if err != nil {
		return nil, WrapError("generate_guid_search", err)
	}

	// Expand attributes to include all OU-relevant fields
	searchReq.Attributes = []string{
		"objectGUID", "distinguishedName", "ou", "name",
		"description", "ntSecurityDescriptor", "whenCreated", "whenChanged", "managedBy",
	}
	searchReq.TimeLimit = om.timeout

	// Add the organizationalUnit filter
	searchReq.Filter = fmt.Sprintf("(&(objectClass=organizationalUnit)%s)", searchReq.Filter)

	result, err := om.client.Search(om.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_ou_by_guid", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewNotFoundError("get_ou", "OU with GUID %s not found", guid)
	}

	ou, err := om.entryToOU(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_ou_entry", err)
	}

	return ou, nil
}

// GetOUByDN retrieves an OU by its distinguished name.
func (om *OUManager) GetOUByDN(dn string) (*OU, error) {
	if dn == "" {
		return nil, fmt.Errorf("OU DN cannot be empty")
	}

	return om.getOUByDN(dn)
}

// getOUByDN is the internal implementation for DN-based OU retrieval.
func (om *OUManager) getOUByDN(dn string) (*OU, error) {
	searchReq := &SearchRequest{
		BaseDN: dn,
		Scope:  ScopeBaseObject,
		Filter: "(objectClass=organizationalUnit)",
		Attributes: []string{
			"objectGUID", "distinguishedName", "ou", "name",
			"description", "ntSecurityDescriptor", "whenCreated", "whenChanged", "managedBy",
		},
		SizeLimit: 1,
		TimeLimit: om.timeout,
	}

	result, err := om.client.Search(om.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_ou_by_dn", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewNotFoundError("get_ou_by_dn", "OU not found at DN: %s", dn)
	}

	ou, err := om.entryToOU(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_ou_entry", err)
	}

	return ou, nil
}

// UpdateOU updates an existing OU.
func (om *OUManager) UpdateOU(guid string, req *UpdateOURequest) (*OU, error) {
	if guid == "" {
		return nil, fmt.Errorf("OU GUID cannot be empty")
	}

	if req == nil {
		return nil, fmt.Errorf("update OU request cannot be nil")
	}

	// Get current OU to determine DN and validate changes
	currentOU, err := om.GetOU(guid)
	if err != nil {
		return nil, WrapError("get_current_ou", err)
	}

	// Build modification request
	modReq := &ModifyRequest{
		DN:                currentOU.DistinguishedName,
		ReplaceAttributes: make(map[string][]string),
	}

	hasChanges := false

	// Handle name or path change (requires ModifyDN operation)
	needsMove := req.Path != nil && !DNEqual(*req.Path, currentOU.Parent)
	needsRename := req.Name != nil && *req.Name != currentOU.Name

	if needsMove || needsRename {
		newName := currentOU.Name
		if needsRename {
			newName = *req.Name
		}
		newParent := currentOU.Parent
		if needsMove {
			newParent = *req.Path
		}
		renamedOU, err := om.renameAndMoveOU(currentOU, newName, newParent)
		if err != nil {
			return nil, err
		}
		currentOU = renamedOU
		modReq.DN = currentOU.DistinguishedName
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

	// Handle managedBy change
	if req.ManagedBy != nil {
		if *req.ManagedBy == "" {
			// Clear the attribute
			modReq.ReplaceAttributes["managedBy"] = []string{}
		} else {
			modReq.ReplaceAttributes["managedBy"] = []string{*req.ManagedBy}
		}
		hasChanges = true
	}

	// Handle protection change
	if req.Protected != nil && *req.Protected != currentOU.Protected {
		if err := om.SetOUProtection(currentOU.DistinguishedName, *req.Protected); err != nil {
			return nil, WrapError("set_ou_protection", err)
		}
		hasChanges = true
	}

	// Apply other modifications if any
	if hasChanges && (len(modReq.ReplaceAttributes) > 0 || len(modReq.DeleteAttributes) > 0) {
		if err := om.client.Modify(om.ctx, modReq); err != nil {
			return nil, WrapError("modify_ou", err)
		}
	}

	if !hasChanges {
		// No changes needed, return current OU
		return currentOU, nil
	}

	// Retrieve updated OU
	updatedOU, err := om.GetOU(guid)
	if err != nil {
		return nil, WrapError("retrieve_updated_ou", err)
	}

	return updatedOU, nil
}

// renameAndMoveOU performs a ModifyDN operation to rename and/or move an OU.
func (om *OUManager) renameAndMoveOU(currentOU *OU, newName, newParent string) (*OU, error) {
	// Check if any actual change is needed
	if newName == currentOU.Name && DNEqual(newParent, currentOU.Parent) {
		return currentOU, nil
	}

	// Parse the current DN to understand its structure
	parsedDN, err := ldap.ParseDN(currentOU.DistinguishedName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse current DN: %w", err)
	}

	if len(parsedDN.RDNs) == 0 {
		return nil, fmt.Errorf("invalid DN structure")
	}

	// Create the new RDN
	var newRDN string
	if newName == currentOU.Name {
		newRDN = parsedDN.RDNs[0].String()
	} else {
		newRDN = fmt.Sprintf("OU=%s", ldap.EscapeDN(newName))
	}

	// Determine if we need to specify a new superior (parent)
	var newSuperior string
	if !DNEqual(newParent, currentOU.Parent) {
		newSuperior = newParent
	}

	// Create the ModifyDN request
	modifyDNReq := &ModifyDNRequest{
		DN:           currentOU.DistinguishedName,
		NewRDN:       newRDN,
		DeleteOldRDN: true,
		NewSuperior:  newSuperior,
	}

	// Execute the ModifyDN operation
	if err := om.client.ModifyDN(om.ctx, modifyDNReq); err != nil {
		return nil, WrapError("modify_dn", err)
	}

	// Retrieve and return the updated OU
	updatedOU, err := om.GetOU(currentOU.ObjectGUID)
	if err != nil {
		return nil, WrapError("retrieve_renamed_moved_ou", err)
	}

	return updatedOU, nil
}

// DeleteOU deletes an OU by its objectGUID.
func (om *OUManager) DeleteOU(guid string) error {
	if guid == "" {
		return fmt.Errorf("OU GUID cannot be empty")
	}

	// Get OU to determine DN and check protection
	ou, err := om.GetOU(guid)
	if err != nil {
		// Check if it's a "not found" error
		if ldapErr, ok := err.(*LDAPError); ok {
			if ldapErr.Message == fmt.Sprintf("OU with GUID %s not found", guid) {
				// OU already doesn't exist
				return nil
			}
		}
		return WrapError("get_ou_for_deletion", err)
	}

	// Check if OU is protected
	if ou.Protected {
		return fmt.Errorf("cannot delete protected OU: %s", ou.DistinguishedName)
	}

	// Delete the OU
	if err := om.client.Delete(om.ctx, ou.DistinguishedName); err != nil {
		return WrapError("delete_ou", err)
	}

	return nil
}

// SetOUProtection toggles protect-from-accidental-deletion on an OU by
// updating the DACL in nTSecurityDescriptor. It reads and writes only the
// DACL using LDAP_SERVER_SD_FLAGS_OID so owner/group/SACL are not altered.
func (om *OUManager) SetOUProtection(ouDN string, protected bool) error {
	if ouDN == "" {
		return fmt.Errorf("OU DN cannot be empty")
	}

	sdFlags := &ldap.ControlMicrosoftSDFlags{
		Criticality:  true,
		ControlValue: int32(SDFlagsDACLSecurityInformation),
	}

	searchReq := &SearchRequest{
		BaseDN:     ouDN,
		Scope:      ScopeBaseObject,
		Filter:     "(objectClass=organizationalUnit)",
		Attributes: []string{"nTSecurityDescriptor"},
		SizeLimit:  1,
		TimeLimit:  om.timeout,
		Controls:   []ldap.Control{sdFlags},
	}

	result, err := om.client.Search(om.ctx, searchReq)
	if err != nil {
		return WrapError("get_security_descriptor", err)
	}
	if len(result.Entries) == 0 {
		return fmt.Errorf("OU not found: %s", ouDN)
	}

	raw := readSecurityDescriptorBytes(result.Entries[0])
	if len(raw) == 0 {
		return fmt.Errorf("OU %s has no nTSecurityDescriptor", ouDN)
	}

	sd, err := UnmarshalSecurityDescriptor(raw)
	if err != nil {
		return WrapError("parse_security_descriptor", err)
	}

	has := sd.HasDenyDeleteEveryoneACE()
	switch {
	case protected && !has:
		sd.AddDenyDeleteEveryoneACE()
	case !protected && has:
		sd.RemoveDenyDeleteEveryoneACE()
	default:
		return nil // already in desired state
	}

	newRaw, err := sd.Marshal()
	if err != nil {
		return WrapError("marshal_security_descriptor", err)
	}

	modReq := &ModifyRequest{
		DN: ouDN,
		ReplaceAttributes: map[string][]string{
			"nTSecurityDescriptor": {string(newRaw)},
		},
		Controls: []ldap.Control{sdFlags},
	}
	if err := om.client.Modify(om.ctx, modReq); err != nil {
		return WrapError("write_security_descriptor", err)
	}
	return nil
}

// readSecurityDescriptorBytes extracts raw nTSecurityDescriptor bytes. Real
// LDAP responses carry the descriptor in ByteValues, but tests may supply
// base64 strings in Values; handle both.
func readSecurityDescriptorBytes(entry *ldap.Entry) []byte {
	if entry == nil {
		return nil
	}
	// GetRawAttributeValue is case-sensitive. Try both common casings.
	for _, name := range []string{"nTSecurityDescriptor", "ntSecurityDescriptor"} {
		if b := entry.GetRawAttributeValue(name); len(b) > 0 {
			return b
		}
	}
	// Fallback for string-based test fixtures (base64-encoded).
	for _, name := range []string{"nTSecurityDescriptor", "ntSecurityDescriptor"} {
		if v := entry.GetAttributeValue(name); v != "" {
			if decoded, err := base64.StdEncoding.DecodeString(v); err == nil {
				return decoded
			}
			return []byte(v)
		}
	}
	return nil
}

// SearchOUs searches for OUs using various criteria.
func (om *OUManager) SearchOUs(baseDN string, filter string) ([]*OU, error) {
	if baseDN == "" {
		baseDN = om.baseDN
	}

	if filter == "" {
		filter = "(objectClass=organizationalUnit)"
	} else {
		// Ensure we're only searching for OUs
		filter = fmt.Sprintf("(&(objectClass=organizationalUnit)%s)", filter)
	}

	searchReq := &SearchRequest{
		BaseDN:     baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: om.getAllOUAttributes(),
		TimeLimit:  om.timeout,
	}

	result, err := om.client.SearchWithPaging(om.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_ous", err)
	}

	ous := make([]*OU, 0, len(result.Entries))
	for _, entry := range result.Entries {
		ou, err := om.entryToOU(entry)
		if err != nil {
			// Log error but continue with other entries
			continue
		}
		ous = append(ous, ou)
	}

	return ous, nil
}

// GetOUChildren retrieves immediate child OUs of a given OU.
func (om *OUManager) GetOUChildren(ctx context.Context, ouDN string) ([]*OU, error) {
	if ouDN == "" {
		return nil, fmt.Errorf("OU DN cannot be empty")
	}

	searchReq := &SearchRequest{
		BaseDN:     ouDN,
		Scope:      ScopeSingleLevel, // Only immediate children
		Filter:     "(objectClass=organizationalUnit)",
		Attributes: om.getAllOUAttributes(),
		TimeLimit:  om.timeout,
	}

	result, err := om.client.Search(om.ctx, searchReq)
	if err != nil {
		return nil, WrapError("get_ou_children", err)
	}

	children := make([]*OU, 0, len(result.Entries))
	for _, entry := range result.Entries {
		ou, err := om.entryToOU(entry)
		if err != nil {
			continue // Skip malformed entries
		}
		children = append(children, ou)
	}

	return children, nil
}

// entryToOU converts an LDAP entry to an OU struct.
func (om *OUManager) entryToOU(entry *ldap.Entry) (*OU, error) {
	if entry == nil {
		return nil, fmt.Errorf("LDAP entry cannot be nil")
	}

	ou := &OU{}

	// Extract GUID
	guid, err := om.guidHandler.ExtractGUID(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to extract GUID: %w", err)
	}
	ou.ObjectGUID = guid

	// Basic attributes
	ou.DistinguishedName = entry.DN

	// OU name - try 'ou' attribute first, then 'name'
	ou.Name = entry.GetAttributeValue("ou")
	if ou.Name == "" {
		ou.Name = entry.GetAttributeValue("name")
	}

	ou.Description = entry.GetAttributeValue("description")
	ou.ManagedBy = entry.GetAttributeValue("managedBy")

	// Extract parent from DN
	if ou.DistinguishedName != "" {
		// Parse DN to get parent container
		if parsedDN, err := ldap.ParseDN(ou.DistinguishedName); err == nil && len(parsedDN.RDNs) > 1 {
			// Reconstruct parent DN from all RDNs except the first
			parentRDNs := parsedDN.RDNs[1:]
			parentDN := &ldap.DN{RDNs: parentRDNs}
			ou.Parent = parentDN.String()
		}
	}

	// Check protection status by parsing the DACL of the security descriptor.
	if raw := readSecurityDescriptorBytes(entry); len(raw) > 0 {
		ou.Protected = om.isOUProtected(raw)
	}

	// Parse timestamps
	if whenCreated := entry.GetAttributeValue("whenCreated"); whenCreated != "" {
		if t, err := time.Parse("20060102150405.0Z", whenCreated); err == nil {
			ou.WhenCreated = t
		}
	}

	if whenChanged := entry.GetAttributeValue("whenChanged"); whenChanged != "" {
		if t, err := time.Parse("20060102150405.0Z", whenChanged); err == nil {
			ou.WhenChanged = t
		}
	}

	return ou, nil
}

// isOUProtected returns true when the OU's DACL carries the specific deny ACE
// that Windows installs for "protect from accidental deletion".
func (om *OUManager) isOUProtected(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	sd, err := UnmarshalSecurityDescriptor(raw)
	if err != nil {
		return false
	}
	return sd.HasDenyDeleteEveryoneACE()
}

// ListOUsByContainer lists all OUs in a specific container.
func (om *OUManager) ListOUsByContainer(ctx context.Context, containerDN string) ([]*OU, error) {
	if containerDN == "" {
		containerDN = om.baseDN
	}

	filter := "(objectClass=organizationalUnit)"
	attributes := om.getAllOUAttributes()

	searchReq := &SearchRequest{
		BaseDN:     containerDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: attributes,
		TimeLimit:  om.timeout,
	}

	result, err := om.client.Search(om.ctx, searchReq)
	if err != nil {
		return nil, WrapError("list_ous_by_container", err)
	}

	ous := make([]*OU, 0, len(result.Entries))
	for _, entry := range result.Entries {
		ou, err := om.entryToOU(entry)
		if err != nil {
			continue // Skip malformed entries
		}
		ous = append(ous, ou)
	}

	return ous, nil
}

// GetOUStats returns statistics about OUs in the directory.
func (om *OUManager) GetOUStats(ctx context.Context) (map[string]int, error) {
	stats := make(map[string]int)

	// Count total OUs
	allOUs, err := om.SearchOUs("", "")
	if err != nil {
		return nil, WrapError("get_ou_stats", err)
	}

	stats["total"] = len(allOUs)

	// Count protected vs unprotected
	protectedCount := 0
	for _, ou := range allOUs {
		if ou.Protected {
			protectedCount++
		}
	}
	stats["protected"] = protectedCount
	stats["unprotected"] = len(allOUs) - protectedCount

	return stats, nil
}
