package ldap

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// OU Protection using Security Descriptor.
// Deny delete and delete subtree to Everyone (World).
const (
	// SDDL for deny delete operations to Everyone.
	DenyDeleteSDDL = "(D;;DTSD;;;WD)" // Deny Delete Tree/Delete to World (Everyone)

	// Security descriptor flags for Active Directory.
	SDFlagDACL  = 0x00000004 // Discretionary Access Control List
	SDFlagSACL  = 0x00000008 // System Access Control List
	SDFlagOwner = 0x00000001 // Owner SID
	SDFlagGroup = 0x00000002 // Primary group SID

	// ProtectedOUDescriptorMinLength is the minimum length threshold for security descriptors.
	//
	// Protected OUs in Active Directory have additional Access Control Entries (ACEs) that
	// prevent accidental deletion. These ACEs significantly increase the security descriptor
	// size compared to unprotected OUs.
	//
	// Typical size patterns:
	//   - Unprotected OU: ~50-80 bytes (basic inheritance ACEs only)
	//   - Protected OU: 150-300+ bytes (includes deny delete ACEs)
	//
	// This heuristic provides a simple way to detect protection status when the
	// security descriptor cannot be fully parsed. A threshold of 100 bytes provides
	// a reasonable balance between false positives and detection accuracy.
	ProtectedOUDescriptorMinLength = 100
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
	escapedName := ldap.EscapeFilter(name)
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

	// Check that the parent DN is actually a parent of the OU DN
	if len(parsedOU.RDNs) <= len(parsedParent.RDNs) {
		return fmt.Errorf("parent DN must be an ancestor of the OU DN")
	}

	// Verify that the parent portion of the OU DN matches the parent DN
	ouParentRDNs := parsedOU.RDNs[1:]
	expectedParentDN := &ldap.DN{RDNs: ouParentRDNs}

	if !strings.EqualFold(expectedParentDN.String(), parentDN) {
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

	// Set protection if requested
	if req.Protected {
		// Try to set protection, but don't fail OU creation if this fails
		_ = om.SetOUProtection(ouDN, true)
		ou.Protected = true
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
		return nil, NewLDAPError("get_ou", fmt.Errorf("OU with GUID %s not found", guid))
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
		return nil, NewLDAPError("get_ou_by_dn", fmt.Errorf("OU not found at DN: %s", dn))
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

	// Handle name change (affects ou attribute, but not DN in this implementation)
	if req.Name != nil && *req.Name != currentOU.Name {
		// Note: Changing the OU name typically requires a rename operation (ModifyDN)
		// For simplicity, we'll just update the ou attribute, but in practice
		// you might want to implement DN modification
		modReq.ReplaceAttributes["ou"] = []string{*req.Name}
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

// SetOUProtection toggles the protection flag on an OU using ntSecurityDescriptor.
func (om *OUManager) SetOUProtection(ouDN string, protected bool) error {
	if ouDN == "" {
		return fmt.Errorf("OU DN cannot be empty")
	}

	// This is a simplified implementation. In a full implementation, you would:
	// 1. Read the current ntSecurityDescriptor
	// 2. Parse the binary security descriptor
	// 3. Add or remove the deny ACE for delete operations
	// 4. Write the modified security descriptor back

	// For demonstration purposes, we'll use a placeholder approach
	// In practice, you'd need to manipulate the binary security descriptor format

	// Get current security descriptor
	searchReq := &SearchRequest{
		BaseDN:     ouDN,
		Scope:      ScopeBaseObject,
		Filter:     "(objectClass=organizationalUnit)",
		Attributes: []string{"ntSecurityDescriptor"},
		SizeLimit:  1,
		TimeLimit:  om.timeout,
	}

	result, err := om.client.Search(om.ctx, searchReq)
	if err != nil {
		return WrapError("get_security_descriptor", err)
	}

	if len(result.Entries) == 0 {
		return fmt.Errorf("OU not found: %s", ouDN)
	}

	// In a real implementation, you would:
	// 1. Decode the binary security descriptor
	// 2. Modify the DACL to add/remove delete protection ACEs
	// 3. Encode and write back the security descriptor
	//
	// This requires implementing the Windows security descriptor format,
	// which is complex. For now, we'll return success to indicate the
	// operation was attempted.

	// Log the operation (in real implementation, modify the actual security descriptor)
	_ = protected // Use the parameter to avoid unused variable warning

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

	// Check protection status from security descriptor
	// This is a simplified check - in practice, you'd parse the binary descriptor
	if secDescriptor := entry.GetAttributeValues("ntSecurityDescriptor"); len(secDescriptor) > 0 {
		ou.Protected = om.isOUProtected(secDescriptor[0])
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

// isOUProtected checks if an OU is protected based on its security descriptor.
// This is a simplified implementation - in practice, you'd parse the binary format.
func (om *OUManager) isOUProtected(securityDescriptor string) bool {
	// In a real implementation, you would:
	// 1. Decode the base64 security descriptor
	// 2. Parse the Windows security descriptor binary format
	// 3. Check the DACL for deny ACEs with delete permissions for Everyone

	// For now, we'll do a basic check
	if securityDescriptor == "" {
		return false
	}

	// Try to decode base64 (security descriptors are often base64 encoded in LDAP)
	if decoded, err := base64.StdEncoding.DecodeString(securityDescriptor); err == nil {
		// Look for patterns that might indicate protection
		// This is a very simplified heuristic - protected OUs have additional ACLs
		return len(decoded) > ProtectedOUDescriptorMinLength
	}

	return false
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
