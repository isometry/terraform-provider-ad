package ldap

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// IdentifierType represents the type of identifier detected.
type IdentifierType int

const (
	IdentifierTypeUnknown IdentifierType = iota
	IdentifierTypeDN                     // Distinguished Name
	IdentifierTypeGUID                   // Globally Unique Identifier
	IdentifierTypeSID                    // Security Identifier
	IdentifierTypeUPN                    // User Principal Name
	IdentifierTypeSAM                    // SAM Account Name (DOMAIN\username)
)

// String returns the string representation of the identifier type.
func (i IdentifierType) String() string {
	switch i {
	case IdentifierTypeDN:
		return "DN"
	case IdentifierTypeGUID:
		return "GUID"
	case IdentifierTypeSID:
		return "SID"
	case IdentifierTypeUPN:
		return "UPN"
	case IdentifierTypeSAM:
		return "SAM"
	default:
		return "Unknown"
	}
}

// Regular expressions for identifier format detection.
var (
	// DN format: CN=User,OU=Users,DC=example,DC=com.
	dnRegex = regexp.MustCompile(`^(?i)(CN|OU|DC|O|C|STREET|L|ST|POSTALCODE)=.+`)

	// SID format: S-1-5-21-domain-rid or S-1-5-32-alias.
	sidRegex = regexp.MustCompile(`^S-1-\d+(-\d+)*$`)

	// UPN format: user@domain.com.
	upnRegex = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

	// SAM format: DOMAIN\username or just username.
	samRegex = regexp.MustCompile(`^([^\\@\s]+\\)?[^\\@\s]+$`)
)

// MemberNormalizer handles normalization of various identifier formats to Distinguished Names.
type MemberNormalizer struct {
	client       Client
	guidHandler  *GUIDHandler
	baseDN       string
	cacheManager *CacheManager // Reference to shared cache
	timeout      time.Duration
}

// NewMemberNormalizer creates a new member identifier normalizer.
func NewMemberNormalizer(client Client, baseDN string, cacheManager *CacheManager) *MemberNormalizer {
	return &MemberNormalizer{
		client:       client,
		guidHandler:  NewGUIDHandler(),
		baseDN:       baseDN,
		cacheManager: cacheManager, // Use shared cache
		timeout:      30 * time.Second,
	}
}

// SetTimeout sets the LDAP operation timeout.
func (m *MemberNormalizer) SetTimeout(timeout time.Duration) {
	m.timeout = timeout
}

// DetectIdentifierType analyzes an identifier string and determines its type.
func (m *MemberNormalizer) DetectIdentifierType(identifier string) IdentifierType {
	if identifier == "" {
		return IdentifierTypeUnknown
	}

	identifier = strings.TrimSpace(identifier)

	// Check for DN format first (most specific)
	if dnRegex.MatchString(identifier) {
		return IdentifierTypeDN
	}

	// Check for GUID format
	if m.guidHandler.IsValidGUID(identifier) {
		return IdentifierTypeGUID
	}

	// Check for SID format
	if sidRegex.MatchString(identifier) {
		return IdentifierTypeSID
	}

	// Check for UPN format
	if upnRegex.MatchString(identifier) {
		return IdentifierTypeUPN
	}

	// Check for SAM format (least specific, should be last)
	if samRegex.MatchString(identifier) {
		return IdentifierTypeSAM
	}

	return IdentifierTypeUnknown
}

// NormalizeToDN converts any identifier format to a Distinguished Name.
func (m *MemberNormalizer) NormalizeToDN(identifier string) (string, error) {
	if identifier == "" {
		return "", fmt.Errorf("identifier cannot be empty")
	}

	identifier = strings.TrimSpace(identifier)

	// Check cache first
	if m.cacheManager != nil {
		if cachedEntry, found := m.cacheManager.Get(identifier); found {
			return cachedEntry.DN, nil
		}
	}

	// Detect identifier type
	idType := m.DetectIdentifierType(identifier)

	var dn string
	var err error

	switch idType {
	case IdentifierTypeDN:
		// Already a DN, validate and return
		dn, err = m.validateDN(identifier)
	case IdentifierTypeGUID:
		dn, err = m.resolveGUIDToDN(identifier)
	case IdentifierTypeSID:
		dn, err = m.resolveSIDToDN(identifier)
	case IdentifierTypeUPN:
		dn, err = m.resolveUPNToDN(identifier)
	case IdentifierTypeSAM:
		dn, err = m.resolveSAMToDN(identifier)
	default:
		return "", fmt.Errorf("unable to determine identifier type for: %s", identifier)
	}

	if err != nil {
		return "", fmt.Errorf("failed to normalize identifier '%s' (type: %s): %w", identifier, idType.String(), err)
	}

	// Apply DN case normalization to ensure uppercase attribute types
	normalizedDN, err := NormalizeDNCase(dn)
	if err != nil {
		return "", fmt.Errorf("failed to normalize DN case for '%s': %w", dn, err)
	}

	// Cache the result
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN:         normalizedDN,
			ObjectGUID: "", // Will be set from LDAP response if available
			ObjectSID:  "", // Will be set from LDAP response if available
			Attributes: make(map[string][]string),
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return normalizedDN, nil
}

// NormalizeToDNBatch normalizes multiple identifiers in a single operation for better performance.
func (m *MemberNormalizer) NormalizeToDNBatch(identifiers []string) (map[string]string, error) {
	if len(identifiers) == 0 {
		return make(map[string]string), nil
	}

	results := make(map[string]string)
	uncached := make([]string, 0)

	// Check cache for all identifiers first
	if m.cacheManager != nil {
		for _, identifier := range identifiers {
			if identifier == "" {
				continue
			}

			identifier = strings.TrimSpace(identifier)
			if cachedEntry, found := m.cacheManager.Get(identifier); found {
				results[identifier] = cachedEntry.DN
			} else {
				uncached = append(uncached, identifier)
			}
		}
	} else {
		// No cache available, all identifiers need processing
		for _, identifier := range identifiers {
			if identifier == "" {
				continue
			}
			uncached = append(uncached, strings.TrimSpace(identifier))
		}
	}

	// Process uncached identifiers
	for _, identifier := range uncached {
		dn, err := m.NormalizeToDN(identifier)
		if err != nil {
			return nil, fmt.Errorf("failed to normalize identifier '%s': %w", identifier, err)
		}
		results[identifier] = dn
	}

	return results, nil
}

// validateDN verifies that a DN exists in Active Directory.
func (m *MemberNormalizer) validateDN(dn string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Normalize DN case before searching to ensure consistent format
	normalizedSearchDN, err := NormalizeDNCase(dn)
	if err != nil {
		return "", fmt.Errorf("failed to normalize DN case for search: %w", err)
	}

	// Perform a base object search to verify the DN exists
	searchReq := &SearchRequest{
		BaseDN:     normalizedSearchDN,
		Scope:      ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"distinguishedName"},
		SizeLimit:  1,
		TimeLimit:  m.timeout,
	}

	result, err := m.client.Search(ctx, searchReq)
	if err != nil {
		return "", fmt.Errorf("DN validation failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("DN not found: %s", normalizedSearchDN)
	}

	// Return the canonical DN from the server, normalized to uppercase attribute types
	canonicalDN := result.Entries[0].GetAttributeValue("distinguishedName")
	if canonicalDN == "" {
		return normalizedSearchDN, nil // Fallback to normalized input DN if canonical not available
	}

	// Normalize the canonical DN from AD (should already be uppercase, but ensure consistency)
	normalizedCanonicalDN, err := NormalizeDNCase(canonicalDN)
	if err != nil {
		return "", fmt.Errorf("failed to normalize canonical DN case: %w", err)
	}

	// Cache the validated DN result
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN:         normalizedCanonicalDN,
			Attributes: make(map[string][]string),
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return normalizedCanonicalDN, nil
}

// resolveGUIDToDN resolves a GUID to its Distinguished Name.
func (m *MemberNormalizer) resolveGUIDToDN(guid string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Create GUID search request
	searchReq, err := m.guidHandler.GenerateGUIDSearchRequest(m.baseDN, guid)
	if err != nil {
		return "", fmt.Errorf("failed to create GUID search request: %w", err)
	}

	searchReq.TimeLimit = m.timeout

	result, err := m.client.Search(ctx, searchReq)
	if err != nil {
		return "", fmt.Errorf("GUID search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("object with GUID %s not found", guid)
	}

	dn := result.Entries[0].DN
	if dn == "" {
		return "", fmt.Errorf("DN not found for GUID %s", guid)
	}

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := NormalizeDNCase(dn)
	if err != nil {
		return "", fmt.Errorf("failed to normalize DN case for GUID %s: %w", guid, err)
	}

	// Cache the result with GUID for future lookups
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN:         normalizedDN,
			ObjectGUID: guid,
			Attributes: make(map[string][]string),
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return normalizedDN, nil
}

// resolveSIDToDN resolves a Security Identifier to its Distinguished Name.
func (m *MemberNormalizer) resolveSIDToDN(sid string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Search by objectSid
	searchReq := &SearchRequest{
		BaseDN:     m.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     fmt.Sprintf("(objectSid=%s)", ldap.EscapeFilter(sid)),
		Attributes: []string{"distinguishedName"},
		SizeLimit:  1,
		TimeLimit:  m.timeout,
	}

	result, err := m.client.Search(ctx, searchReq)
	if err != nil {
		return "", fmt.Errorf("SID search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("object with SID %s not found", sid)
	}

	dn := result.Entries[0].DN
	if dn == "" {
		return "", fmt.Errorf("DN not found for SID %s", sid)
	}

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := NormalizeDNCase(dn)
	if err != nil {
		return "", fmt.Errorf("failed to normalize DN case for SID %s: %w", sid, err)
	}

	// Cache the result with SID for future lookups
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN:         normalizedDN,
			ObjectSID:  sid,
			Attributes: make(map[string][]string),
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return normalizedDN, nil
}

// resolveUPNToDN resolves a User Principal Name to its Distinguished Name.
func (m *MemberNormalizer) resolveUPNToDN(upn string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Search by userPrincipalName
	searchReq := &SearchRequest{
		BaseDN:     m.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     fmt.Sprintf("(userPrincipalName=%s)", ldap.EscapeFilter(upn)),
		Attributes: []string{"distinguishedName"},
		SizeLimit:  1,
		TimeLimit:  m.timeout,
	}

	result, err := m.client.Search(ctx, searchReq)
	if err != nil {
		return "", fmt.Errorf("UPN search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("object with UPN %s not found", upn)
	}

	dn := result.Entries[0].DN
	if dn == "" {
		return "", fmt.Errorf("DN not found for UPN %s", upn)
	}

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := NormalizeDNCase(dn)
	if err != nil {
		return "", fmt.Errorf("failed to normalize DN case for UPN %s: %w", upn, err)
	}

	// Cache the result with UPN for future lookups
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN: normalizedDN,
			Attributes: map[string][]string{
				"userPrincipalName": {upn},
			},
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return normalizedDN, nil
}

// resolveSAMToDN resolves a SAM Account Name to its Distinguished Name.
func (m *MemberNormalizer) resolveSAMToDN(sam string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Extract username from DOMAIN\username format
	username := sam
	if strings.Contains(sam, "\\") {
		parts := strings.SplitN(sam, "\\", 2)
		if len(parts) == 2 {
			username = parts[1]
		}
	}

	// Search by sAMAccountName
	searchReq := &SearchRequest{
		BaseDN:     m.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(username)),
		Attributes: []string{"distinguishedName"},
		SizeLimit:  1,
		TimeLimit:  m.timeout,
	}

	result, err := m.client.Search(ctx, searchReq)
	if err != nil {
		return "", fmt.Errorf("SAM search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("object with SAM %s not found", sam)
	}

	dn := result.Entries[0].DN
	if dn == "" {
		return "", fmt.Errorf("DN not found for SAM %s", sam)
	}

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := NormalizeDNCase(dn)
	if err != nil {
		return "", fmt.Errorf("failed to normalize DN case for SAM %s: %w", sam, err)
	}

	// Cache the result with SAM for future lookups
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN: normalizedDN,
			Attributes: map[string][]string{
				"sAMAccountName": {username},
			},
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return normalizedDN, nil
}

// ValidateIdentifier checks if an identifier is valid and can be normalized.
func (m *MemberNormalizer) ValidateIdentifier(identifier string) error {
	if identifier == "" {
		return fmt.Errorf("identifier cannot be empty")
	}

	identifier = strings.TrimSpace(identifier)
	idType := m.DetectIdentifierType(identifier)

	if idType == IdentifierTypeUnknown {
		return fmt.Errorf("unknown identifier format: %s", identifier)
	}

	// Perform format-specific validation
	switch idType {
	case IdentifierTypeGUID:
		if !m.guidHandler.IsValidGUID(identifier) {
			return fmt.Errorf("invalid GUID format: %s", identifier)
		}
	case IdentifierTypeSID:
		if !sidRegex.MatchString(identifier) {
			return fmt.Errorf("invalid SID format: %s", identifier)
		}
	case IdentifierTypeUPN:
		if !upnRegex.MatchString(identifier) {
			return fmt.Errorf("invalid UPN format: %s", identifier)
		}
	case IdentifierTypeSAM:
		if !samRegex.MatchString(identifier) {
			return fmt.Errorf("invalid SAM format: %s", identifier)
		}
	}

	return nil
}

// GetSupportedFormats returns a list of supported identifier formats.
func (m *MemberNormalizer) GetSupportedFormats() []string {
	return []string{
		"Distinguished Name (DN): CN=User,OU=Users,DC=example,DC=com",
		"GUID: 12345678-1234-1234-1234-123456789012",
		"Security Identifier (SID): S-1-5-21-123456789-123456789-123456789-1001",
		"User Principal Name (UPN): user@example.com",
		"SAM Account Name: DOMAIN\\username or username",
	}
}

// SetBaseDN updates the base DN used for searches.
func (m *MemberNormalizer) SetBaseDN(baseDN string) {
	m.baseDN = baseDN
}

// GetBaseDN returns the current base DN.
func (m *MemberNormalizer) GetBaseDN() string {
	return m.baseDN
}
