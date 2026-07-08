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

// ResolvedIdentifier is the full result of resolving a DN/GUID/SID/UPN/SAM
// identifier to the AD object it names. GUID is empty when unavailable
// (never an error on its own).
type ResolvedIdentifier struct {
	DN   string
	GUID string // canonical hyphenated form
}

// MemberNormalizer handles normalization of various identifier formats to Distinguished Names.
type MemberNormalizer struct {
	client       Client
	guidHandler  *GUIDHandler
	sidHandler   *SIDHandler
	baseDN       string
	cacheManager *CacheManager // Reference to shared cache
	timeout      time.Duration
}

// NewMemberNormalizer creates a new member identifier normalizer.
func NewMemberNormalizer(client Client, baseDN string, cacheManager *CacheManager) *MemberNormalizer {
	return &MemberNormalizer{
		client:       client,
		guidHandler:  NewGUIDHandler(),
		sidHandler:   NewSIDHandler(),
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

// Resolve converts any identifier format (DN/GUID/SID/UPN/SAM) to the AD
// object it names, returning both its Distinguished Name and (when available)
// its GUID.
func (m *MemberNormalizer) Resolve(identifier string) (ResolvedIdentifier, error) {
	if identifier == "" {
		return ResolvedIdentifier{}, fmt.Errorf("identifier cannot be empty")
	}

	identifier = strings.TrimSpace(identifier)

	// Check cache first
	if m.cacheManager != nil {
		if cachedEntry, found := m.cacheManager.Get(identifier); found {
			return ResolvedIdentifier{DN: cachedEntry.DN, GUID: cachedEntry.ObjectGUID}, nil
		}
	}

	// Detect identifier type
	idType := m.DetectIdentifierType(identifier)

	var resolved ResolvedIdentifier
	var err error

	switch idType {
	case IdentifierTypeDN:
		// Already a DN, validate and return
		resolved, err = m.validateDN(identifier)
	case IdentifierTypeGUID:
		resolved, err = m.resolveGUID(identifier)
	case IdentifierTypeSID:
		resolved, err = m.ResolveSID(identifier)
	case IdentifierTypeUPN:
		resolved, err = m.resolveUPN(identifier)
	case IdentifierTypeSAM:
		resolved, err = m.resolveSAM(identifier)
	default:
		return ResolvedIdentifier{}, fmt.Errorf("unable to determine identifier type for: %s", identifier)
	}

	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("failed to normalize identifier '%s' (type: %s): %w", identifier, idType.String(), err)
	}

	// Apply DN case normalization to ensure uppercase attribute types
	normalizedDN, err := NormalizeDNCase(resolved.DN)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("failed to normalize DN case for '%s': %w", resolved.DN, err)
	}
	resolved.DN = normalizedDN

	// Cache the result
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN:         resolved.DN,
			ObjectGUID: resolved.GUID,
			ObjectSID:  "", // Will be set from LDAP response if available
			Attributes: make(map[string][]string),
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return resolved, nil
}

// ResolveBatch resolves multiple identifiers in a single operation for better performance.
// Returns two maps: successful resolutions (identifier -> ResolvedIdentifier) and failures
// (identifier -> error). This allows callers to decide how to handle partial failures based
// on configuration.
//
// Results and failures are keyed by the caller's original identifier (whitespace
// preserved); internal cache and LDAP lookups use the trimmed value. Identifiers
// that are empty or whitespace-only are skipped and appear in neither map.
func (m *MemberNormalizer) ResolveBatch(identifiers []string) (map[string]ResolvedIdentifier, map[string]error) {
	results := make(map[string]ResolvedIdentifier, len(identifiers))
	failures := make(map[string]error, len(identifiers))

	for _, original := range identifiers {
		trimmed := strings.TrimSpace(original)
		if trimmed == "" {
			continue
		}
		if m.cacheManager != nil {
			if cached, found := m.cacheManager.Get(trimmed); found {
				results[original] = ResolvedIdentifier{DN: cached.DN, GUID: cached.ObjectGUID}
				continue
			}
		}
		resolved, err := m.Resolve(trimmed)
		if err != nil {
			failures[original] = err
		} else {
			results[original] = resolved
		}
	}
	return results, failures
}

// validateDN verifies that a DN-shaped input exists in Active Directory.
func (m *MemberNormalizer) validateDN(dn string) (ResolvedIdentifier, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Normalize DN case before searching to ensure consistent format
	normalizedSearchDN, err := NormalizeDNCase(dn)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("failed to normalize DN case for search: %w", err)
	}

	// Perform a base object search to verify the DN exists
	searchReq := &SearchRequest{
		BaseDN:     normalizedSearchDN,
		Scope:      ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"distinguishedName", "objectGUID"},
		SizeLimit:  1,
		TimeLimit:  m.timeout,
	}

	result, err := m.client.Search(ctx, searchReq)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("DN validation failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return ResolvedIdentifier{}, fmt.Errorf("DN not found: %s", normalizedSearchDN)
	}

	guid := m.guidHandler.ExtractGUIDSafe(result.Entries[0])

	// Return the canonical DN from the server, normalized to uppercase attribute types
	canonicalDN := result.Entries[0].GetAttributeValue("distinguishedName")
	if canonicalDN == "" {
		return ResolvedIdentifier{DN: normalizedSearchDN, GUID: guid}, nil // Fallback to normalized input DN if canonical not available
	}

	// Normalize the canonical DN from AD (should already be uppercase, but ensure consistency)
	normalizedCanonicalDN, err := NormalizeDNCase(canonicalDN)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("failed to normalize canonical DN case: %w", err)
	}

	// Cache the validated DN result
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN:         normalizedCanonicalDN,
			ObjectGUID: guid,
			Attributes: make(map[string][]string),
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return ResolvedIdentifier{DN: normalizedCanonicalDN, GUID: guid}, nil
}

// resolveGUID resolves a GUID to its Distinguished Name.
func (m *MemberNormalizer) resolveGUID(guid string) (ResolvedIdentifier, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Create GUID search request
	searchReq, err := m.guidHandler.GenerateGUIDSearchRequest(m.baseDN, guid)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("failed to create GUID search request: %w", err)
	}

	searchReq.TimeLimit = m.timeout

	result, err := m.client.Search(ctx, searchReq)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("GUID search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return ResolvedIdentifier{}, fmt.Errorf("object with GUID %s not found", guid)
	}

	dn := result.Entries[0].DN
	if dn == "" {
		return ResolvedIdentifier{}, fmt.Errorf("DN not found for GUID %s", guid)
	}

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := NormalizeDNCase(dn)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("failed to normalize DN case for GUID %s: %w", guid, err)
	}

	// Prefer the canonical GUID extracted from the entry itself, falling back
	// to the (already-canonical, since it matched IdentifierTypeGUID) input.
	resolvedGUID := m.guidHandler.ExtractGUIDSafe(result.Entries[0])
	if resolvedGUID == "" {
		if normalized, normErr := m.guidHandler.NormalizeGUID(guid); normErr == nil {
			resolvedGUID = normalized
		}
	}

	// Cache the result with GUID for future lookups
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN:         normalizedDN,
			ObjectGUID: resolvedGUID,
			Attributes: make(map[string][]string),
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return ResolvedIdentifier{DN: normalizedDN, GUID: resolvedGUID}, nil
}

// ResolveSID resolves a Security Identifier to its Distinguished Name.
func (m *MemberNormalizer) ResolveSID(sid string) (ResolvedIdentifier, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Search by objectSid using binary encoding
	sidFilter, err := m.sidHandler.SIDToSearchFilter(sid)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("failed to create SID search filter: %w", err)
	}

	searchReq := &SearchRequest{
		BaseDN:     m.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     sidFilter,
		Attributes: []string{"distinguishedName", "objectGUID"},
		SizeLimit:  1,
		TimeLimit:  m.timeout,
	}

	result, err := m.client.Search(ctx, searchReq)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("SID search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return ResolvedIdentifier{}, fmt.Errorf("object with SID %s not found", sid)
	}

	dn := result.Entries[0].DN
	if dn == "" {
		return ResolvedIdentifier{}, fmt.Errorf("DN not found for SID %s", sid)
	}

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := NormalizeDNCase(dn)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("failed to normalize DN case for SID %s: %w", sid, err)
	}

	guid := m.guidHandler.ExtractGUIDSafe(result.Entries[0])

	// Cache the result with SID for future lookups
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN:         normalizedDN,
			ObjectGUID: guid,
			ObjectSID:  sid,
			Attributes: make(map[string][]string),
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return ResolvedIdentifier{DN: normalizedDN, GUID: guid}, nil
}

// resolveUPN resolves a User Principal Name to its Distinguished Name.
func (m *MemberNormalizer) resolveUPN(upn string) (ResolvedIdentifier, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Search by userPrincipalName
	searchReq := &SearchRequest{
		BaseDN:     m.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     fmt.Sprintf("(userPrincipalName=%s)", ldap.EscapeFilter(upn)),
		Attributes: []string{"distinguishedName", "objectGUID"},
		SizeLimit:  1,
		TimeLimit:  m.timeout,
	}

	result, err := m.client.Search(ctx, searchReq)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("UPN search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return ResolvedIdentifier{}, fmt.Errorf("object with UPN %s not found", upn)
	}

	dn := result.Entries[0].DN
	if dn == "" {
		return ResolvedIdentifier{}, fmt.Errorf("DN not found for UPN %s", upn)
	}

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := NormalizeDNCase(dn)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("failed to normalize DN case for UPN %s: %w", upn, err)
	}

	guid := m.guidHandler.ExtractGUIDSafe(result.Entries[0])

	// Cache the result with UPN for future lookups
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN:         normalizedDN,
			ObjectGUID: guid,
			Attributes: map[string][]string{
				"userPrincipalName": {upn},
			},
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return ResolvedIdentifier{DN: normalizedDN, GUID: guid}, nil
}

// resolveSAM resolves a SAM Account Name to its Distinguished Name.
func (m *MemberNormalizer) resolveSAM(sam string) (ResolvedIdentifier, error) {
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
		Attributes: []string{"distinguishedName", "objectGUID"},
		SizeLimit:  1,
		TimeLimit:  m.timeout,
	}

	result, err := m.client.Search(ctx, searchReq)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("SAM search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return ResolvedIdentifier{}, fmt.Errorf("object with SAM %s not found", sam)
	}

	dn := result.Entries[0].DN
	if dn == "" {
		return ResolvedIdentifier{}, fmt.Errorf("DN not found for SAM %s", sam)
	}

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := NormalizeDNCase(dn)
	if err != nil {
		return ResolvedIdentifier{}, fmt.Errorf("failed to normalize DN case for SAM %s: %w", sam, err)
	}

	guid := m.guidHandler.ExtractGUIDSafe(result.Entries[0])

	// Cache the result with SAM for future lookups
	if m.cacheManager != nil {
		cacheEntry := &LDAPCacheEntry{
			DN:         normalizedDN,
			ObjectGUID: guid,
			Attributes: map[string][]string{
				"sAMAccountName": {username},
			},
		}
		_ = m.cacheManager.Put(cacheEntry) // Ignore cache errors - they're not critical
	}

	return ResolvedIdentifier{DN: normalizedDN, GUID: guid}, nil
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
