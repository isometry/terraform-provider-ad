package ldap

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
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

// Regular expressions for identifier format detection
var (
	// DN format: CN=User,OU=Users,DC=example,DC=com
	dnRegex = regexp.MustCompile(`^(?i)(CN|OU|DC|O|C|STREET|L|ST|POSTALCODE)=.+`)

	// SID format: S-1-5-21-domain-rid or S-1-5-32-alias
	sidRegex = regexp.MustCompile(`^S-1-\d+(-\d+)*$`)

	// UPN format: user@domain.com
	upnRegex = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

	// SAM format: DOMAIN\username or just username
	samRegex = regexp.MustCompile(`^([^\\@\s]+\\)?[^\\@\s]+$`)
)

// CacheEntry represents a cached normalization result.
type CacheEntry struct {
	DN        string
	Timestamp time.Time
	TTL       time.Duration
}

// IsExpired checks if the cache entry has expired.
func (c *CacheEntry) IsExpired() bool {
	return time.Since(c.Timestamp) > c.TTL
}

// MemberNormalizer handles normalization of various identifier formats to Distinguished Names.
type MemberNormalizer struct {
	client      Client
	guidHandler *GUIDHandler
	baseDN      string

	// Caching for performance optimization
	cache    map[string]*CacheEntry
	cacheMu  sync.RWMutex
	cacheTTL time.Duration

	// Configuration
	maxCacheSize int
	timeout      time.Duration
}

// NewMemberNormalizer creates a new member identifier normalizer.
func NewMemberNormalizer(client Client, baseDN string) *MemberNormalizer {
	return &MemberNormalizer{
		client:       client,
		guidHandler:  NewGUIDHandler(),
		baseDN:       baseDN,
		cache:        make(map[string]*CacheEntry),
		cacheTTL:     15 * time.Minute, // Cache results for 15 minutes
		maxCacheSize: 1000,             // Maximum cache entries
		timeout:      30 * time.Second, // LDAP operation timeout
	}
}

// SetCacheTTL sets the cache time-to-live duration.
func (m *MemberNormalizer) SetCacheTTL(ttl time.Duration) {
	m.cacheTTL = ttl
}

// SetMaxCacheSize sets the maximum number of cache entries.
func (m *MemberNormalizer) SetMaxCacheSize(size int) {
	m.maxCacheSize = size
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
	if dn, found := m.getCachedDN(identifier); found {
		return dn, nil
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

	// Cache the result
	m.cacheDN(identifier, dn)

	return dn, nil
}

// NormalizeToDNBatch normalizes multiple identifiers in a single operation for better performance.
func (m *MemberNormalizer) NormalizeToDNBatch(identifiers []string) (map[string]string, error) {
	if len(identifiers) == 0 {
		return make(map[string]string), nil
	}

	results := make(map[string]string)
	uncached := make([]string, 0)

	// Check cache for all identifiers first
	for _, identifier := range identifiers {
		if identifier == "" {
			continue
		}

		identifier = strings.TrimSpace(identifier)
		if dn, found := m.getCachedDN(identifier); found {
			results[identifier] = dn
		} else {
			uncached = append(uncached, identifier)
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

	// Perform a base object search to verify the DN exists
	searchReq := &SearchRequest{
		BaseDN:     dn,
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
		return "", fmt.Errorf("DN not found: %s", dn)
	}

	// Return the canonical DN from the server
	canonicalDN := result.Entries[0].GetAttributeValue("distinguishedName")
	if canonicalDN == "" {
		return dn, nil // Fallback to input DN if canonical not available
	}

	return canonicalDN, nil
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

	return dn, nil
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

	return dn, nil
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

	return dn, nil
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

	return dn, nil
}

// getCachedDN retrieves a DN from cache if available and not expired.
func (m *MemberNormalizer) getCachedDN(identifier string) (string, bool) {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()

	entry, exists := m.cache[identifier]
	if !exists {
		return "", false
	}

	if entry.IsExpired() {
		// Entry expired, remove it
		go m.removeExpiredEntry(identifier)
		return "", false
	}

	return entry.DN, true
}

// cacheDN stores a DN in cache.
func (m *MemberNormalizer) cacheDN(identifier, dn string) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	// Check if cache is full
	if len(m.cache) >= m.maxCacheSize {
		m.evictOldestEntry()
	}

	m.cache[identifier] = &CacheEntry{
		DN:        dn,
		Timestamp: time.Now(),
		TTL:       m.cacheTTL,
	}
}

// removeExpiredEntry removes an expired entry from cache.
func (m *MemberNormalizer) removeExpiredEntry(identifier string) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	if entry, exists := m.cache[identifier]; exists && entry.IsExpired() {
		delete(m.cache, identifier)
	}
}

// evictOldestEntry removes the oldest entry from cache to make room for new ones.
func (m *MemberNormalizer) evictOldestEntry() {
	var oldestKey string
	var oldestTime time.Time

	first := true
	for key, entry := range m.cache {
		if first || entry.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Timestamp
			first = false
		}
	}

	if oldestKey != "" {
		delete(m.cache, oldestKey)
	}
}

// ClearCache removes all entries from the cache.
func (m *MemberNormalizer) ClearCache() {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	m.cache = make(map[string]*CacheEntry)
}

// CacheStats returns statistics about the cache.
func (m *MemberNormalizer) CacheStats() map[string]interface{} {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()

	total := len(m.cache)
	expired := 0

	for _, entry := range m.cache {
		if entry.IsExpired() {
			expired++
		}
	}

	return map[string]interface{}{
		"total_entries":   total,
		"expired_entries": expired,
		"active_entries":  total - expired,
		"max_size":        m.maxCacheSize,
		"cache_ttl":       m.cacheTTL.String(),
	}
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
