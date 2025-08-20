package ldap

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// GUIDHandler provides GUID operations for Active Directory.
// Active Directory stores GUIDs in a mixed-endian format that differs from standard UUID byte ordering.
type GUIDHandler struct{}

// NewGUIDHandler creates a new GUID handler instance.
func NewGUIDHandler() *GUIDHandler {
	return &GUIDHandler{}
}

// Active Directory GUID format patterns
var (
	// Hyphenated GUID format: 12345678-1234-1234-1234-123456789012
	hyphenatedGUIDRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	// Compact GUID format: 123456781234123412341234567890123
	compactGUIDRegex = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
)

// Constants for GUID byte array length
const (
	GUIDBytesLength   = 16 // GUID is always 16 bytes
	GUIDStringLength  = 36 // Hyphenated GUID string length
	CompactGUIDLength = 32 // Compact GUID string length
)

// IsValidGUID checks if a string is a valid GUID format (hyphenated or compact).
func (g *GUIDHandler) IsValidGUID(guidString string) bool {
	if guidString == "" {
		return false
	}

	return hyphenatedGUIDRegex.MatchString(guidString) || compactGUIDRegex.MatchString(guidString)
}

// NormalizeGUID converts a GUID string to standard hyphenated format.
func (g *GUIDHandler) NormalizeGUID(guidString string) (string, error) {
	if guidString == "" {
		return "", fmt.Errorf("GUID string cannot be empty")
	}

	// Remove any whitespace
	guidString = strings.TrimSpace(guidString)

	// If already hyphenated and valid, return as-is
	if hyphenatedGUIDRegex.MatchString(guidString) {
		return strings.ToLower(guidString), nil
	}

	// If compact format, convert to hyphenated
	if compactGUIDRegex.MatchString(guidString) {
		guidString = strings.ToLower(guidString)
		return fmt.Sprintf("%s-%s-%s-%s-%s",
			guidString[0:8],
			guidString[8:12],
			guidString[12:16],
			guidString[16:20],
			guidString[20:32],
		), nil
	}

	return "", fmt.Errorf("invalid GUID format: %s", guidString)
}

// StringToGUIDBytes converts a GUID string to Active Directory byte format.
// Active Directory uses mixed-endian encoding:
// - First 4 bytes (Data1): little-endian
// - Next 2 bytes (Data2): little-endian
// - Next 2 bytes (Data3): little-endian
// - Last 8 bytes (Data4): big-endian
func (g *GUIDHandler) StringToGUIDBytes(guidString string) ([]byte, error) {
	normalizedGUID, err := g.NormalizeGUID(guidString)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize GUID: %w", err)
	}

	// Remove hyphens for processing
	guidHex := strings.ReplaceAll(normalizedGUID, "-", "")

	// Convert hex string to bytes
	guidBytes, err := hex.DecodeString(guidHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode GUID hex: %w", err)
	}

	if len(guidBytes) != GUIDBytesLength {
		return nil, fmt.Errorf("invalid GUID byte length: expected %d, got %d", GUIDBytesLength, len(guidBytes))
	}

	// Convert to Active Directory mixed-endian format
	adBytes := make([]byte, GUIDBytesLength)

	// Data1 (bytes 0-3): reverse byte order (little-endian)
	adBytes[0] = guidBytes[3]
	adBytes[1] = guidBytes[2]
	adBytes[2] = guidBytes[1]
	adBytes[3] = guidBytes[0]

	// Data2 (bytes 4-5): reverse byte order (little-endian)
	adBytes[4] = guidBytes[5]
	adBytes[5] = guidBytes[4]

	// Data3 (bytes 6-7): reverse byte order (little-endian)
	adBytes[6] = guidBytes[7]
	adBytes[7] = guidBytes[6]

	// Data4 (bytes 8-15): keep original order (big-endian)
	copy(adBytes[8:], guidBytes[8:])

	return adBytes, nil
}

// GUIDBytesToString converts Active Directory GUID bytes to standard string format.
func (g *GUIDHandler) GUIDBytesToString(guidBytes []byte) (string, error) {
	if len(guidBytes) != GUIDBytesLength {
		return "", fmt.Errorf("invalid GUID byte length: expected %d, got %d", GUIDBytesLength, len(guidBytes))
	}

	// Convert from Active Directory mixed-endian format to standard format
	standardBytes := make([]byte, GUIDBytesLength)

	// Data1 (bytes 0-3): reverse byte order (from little-endian)
	standardBytes[0] = guidBytes[3]
	standardBytes[1] = guidBytes[2]
	standardBytes[2] = guidBytes[1]
	standardBytes[3] = guidBytes[0]

	// Data2 (bytes 4-5): reverse byte order (from little-endian)
	standardBytes[4] = guidBytes[5]
	standardBytes[5] = guidBytes[4]

	// Data3 (bytes 6-7): reverse byte order (from little-endian)
	standardBytes[6] = guidBytes[7]
	standardBytes[7] = guidBytes[6]

	// Data4 (bytes 8-15): keep original order (big-endian)
	copy(standardBytes[8:], guidBytes[8:])

	// Convert to hex string and format
	hexString := hex.EncodeToString(standardBytes)

	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexString[0:8],
		hexString[8:12],
		hexString[12:16],
		hexString[16:20],
		hexString[20:32],
	), nil
}

// GUIDToSearchFilter creates an LDAP search filter for a GUID using binary format.
// This is the most efficient way to search for objects by GUID in Active Directory.
func (g *GUIDHandler) GUIDToSearchFilter(guidString string) (string, error) {
	guidBytes, err := g.StringToGUIDBytes(guidString)
	if err != nil {
		return "", fmt.Errorf("failed to convert GUID to bytes: %w", err)
	}

	// Create binary search filter - AD requires this format for GUID searches
	filter := fmt.Sprintf("(objectGUID=%s)", ldap.EscapeFilter(string(guidBytes)))

	return filter, nil
}

// GUIDToHexSearchFilter creates an LDAP search filter using hex-encoded GUID.
// This is an alternative format that some LDAP implementations support.
func (g *GUIDHandler) GUIDToHexSearchFilter(guidString string) (string, error) {
	guidBytes, err := g.StringToGUIDBytes(guidString)
	if err != nil {
		return "", fmt.Errorf("failed to convert GUID to bytes: %w", err)
	}

	// Create hex-encoded search filter
	hexString := hex.EncodeToString(guidBytes)

	// Format as hex with backslash escaping for each byte
	var filterBytes []string
	for i := 0; i < len(hexString); i += 2 {
		filterBytes = append(filterBytes, "\\"+hexString[i:i+2])
	}

	filter := fmt.Sprintf("(objectGUID=%s)", strings.Join(filterBytes, ""))

	return filter, nil
}

// ExtractGUID extracts the objectGUID from an LDAP entry and returns it as a string.
func (g *GUIDHandler) ExtractGUID(entry *ldap.Entry) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("LDAP entry cannot be nil")
	}

	// Get the objectGUID attribute
	guidAttr := entry.GetRawAttributeValue("objectGUID")
	if len(guidAttr) == 0 {
		return "", fmt.Errorf("objectGUID attribute not found in entry")
	}

	if len(guidAttr) != GUIDBytesLength {
		return "", fmt.Errorf("invalid objectGUID length: expected %d bytes, got %d", GUIDBytesLength, len(guidAttr))
	}

	return g.GUIDBytesToString(guidAttr)
}

// ExtractGUIDSafe extracts the objectGUID from an LDAP entry, returning empty string if not found.
// This is useful when GUID might not be present and you want to handle it gracefully.
func (g *GUIDHandler) ExtractGUIDSafe(entry *ldap.Entry) string {
	guid, err := g.ExtractGUID(entry)
	if err != nil {
		return ""
	}
	return guid
}

// CompareGUIDs compares two GUID strings for equality, handling different formats.
func (g *GUIDHandler) CompareGUIDs(guid1, guid2 string) (bool, error) {
	normalized1, err := g.NormalizeGUID(guid1)
	if err != nil {
		return false, fmt.Errorf("failed to normalize first GUID: %w", err)
	}

	normalized2, err := g.NormalizeGUID(guid2)
	if err != nil {
		return false, fmt.Errorf("failed to normalize second GUID: %w", err)
	}

	return strings.EqualFold(normalized1, normalized2), nil
}

// GenerateGUIDSearchRequest creates a SearchRequest for finding an object by GUID.
func (g *GUIDHandler) GenerateGUIDSearchRequest(baseDN, guidString string) (*SearchRequest, error) {
	filter, err := g.GUIDToSearchFilter(guidString)
	if err != nil {
		return nil, fmt.Errorf("failed to create GUID search filter: %w", err)
	}

	return &SearchRequest{
		BaseDN:     baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: []string{"objectGUID", "distinguishedName", "objectClass"},
		SizeLimit:  1, // GUID should be unique
	}, nil
}

// ValidateGUIDBytes validates that bytes represent a valid GUID.
func (g *GUIDHandler) ValidateGUIDBytes(guidBytes []byte) error {
	if len(guidBytes) != GUIDBytesLength {
		return fmt.Errorf("invalid GUID byte length: expected %d, got %d", GUIDBytesLength, len(guidBytes))
	}

	// Check for nil GUID (all zeros)
	allZero := true
	for _, b := range guidBytes {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		return fmt.Errorf("GUID cannot be all zeros")
	}

	return nil
}

// ParseGUIDFromDN attempts to extract a GUID from a distinguished name if it contains one.
// Some DNs might include GUIDs in special formats.
func (g *GUIDHandler) ParseGUIDFromDN(dn string) (string, bool) {
	// Look for GUID patterns in the DN
	if hyphenatedGUIDRegex.MatchString(dn) {
		return dn, true
	}

	// Look for compact GUID patterns
	if compactGUIDRegex.MatchString(dn) {
		normalized, err := g.NormalizeGUID(dn)
		if err == nil {
			return normalized, true
		}
	}

	return "", false
}
