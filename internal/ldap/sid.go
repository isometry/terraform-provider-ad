package ldap

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// SID represents a Windows Security Identifier.
// Binary layout: revision (1 byte), sub-authority count (1 byte),
// authority (6 bytes big-endian), sub-authorities (4 bytes each, little-endian).
type SID struct {
	RevisionLevel  uint8
	Authority      uint64
	SubAuthorities []uint32
}

// String returns the standard string representation of the SID (e.g., S-1-5-21-...).
func (s SID) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "S-%d-%d", s.RevisionLevel, s.Authority)
	for _, sa := range s.SubAuthorities {
		fmt.Fprintf(&b, "-%d", sa)
	}
	return b.String()
}

// RID returns the Relative Identifier (last sub-authority).
func (s SID) RID() uint32 {
	if len(s.SubAuthorities) == 0 {
		return 0
	}
	return s.SubAuthorities[len(s.SubAuthorities)-1]
}

// maxSIDAuthority is the largest value the 6-byte big-endian Authority field
// of a Windows SID can hold (2^48 - 1).
const maxSIDAuthority uint64 = 1<<48 - 1

// Bytes encodes the SID to its binary representation as stored in Active Directory.
func (s SID) Bytes() ([]byte, error) {
	count := len(s.SubAuthorities)
	if count > 255 {
		return nil, fmt.Errorf("too many sub-authorities: %d (max 255)", count)
	}
	if s.Authority > maxSIDAuthority {
		return nil, fmt.Errorf("authority %d exceeds 48-bit maximum %d", s.Authority, maxSIDAuthority)
	}

	buf := make([]byte, 8+4*count)
	buf[0] = s.RevisionLevel
	buf[1] = byte(count)

	// Authority is stored as 6 bytes big-endian. Encode as full 8-byte
	// big-endian and copy the low 6 bytes; the bound check above guarantees
	// the high two bytes are zero.
	var authBuf [8]byte
	binary.BigEndian.PutUint64(authBuf[:], s.Authority)
	copy(buf[2:8], authBuf[2:8])

	// Sub-authorities are stored as 4 bytes little-endian each.
	for i, sa := range s.SubAuthorities {
		binary.LittleEndian.PutUint32(buf[8+4*i:], sa)
	}

	return buf, nil
}

// DecodeSID decodes a binary SID into a SID struct.
func DecodeSID(b []byte) (SID, error) {
	if len(b) < 8 {
		return SID{}, fmt.Errorf("binary SID too short: %d bytes (minimum 8)", len(b))
	}

	revision := b[0]
	count := int(b[1])

	if len(b) < 8+4*count {
		return SID{}, fmt.Errorf("binary SID truncated: got %d bytes, need %d for %d sub-authorities", len(b), 8+4*count, count)
	}

	var authority uint64
	for i := 2; i <= 7; i++ {
		authority = authority | uint64(b[i])<<(8*(7-i))
	}

	subAuthorities := make([]uint32, count)
	for i := range count {
		subAuthorities[i] = binary.LittleEndian.Uint32(b[8+4*i:])
	}

	return SID{
		RevisionLevel:  revision,
		Authority:      authority,
		SubAuthorities: subAuthorities,
	}, nil
}

// ParseSID parses a string SID (e.g., "S-1-5-21-123456789-...") into a SID struct.
func ParseSID(s string) (SID, error) {
	if s == "" {
		return SID{}, fmt.Errorf("SID string cannot be empty")
	}

	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return SID{}, fmt.Errorf("invalid SID format: %s", s)
	}

	revision, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return SID{}, fmt.Errorf("invalid SID revision '%s': %w", parts[1], err)
	}

	authority, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return SID{}, fmt.Errorf("invalid SID authority '%s': %w", parts[2], err)
	}

	subAuthorities := make([]uint32, len(parts)-3)
	for i, part := range parts[3:] {
		sa, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return SID{}, fmt.Errorf("invalid SID sub-authority '%s': %w", part, err)
		}
		subAuthorities[i] = uint32(sa)
	}

	return SID{
		RevisionLevel:  uint8(revision),
		Authority:      authority,
		SubAuthorities: subAuthorities,
	}, nil
}

// SIDHandler provides SID operations for Active Directory.
type SIDHandler struct{}

// NewSIDHandler creates a new SID handler instance.
func NewSIDHandler() *SIDHandler {
	return &SIDHandler{}
}

// ConvertBinarySIDToString converts a binary SID to its string representation.
func (h *SIDHandler) ConvertBinarySIDToString(binarySID []byte) (string, error) {
	if len(binarySID) == 0 {
		return "", fmt.Errorf("binary SID cannot be empty")
	}
	sid, err := DecodeSID(binarySID)
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}

// ConvertBinarySIDToStringSafe converts a binary SID to string, returning empty string if conversion fails.
func (h *SIDHandler) ConvertBinarySIDToStringSafe(binarySID []byte) string {
	s, err := h.ConvertBinarySIDToString(binarySID)
	if err != nil {
		return ""
	}
	return s
}

// ExtractSID extracts the objectSid from an LDAP entry and returns it as a string.
func (h *SIDHandler) ExtractSID(entry *ldap.Entry) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("LDAP entry cannot be nil")
	}
	sidBytes := entry.GetRawAttributeValue("objectSid")
	if len(sidBytes) == 0 {
		return "", fmt.Errorf("objectSid attribute not found in entry")
	}
	return h.ConvertBinarySIDToString(sidBytes)
}

// ExtractSIDSafe extracts the objectSid from an LDAP entry, returning empty string if not found.
// Handles both binary SID data (from real LDAP) and string SID data (for testing).
func (h *SIDHandler) ExtractSIDSafe(entry *ldap.Entry) string {
	if entry == nil {
		return ""
	}

	// First try raw binary SID data (real LDAP).
	sidBytes := entry.GetRawAttributeValue("objectSid")
	if len(sidBytes) > 0 {
		s, err := h.ConvertBinarySIDToString(sidBytes)
		if err != nil {
			return ""
		}
		return s
	}

	// Fallback to string SID value (for testing).
	sidString := entry.GetAttributeValue("objectSid")
	if sidString != "" && h.ValidateSIDString(sidString) == nil {
		return sidString
	}

	return ""
}

// ValidateSIDString validates that a string is a properly formatted SID.
func (h *SIDHandler) ValidateSIDString(sidString string) error {
	_, err := ParseSID(sidString)
	return err
}

// IsWellKnownSID checks if the SID is a well-known SID.
func (h *SIDHandler) IsWellKnownSID(sidString string) bool {
	wellKnownPrefixes := []string{
		"S-1-0",    // Null Authority
		"S-1-1",    // World Authority
		"S-1-2",    // Local Authority
		"S-1-3",    // Creator Authority
		"S-1-4",    // Non-unique Authority
		"S-1-5-18", // Local System
		"S-1-5-19", // Local Service
		"S-1-5-20", // Network Service
	}

	for _, prefix := range wellKnownPrefixes {
		if len(sidString) >= len(prefix) && sidString[:len(prefix)] == prefix {
			return true
		}
	}

	return false
}

// StringToSIDBytes converts a string SID to its binary representation.
func (h *SIDHandler) StringToSIDBytes(sidString string) ([]byte, error) {
	sid, err := ParseSID(sidString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SID string: %w", err)
	}
	return sid.Bytes()
}

// SIDToSearchFilter creates an LDAP search filter for a SID using binary format.
// This is required because Active Directory stores objectSid as binary data.
func (h *SIDHandler) SIDToSearchFilter(sidString string) (string, error) {
	sidBytes, err := h.StringToSIDBytes(sidString)
	if err != nil {
		return "", fmt.Errorf("failed to convert SID to bytes: %w", err)
	}
	return fmt.Sprintf("(objectSid=%s)", ldap.EscapeFilter(string(sidBytes))), nil
}
