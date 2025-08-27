package ldap

import (
	"fmt"

	"github.com/bwmarrin/go-objectsid"
	"github.com/go-ldap/ldap/v3"
)

// SIDHandler provides SID operations for Active Directory.
// Active Directory stores SIDs in binary format that needs to be converted to human-readable strings.
type SIDHandler struct{}

// NewSIDHandler creates a new SID handler instance.
func NewSIDHandler() *SIDHandler {
	return &SIDHandler{}
}

// ConvertBinarySIDToString converts a binary SID to its string representation.
// Active Directory stores objectSid as binary data that needs conversion to S-1-5-21-... format.
func (s *SIDHandler) ConvertBinarySIDToString(binarySID []byte) (string, error) {
	if len(binarySID) == 0 {
		return "", fmt.Errorf("binary SID cannot be empty")
	}

	// Use go-objectsid to decode the binary SID
	sid := objectsid.Decode(binarySID)

	// Return the string representation
	return sid.String(), nil
}

// ConvertBinarySIDToStringSafe converts a binary SID to string, returning empty string if conversion fails.
// This is useful when SID might be malformed and you want to handle it gracefully.
func (s *SIDHandler) ConvertBinarySIDToStringSafe(binarySID []byte) string {
	sidString, err := s.ConvertBinarySIDToString(binarySID)
	if err != nil {
		return ""
	}
	return sidString
}

// ExtractSID extracts the objectSid from an LDAP entry and returns it as a string.
func (s *SIDHandler) ExtractSID(entry *ldap.Entry) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("LDAP entry cannot be nil")
	}

	// Get the objectSid attribute as raw bytes
	sidBytes := entry.GetRawAttributeValue("objectSid")
	if len(sidBytes) == 0 {
		return "", fmt.Errorf("objectSid attribute not found in entry")
	}

	return s.ConvertBinarySIDToString(sidBytes)
}

// ExtractSIDSafe extracts the objectSid from an LDAP entry, returning empty string if not found.
// This is useful when SID might not be present and you want to handle it gracefully.
// This function handles both binary SID data (from real LDAP) and string SID data (for testing).
func (s *SIDHandler) ExtractSIDSafe(entry *ldap.Entry) string {
	if entry == nil {
		return ""
	}

	// First try to get raw binary SID data (real LDAP)
	sidBytes := entry.GetRawAttributeValue("objectSid")
	if len(sidBytes) > 0 {
		sid, err := s.ConvertBinarySIDToString(sidBytes)
		if err != nil {
			return ""
		}
		return sid
	}

	// Fallback to string SID value (for testing)
	sidString := entry.GetAttributeValue("objectSid")
	if sidString != "" && s.ValidateSIDString(sidString) == nil {
		return sidString
	}

	return ""
}

// ValidateSIDString validates that a string is a properly formatted SID.
func (s *SIDHandler) ValidateSIDString(sidString string) error {
	if sidString == "" {
		return fmt.Errorf("SID string cannot be empty")
	}

	// Basic SID format validation - should start with S- and contain only valid characters
	if len(sidString) < 5 || sidString[:2] != "S-" {
		return fmt.Errorf("invalid SID format: must start with 'S-'")
	}

	// Additional validation could be added here if needed
	return nil
}

// IsWellKnownSID checks if the SID is a well-known SID.
func (s *SIDHandler) IsWellKnownSID(sidString string) bool {
	// Well-known SIDs typically have specific patterns
	// This is a basic implementation - could be expanded with more well-known SIDs
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

// GetSIDComponents extracts components from a binary SID using go-objectsid.
// Returns the SID object which provides access to individual components.
func (s *SIDHandler) GetSIDComponents(binarySID []byte) (*objectsid.SID, error) {
	if len(binarySID) == 0 {
		return nil, fmt.Errorf("binary SID cannot be empty")
	}

	sid := objectsid.Decode(binarySID)

	return &sid, nil
}
