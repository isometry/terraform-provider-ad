package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGUIDHandler_IsValidGUID(t *testing.T) {
	handler := NewGUIDHandler()

	tests := []struct {
		name     string
		guid     string
		expected bool
	}{
		{
			name:     "valid hyphenated GUID",
			guid:     "12345678-1234-1234-1234-123456789012",
			expected: true,
		},
		{
			name:     "valid hyphenated GUID uppercase",
			guid:     "12345678-1234-1234-1234-123456789012",
			expected: true,
		},
		{
			name:     "valid compact GUID",
			guid:     "12345678123412341234123456789012",
			expected: true,
		},
		{
			name:     "valid compact GUID uppercase",
			guid:     "12345678123412341234123456789012",
			expected: true,
		},
		{
			name:     "empty string",
			guid:     "",
			expected: false,
		},
		{
			name:     "invalid format - too short",
			guid:     "12345678-1234-1234-1234-12345678901",
			expected: false,
		},
		{
			name:     "invalid format - too long",
			guid:     "12345678-1234-1234-1234-1234567890123",
			expected: false,
		},
		{
			name:     "invalid format - wrong separators",
			guid:     "12345678_1234_1234_1234_123456789012",
			expected: false,
		},
		{
			name:     "invalid format - non-hex characters",
			guid:     "12345678-1234-1234-1234-12345678901g",
			expected: false,
		},
		{
			name:     "invalid compact - too short",
			guid:     "1234567812341234123412345678901",
			expected: false,
		},
		{
			name:     "invalid compact - too long",
			guid:     "123456781234123412341234567890123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.IsValidGUID(tt.guid)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGUIDHandler_NormalizeGUID(t *testing.T) {
	handler := NewGUIDHandler()

	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "already normalized lowercase",
			input:    "12345678-1234-1234-1234-123456789012",
			expected: "12345678-1234-1234-1234-123456789012",
			wantErr:  false,
		},
		{
			name:     "uppercase to lowercase",
			input:    "12345678-1234-1234-1234-123456789012",
			expected: "12345678-1234-1234-1234-123456789012",
			wantErr:  false,
		},
		{
			name:     "compact to hyphenated",
			input:    "12345678123412341234123456789012",
			expected: "12345678-1234-1234-1234-123456789012",
			wantErr:  false,
		},
		{
			name:     "compact uppercase to hyphenated lowercase",
			input:    "12345678123412341234123456789012",
			expected: "12345678-1234-1234-1234-123456789012",
			wantErr:  false,
		},
		{
			name:     "with whitespace",
			input:    "  12345678-1234-1234-1234-123456789012  ",
			expected: "12345678-1234-1234-1234-123456789012",
			wantErr:  false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid format",
			input:   "invalid-guid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.NormalizeGUID(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGUIDHandler_StringToGUIDBytes(t *testing.T) {
	handler := NewGUIDHandler()

	// Test GUID: 12345678-1234-1234-1234-123456789012
	// Standard byte order:   [0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12]
	// AD mixed-endian order: [0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12]

	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:  "valid hyphenated GUID",
			input: "12345678-1234-1234-1234-123456789012",
			expected: []byte{
				0x78, 0x56, 0x34, 0x12, // Data1: reversed
				0x34, 0x12, // Data2: reversed
				0x34, 0x12, // Data3: reversed
				0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, // Data4: original order
			},
			wantErr: false,
		},
		{
			name:  "valid compact GUID",
			input: "12345678123412341234123456789012",
			expected: []byte{
				0x78, 0x56, 0x34, 0x12, // Data1: reversed
				0x34, 0x12, // Data2: reversed
				0x34, 0x12, // Data3: reversed
				0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, // Data4: original order
			},
			wantErr: false,
		},
		{
			name:    "invalid GUID",
			input:   "invalid-guid",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.StringToGUIDBytes(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
			assert.Equal(t, GUIDBytesLength, len(result))
		})
	}
}

func TestGUIDHandler_GUIDBytesToString(t *testing.T) {
	handler := NewGUIDHandler()

	// AD mixed-endian bytes for GUID: 12345678-1234-1234-1234-123456789012
	adBytes := []byte{
		0x78, 0x56, 0x34, 0x12, // Data1: little-endian
		0x34, 0x12, // Data2: little-endian
		0x34, 0x12, // Data3: little-endian
		0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, // Data4: big-endian
	}

	tests := []struct {
		name     string
		input    []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "valid AD bytes",
			input:    adBytes,
			expected: "12345678-1234-1234-1234-123456789012",
			wantErr:  false,
		},
		{
			name:    "invalid length - too short",
			input:   []byte{0x78, 0x56, 0x34, 0x12},
			wantErr: true,
		},
		{
			name:    "invalid length - too long",
			input:   append(adBytes, 0x00),
			wantErr: true,
		},
		{
			name:    "nil bytes",
			input:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.GUIDBytesToString(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGUIDHandler_RoundTrip(t *testing.T) {
	handler := NewGUIDHandler()

	testGUIDs := []string{
		"12345678-1234-1234-1234-123456789012",
		"abcdef00-1111-2222-3333-444455556666",
		"00000000-0000-0000-0000-000000000001",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
	}

	for _, originalGUID := range testGUIDs {
		t.Run("roundtrip_"+originalGUID, func(t *testing.T) {
			// Convert to bytes
			guidBytes, err := handler.StringToGUIDBytes(originalGUID)
			require.NoError(t, err)

			// Convert back to string
			resultGUID, err := handler.GUIDBytesToString(guidBytes)
			require.NoError(t, err)

			// Should match original
			assert.Equal(t, originalGUID, resultGUID)
		})
	}
}

func TestGUIDHandler_GUIDToSearchFilter(t *testing.T) {
	handler := NewGUIDHandler()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid GUID",
			input:   "12345678-1234-1234-1234-123456789012",
			wantErr: false,
		},
		{
			name:    "valid compact GUID",
			input:   "12345678123412341234123456789012",
			wantErr: false,
		},
		{
			name:    "invalid GUID",
			input:   "invalid-guid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.GUIDToSearchFilter(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Contains(t, result, "(objectGUID=")
			assert.Contains(t, result, ")")
		})
	}
}

func TestGUIDHandler_ExtractGUID(t *testing.T) {
	handler := NewGUIDHandler()

	// Create mock LDAP entry with objectGUID
	adBytes := []byte{
		0x78, 0x56, 0x34, 0x12, // Data1: little-endian
		0x34, 0x12, // Data2: little-endian
		0x34, 0x12, // Data3: little-endian
		0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, // Data4: big-endian
	}

	tests := []struct {
		name     string
		entry    *ldap.Entry
		expected string
		wantErr  bool
	}{
		{
			name: "valid entry with objectGUID",
			entry: &ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					{
						Name:       "objectGUID",
						ByteValues: [][]byte{adBytes},
					},
				},
			},
			expected: "12345678-1234-1234-1234-123456789012",
			wantErr:  false,
		},
		{
			name:    "nil entry",
			entry:   nil,
			wantErr: true,
		},
		{
			name: "entry without objectGUID",
			entry: &ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   "cn",
						Values: []string{"test"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "entry with empty objectGUID",
			entry: &ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					{
						Name:       "objectGUID",
						ByteValues: [][]byte{{}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "entry with invalid objectGUID length",
			entry: &ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					{
						Name:       "objectGUID",
						ByteValues: [][]byte{{0x12, 0x34}}, // Too short
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.ExtractGUID(tt.entry)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGUIDHandler_ExtractGUIDSafe(t *testing.T) {
	handler := NewGUIDHandler()

	// Create mock LDAP entry with objectGUID
	adBytes := []byte{
		0x78, 0x56, 0x34, 0x12, // Data1: little-endian
		0x34, 0x12, // Data2: little-endian
		0x34, 0x12, // Data3: little-endian
		0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, // Data4: big-endian
	}

	tests := []struct {
		name     string
		entry    *ldap.Entry
		expected string
	}{
		{
			name: "valid entry with objectGUID",
			entry: &ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					{
						Name:       "objectGUID",
						ByteValues: [][]byte{adBytes},
					},
				},
			},
			expected: "12345678-1234-1234-1234-123456789012",
		},
		{
			name:     "nil entry",
			entry:    nil,
			expected: "",
		},
		{
			name: "entry without objectGUID",
			entry: &ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   "cn",
						Values: []string{"test"},
					},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.ExtractGUIDSafe(tt.entry)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGUIDHandler_GenerateGUIDSearchRequest(t *testing.T) {
	handler := NewGUIDHandler()

	tests := []struct {
		name    string
		baseDN  string
		guid    string
		wantErr bool
	}{
		{
			name:    "valid parameters",
			baseDN:  "dc=example,dc=com",
			guid:    "12345678-1234-1234-1234-123456789012",
			wantErr: false,
		},
		{
			name:    "invalid GUID",
			baseDN:  "dc=example,dc=com",
			guid:    "invalid-guid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.GenerateGUIDSearchRequest(tt.baseDN, tt.guid)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.baseDN, result.BaseDN)
			assert.Equal(t, ScopeWholeSubtree, result.Scope)
			assert.Contains(t, result.Filter, "(objectGUID=")
			assert.Equal(t, 1, result.SizeLimit)
			assert.Contains(t, result.Attributes, "objectGUID")
			assert.Contains(t, result.Attributes, "distinguishedName")
			assert.Contains(t, result.Attributes, "objectClass")
		})
	}
}

func TestGUIDToAltDN(t *testing.T) {
	tests := []struct {
		name     string
		guid     string
		expected string
		wantErr  bool
	}{
		{
			name:     "hyphenated GUID",
			guid:     "12345678-1234-1234-1234-123456789012",
			expected: "<GUID=12345678-1234-1234-1234-123456789012>",
		},
		{
			name:     "compact GUID is normalized to hyphenated form",
			guid:     "12345678123412341234123456789012",
			expected: "<GUID=12345678-1234-1234-1234-123456789012>",
		},
		{
			name:     "mixed-case GUID is normalized to lowercase",
			guid:     "ABCDEF01-1234-1234-1234-123456789012",
			expected: "<GUID=abcdef01-1234-1234-1234-123456789012>",
		},
		{
			name:    "malformed GUID rejected",
			guid:    "not-a-guid",
			wantErr: true,
		},
		{
			name:    "empty GUID rejected",
			guid:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GUIDToAltDN(tt.guid)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, result)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsAltGUIDDN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "well-formed alternative DN",
			input:    "<GUID=12345678-1234-1234-1234-123456789012>",
			expected: true,
		},
		{
			name:     "malformed content still recognised as the shape",
			input:    "<GUID=not-a-guid>",
			expected: true,
		},
		{
			name:     "lowercase guid keyword",
			input:    "<guid=12345678-1234-1234-1234-123456789012>",
			expected: true,
		},
		{
			name:     "padded with whitespace",
			input:    "  <GUID=12345678-1234-1234-1234-123456789012>  ",
			expected: true,
		},
		{
			name:     "plain DN",
			input:    "CN=User,OU=Users,DC=example,DC=com",
			expected: false,
		},
		{
			name:     "missing closing bracket",
			input:    "<GUID=12345678-1234-1234-1234-123456789012",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsAltGUIDDN(tt.input))
		})
	}
}

func TestGUIDToAltDN_IsAltGUIDDN_RoundTrip(t *testing.T) {
	guid := "12345678-1234-1234-1234-123456789012"

	altDN, err := GUIDToAltDN(guid)
	require.NoError(t, err)

	assert.True(t, IsAltGUIDDN(altDN))
	assert.False(t, IsAltGUIDDN(guid), "the bare GUID itself is not the alternative-DN shape")
}

// Benchmark tests for performance validation.
func BenchmarkGUIDHandler_StringToGUIDBytes(b *testing.B) {
	handler := NewGUIDHandler()
	guid := "12345678-1234-1234-1234-123456789012"

	for b.Loop() {
		_, err := handler.StringToGUIDBytes(guid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGUIDHandler_GUIDBytesToString(b *testing.B) {
	handler := NewGUIDHandler()
	guidBytes := []byte{
		0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12,
		0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12,
	}

	for b.Loop() {
		_, err := handler.GUIDBytesToString(guidBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGUIDHandler_NormalizeGUID(b *testing.B) {
	handler := NewGUIDHandler()
	guid := "12345678123412341234123456789012" // Compact format

	for b.Loop() {
		_, err := handler.NormalizeGUID(guid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Test for Active Directory specific GUID byte encoding accuracy.
func TestActiveDirectoryGUIDEncoding(t *testing.T) {
	handler := NewGUIDHandler()

	// Test with a real Active Directory GUID scenario
	// GUID: 01234567-89ab-cdef-0123-456789abcdef
	guidString := "01234567-89ab-cdef-0123-456789abcdef"

	// Expected AD bytes (mixed-endian format)
	expectedADBytes := []byte{
		0x67, 0x45, 0x23, 0x01, // Data1: little-endian (01234567 -> 67452301)
		0xab, 0x89, // Data2: little-endian (89ab -> ab89)
		0xef, 0xcd, // Data3: little-endian (cdef -> efcd)
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, // Data4: big-endian (unchanged)
	}

	// Convert string to AD bytes
	adBytes, err := handler.StringToGUIDBytes(guidString)
	require.NoError(t, err)
	assert.Equal(t, expectedADBytes, adBytes)

	// Convert AD bytes back to string
	resultString, err := handler.GUIDBytesToString(adBytes)
	require.NoError(t, err)
	assert.Equal(t, guidString, resultString)
}
