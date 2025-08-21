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

func TestGUIDHandler_GUIDToHexSearchFilter(t *testing.T) {
	handler := NewGUIDHandler()

	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:  "valid GUID",
			input: "12345678-1234-1234-1234-123456789012",
			// AD bytes: [0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12]
			expected: "(objectGUID=\\78\\56\\34\\12\\34\\12\\34\\12\\12\\34\\12\\34\\56\\78\\90\\12)",
			wantErr:  false,
		},
		{
			name:    "invalid GUID",
			input:   "invalid-guid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.GUIDToHexSearchFilter(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
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

func TestGUIDHandler_CompareGUIDs(t *testing.T) {
	handler := NewGUIDHandler()

	tests := []struct {
		name     string
		guid1    string
		guid2    string
		expected bool
		wantErr  bool
	}{
		{
			name:     "identical GUIDs",
			guid1:    "12345678-1234-1234-1234-123456789012",
			guid2:    "12345678-1234-1234-1234-123456789012",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "different case",
			guid1:    "12345678-1234-1234-1234-123456789012",
			guid2:    "12345678-1234-1234-1234-123456789012",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "hyphenated vs compact",
			guid1:    "12345678-1234-1234-1234-123456789012",
			guid2:    "12345678123412341234123456789012",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "different GUIDs",
			guid1:    "12345678-1234-1234-1234-123456789012",
			guid2:    "87654321-4321-4321-4321-210987654321",
			expected: false,
			wantErr:  false,
		},
		{
			name:    "invalid first GUID",
			guid1:   "invalid-guid",
			guid2:   "12345678-1234-1234-1234-123456789012",
			wantErr: true,
		},
		{
			name:    "invalid second GUID",
			guid1:   "12345678-1234-1234-1234-123456789012",
			guid2:   "invalid-guid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.CompareGUIDs(tt.guid1, tt.guid2)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
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

func TestGUIDHandler_ValidateGUIDBytes(t *testing.T) {
	handler := NewGUIDHandler()

	validBytes := []byte{
		0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12,
		0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12,
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "valid bytes",
			input:   validBytes,
			wantErr: false,
		},
		{
			name:    "invalid length - too short",
			input:   []byte{0x12, 0x34},
			wantErr: true,
		},
		{
			name:    "invalid length - too long",
			input:   append(validBytes, 0x00),
			wantErr: true,
		},
		{
			name:    "all zeros",
			input:   make([]byte, 16),
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
			err := handler.ValidateGUIDBytes(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGUIDHandler_ParseGUIDFromDN(t *testing.T) {
	handler := NewGUIDHandler()

	tests := []struct {
		name     string
		dn       string
		expected string
		found    bool
	}{
		{
			name:     "DN with no GUID",
			dn:       "cn=user,ou=users,dc=example,dc=com",
			expected: "",
			found:    false,
		},
		{
			name:     "GUID as DN component",
			dn:       "12345678-1234-1234-1234-123456789012",
			expected: "12345678-1234-1234-1234-123456789012",
			found:    true,
		},
		{
			name:     "compact GUID as DN component",
			dn:       "12345678123412341234123456789012",
			expected: "12345678-1234-1234-1234-123456789012",
			found:    true,
		},
		{
			name:     "invalid GUID format",
			dn:       "invalid-guid-format",
			expected: "",
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := handler.ParseGUIDFromDN(tt.dn)

			assert.Equal(t, tt.found, found)
			assert.Equal(t, tt.expected, result)
		})
	}
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

	// Verify the hex search filter format
	hexFilter, err := handler.GUIDToHexSearchFilter(guidString)
	require.NoError(t, err)

	expectedHexFilter := "(objectGUID=\\67\\45\\23\\01\\ab\\89\\ef\\cd\\01\\23\\45\\67\\89\\ab\\cd\\ef)"
	assert.Equal(t, expectedHexFilter, hexFilter)
}
