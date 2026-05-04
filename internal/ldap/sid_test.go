package ldap

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeSID(t *testing.T) {
	tests := []struct {
		name    string
		hex     string
		want    string
		wantErr bool
	}{
		{
			name: "local system S-1-5-18",
			hex:  "010100000000000512000000",
			want: "S-1-5-18",
		},
		{
			name: "everyone S-1-1-0",
			hex:  "010100000000000100000000",
			want: "S-1-1-0",
		},
		{
			name: "builtin administrators S-1-5-32-544",
			hex:  "01020000000000052000000020020000",
			want: "S-1-5-32-544",
		},
		{
			name:    "empty",
			hex:     "",
			wantErr: true,
		},
		{
			name:    "too short",
			hex:     "0105",
			wantErr: true,
		},
		{
			name:    "truncated sub-authorities",
			hex:     "01050000000000050000000000000000",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := hex.DecodeString(tt.hex)
			require.NoError(t, err)

			sid, err := DecodeSID(b)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.want != "" {
				assert.Equal(t, tt.want, sid.String())
			}
		})
	}
}

func TestParseSID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "local system", input: "S-1-5-18"},
		{name: "everyone", input: "S-1-1-0"},
		{name: "domain user", input: "S-1-5-21-123456789-987654321-111222333-1001"},
		{name: "no sub-authorities", input: "S-1-5"},
		{name: "empty", input: "", wantErr: true},
		{name: "no S prefix", input: "1-5-21", wantErr: true},
		{name: "bad revision", input: "S-abc-5-21", wantErr: true},
		{name: "bad authority", input: "S-1-abc-21", wantErr: true},
		{name: "bad sub-authority", input: "S-1-5-abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sid, err := ParseSID(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.input, sid.String())
		})
	}
}

func TestSID_RoundTrip_Bytes(t *testing.T) {
	sids := []string{
		"S-1-5-18",
		"S-1-1-0",
		"S-1-5-21-123456789-987654321-111222333-1001",
		"S-1-5-32-544",
		"S-1-5",
	}

	for _, s := range sids {
		t.Run(s, func(t *testing.T) {
			sid, err := ParseSID(s)
			require.NoError(t, err)

			b, err := sid.Bytes()
			require.NoError(t, err)

			decoded, err := DecodeSID(b)
			require.NoError(t, err)

			assert.Equal(t, sid, decoded)
			assert.Equal(t, s, decoded.String())
		})
	}
}

func TestSID_Bytes_AuthorityOutOfRange(t *testing.T) {
	sid := SID{RevisionLevel: 1, Authority: 1 << 48}
	_, err := sid.Bytes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds 48-bit maximum")
}

func TestSID_Bytes_AuthorityMax(t *testing.T) {
	sid := SID{RevisionLevel: 1, Authority: 1<<48 - 1}
	b, err := sid.Bytes()
	require.NoError(t, err)
	require.Len(t, b, 8)
	decoded, err := DecodeSID(b)
	require.NoError(t, err)
	assert.Equal(t, sid.RevisionLevel, decoded.RevisionLevel)
	assert.Equal(t, sid.Authority, decoded.Authority)
	assert.Empty(t, decoded.SubAuthorities)
}

func TestSID_RoundTrip_String(t *testing.T) {
	// Known binary SID for S-1-5-18 (Local System).
	b, err := hex.DecodeString("010100000000000512000000")
	require.NoError(t, err)

	sid, err := DecodeSID(b)
	require.NoError(t, err)
	assert.Equal(t, "S-1-5-18", sid.String())

	reencoded, err := sid.Bytes()
	require.NoError(t, err)
	assert.Equal(t, b, reencoded)
}

func TestSID_RID(t *testing.T) {
	sid, err := ParseSID("S-1-5-21-123456789-987654321-111222333-1001")
	require.NoError(t, err)
	assert.Equal(t, uint32(1001), sid.RID())
}

func TestSID_RID_Empty(t *testing.T) {
	sid := SID{RevisionLevel: 1, Authority: 5}
	assert.Equal(t, uint32(0), sid.RID())
}

func TestSIDHandler_SIDToSearchFilter(t *testing.T) {
	h := NewSIDHandler()

	filter, err := h.SIDToSearchFilter("S-1-5-18")
	require.NoError(t, err)
	assert.Contains(t, filter, "(objectSid=")
	assert.True(t, len(filter) > len("(objectSid=)"))
}

func TestSIDHandler_SIDToSearchFilter_Invalid(t *testing.T) {
	h := NewSIDHandler()

	_, err := h.SIDToSearchFilter("invalid")
	assert.Error(t, err)
}

func TestSIDHandler_StringToSIDBytes(t *testing.T) {
	h := NewSIDHandler()

	b, err := h.StringToSIDBytes("S-1-5-18")
	require.NoError(t, err)

	// Verify by decoding back.
	sid, err := DecodeSID(b)
	require.NoError(t, err)
	assert.Equal(t, "S-1-5-18", sid.String())
}

func TestSIDHandler_ValidateSIDString(t *testing.T) {
	h := NewSIDHandler()

	assert.NoError(t, h.ValidateSIDString("S-1-5-21-123456789-987654321-111222333-1001"))
	assert.Error(t, h.ValidateSIDString(""))
	assert.Error(t, h.ValidateSIDString("not-a-sid"))
}

func TestSIDHandler_IsWellKnownSID(t *testing.T) {
	h := NewSIDHandler()

	assert.True(t, h.IsWellKnownSID("S-1-5-18"))
	assert.True(t, h.IsWellKnownSID("S-1-1-0"))
	assert.False(t, h.IsWellKnownSID("S-1-5-21-123456789-987654321-111222333-1001"))
}

func TestSIDHandler_ConvertBinarySIDToString(t *testing.T) {
	h := NewSIDHandler()

	_, err := h.ConvertBinarySIDToString(nil)
	assert.Error(t, err)

	_, err = h.ConvertBinarySIDToString([]byte{})
	assert.Error(t, err)
}

func TestSIDHandler_ConvertBinarySIDToStringSafe(t *testing.T) {
	h := NewSIDHandler()

	assert.Equal(t, "", h.ConvertBinarySIDToStringSafe(nil))
	assert.Equal(t, "", h.ConvertBinarySIDToStringSafe([]byte{}))
}
