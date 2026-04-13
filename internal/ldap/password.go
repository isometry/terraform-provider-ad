package ldap

import (
	"encoding/binary"
	"unicode/utf16"
)

// EncodeADPassword encodes a password for Active Directory's unicodePwd attribute.
// Per MS-ADTS, Active Directory requires passwords to be:
// 1. Enclosed in double quotes
// 2. Encoded as UTF-16LE (Little Endian)
// Ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2
func EncodeADPassword(password string) []byte {
	// Wrap password in double quotes as required by AD
	quotedPassword := "\"" + password + "\""

	// Convert to UTF-16 code points
	utf16Codes := utf16.Encode([]rune(quotedPassword))

	// Convert UTF-16 to Little Endian bytes
	result := make([]byte, len(utf16Codes)*2)
	for i, code := range utf16Codes {
		binary.LittleEndian.PutUint16(result[i*2:], code)
	}

	return result
}
