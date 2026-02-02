package ldap

import (
	"encoding/binary"
	"unicode/utf16"
)

// EncodeADPassword encodes a password for Active Directory's unicodePwd attribute.
// Active Directory requires passwords to be:
// 1. Enclosed in double quotes
// 2. Encoded as UTF-16LE (Little Endian)
//
// This function handles the encoding automatically.
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
