package ldap

import (
	"strings"
)

// EscapeDNValue escapes special characters in a DN attribute value according to RFC 4514.
//
// RFC 4514 defines the following escaping rules for DN attribute values:
// - Special characters that must be escaped: , + " \ < > ;
// - Leading # must be escaped
// - Leading and trailing spaces must be escaped
// - NULL bytes must be escaped as \00
//
// Examples:
//   - "John Doe" → "John Doe" (no change)
//   - "Doe, John" → "Doe\, John" (comma escaped)
//   - " John " → "\ John\ " (leading/trailing spaces escaped)
//   - "#123" → "\#123" (leading # escaped)
//   - "John<>Doe" → "John\<\>Doe" (angle brackets escaped)
func EscapeDNValue(value string) string {
	if value == "" {
		return value
	}

	var result strings.Builder
	result.Grow(len(value) + 10) // Pre-allocate with buffer for escape characters

	for i, r := range value {
		switch r {
		case ',', '+', '"', '\\', '<', '>', ';':
			// Special characters that must always be escaped
			result.WriteRune('\\')
			result.WriteRune(r)
		case '#':
			// Leading # must be escaped
			if i == 0 {
				result.WriteRune('\\')
			}
			result.WriteRune(r)
		case ' ':
			// Leading and trailing spaces must be escaped
			if i == 0 || i == len(value)-1 {
				result.WriteRune('\\')
			}
			result.WriteRune(r)
		case 0:
			// NULL byte must be escaped as \00
			result.WriteString("\\00")
		default:
			result.WriteRune(r)
		}
	}

	return result.String()
}

// UnescapeDNValue removes escaping from a DN attribute value according to RFC 4514.
//
// This is the inverse operation of EscapeDNValue. It removes escape sequences
// to restore the original value.
//
// Examples:
//   - "Doe\, John" → "Doe, John"
//   - "\ John\ " → " John "
//   - "\#123" → "#123"
//   - "John\<\>Doe" → "John<>Doe"
func UnescapeDNValue(value string) string {
	if value == "" || !strings.Contains(value, "\\") {
		return value
	}

	var result strings.Builder
	result.Grow(len(value)) // Pre-allocate

	escaped := false
	hexBuffer := make([]rune, 0, 2)

	for i, r := range value {
		if escaped {
			// Handle hex escapes like \00
			if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
				hexBuffer = append(hexBuffer, r)
				if len(hexBuffer) == 2 {
					// Convert hex to character
					var hexValue int
					for _, h := range hexBuffer {
						hexValue = hexValue * 16
						if h >= '0' && h <= '9' {
							hexValue += int(h - '0')
						} else if h >= 'a' && h <= 'f' {
							hexValue += int(h - 'a' + 10)
						} else if h >= 'A' && h <= 'F' {
							hexValue += int(h - 'A' + 10)
						}
					}
					result.WriteRune(rune(hexValue))
					hexBuffer = hexBuffer[:0]
					escaped = false
				}
				continue
			}

			// If we had started hex but got non-hex char, write the backslash and hex chars
			if len(hexBuffer) > 0 {
				result.WriteRune('\\')
				for _, h := range hexBuffer {
					result.WriteRune(h)
				}
				hexBuffer = hexBuffer[:0]
			}

			// Regular escaped character
			result.WriteRune(r)
			escaped = false
		} else if r == '\\' {
			// Start of escape sequence
			// Check if this is the last character (invalid escape)
			if i == len(value)-1 {
				result.WriteRune(r) // Keep the backslash
			} else {
				escaped = true
			}
		} else {
			result.WriteRune(r)
		}
	}

	// Handle incomplete escape sequence at end
	if escaped {
		result.WriteRune('\\')
	}
	if len(hexBuffer) > 0 {
		result.WriteRune('\\')
		for _, h := range hexBuffer {
			result.WriteRune(h)
		}
	}

	return result.String()
}

// NeedsDNEscaping checks if a value contains characters that need DN escaping.
// This is useful for optimization - if no escaping is needed, the original value can be used.
func NeedsDNEscaping(value string) bool {
	if value == "" {
		return false
	}

	// Check for leading/trailing spaces
	if value[0] == ' ' || value[len(value)-1] == ' ' {
		return true
	}

	// Check for leading #
	if value[0] == '#' {
		return true
	}

	// Check for special characters
	for _, r := range value {
		switch r {
		case ',', '+', '"', '\\', '<', '>', ';', 0:
			return true
		}
	}

	return false
}
