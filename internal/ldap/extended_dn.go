package ldap

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ExtendedDN is a parsed Active Directory extended DN as returned for
// DN-syntax attribute values (e.g. member) when a search carries the
// LDAP_SERVER_EXTENDED_DN_OID control (MS-ADTS 3.1.1.3.4.1.5):
//
//	<GUID=guid_value>;<SID=sid_value>;dn
//	<GUID=guid_value>;dn                  (objects without objectSid)
type ExtendedDN struct {
	// GUID is the canonical lower-case dashed objectGUID, or "" when the
	// value carried no GUID component.
	GUID string
	// SID is the raw sid_value exactly as returned by the server (hex in
	// Flag 0 form, "S-..." in Flag 1 form), or "" when absent.
	SID string
	// DN is the object's RFC 2253 DN with the extended components removed.
	DN string
}

// NewExtendedDNControl returns the LDAP_SERVER_EXTENDED_DN_OID control with
// its controlValue omitted, which every AD version treats as Flag 0 (GUID and
// SID returned as hex of their binary form; see ExtendedDNGUIDToString).
//
// The control is marked critical: callers rely on the GUID components for
// correctness (identity-based membership comparison), so a server that does
// not implement it must fail the search (unavailableCriticalExtension)
// rather than silently return plain DNs.
func NewExtendedDNControl() ldap.Control {
	return ldap.NewControlString(ldap.ControlTypeMicrosoftExtendedDN, true, "")
}

// ParseExtendedDN parses a single extended-DN value. Values without any
// leading "<...>" components (plain DNs) are accepted and yield an
// ExtendedDN with only DN set, so callers can fall back to DN comparison.
// Unknown "<KEY=...>" components are ignored. An unterminated component, a
// malformed GUID, or an empty DN part is an error.
func ParseExtendedDN(value string) (*ExtendedDN, error) {
	rest := strings.TrimSpace(value)
	result := &ExtendedDN{}
	handler := NewGUIDHandler()

	for strings.HasPrefix(rest, "<") {
		end := strings.IndexByte(rest, '>')
		if end < 0 {
			return nil, fmt.Errorf("unterminated extended DN component in %q", value)
		}
		component := rest[1:end]
		rest = strings.TrimPrefix(rest[end+1:], ";")

		key, val, ok := strings.Cut(component, "=")
		if !ok {
			return nil, fmt.Errorf("malformed extended DN component %q in %q", component, value)
		}

		switch strings.ToUpper(strings.TrimSpace(key)) {
		case "GUID":
			guid, err := handler.ExtendedDNGUIDToString(val)
			if err != nil {
				return nil, fmt.Errorf("invalid GUID component in extended DN %q: %w", value, err)
			}
			result.GUID = guid
		case "SID":
			result.SID = strings.TrimSpace(val)
		}
	}

	result.DN = strings.TrimSpace(rest)
	if result.DN == "" {
		return nil, fmt.Errorf("extended DN %q has no DN part", value)
	}

	return result, nil
}

// PlainDN strips any leading "<TAG=value>;" extended components from an
// extended DN, returning a DN usable as a search base. Plain DNs, and values
// that do not parse, are returned unchanged.
func PlainDN(value string) string {
	if parsed, err := ParseExtendedDN(value); err == nil {
		return parsed.DN
	}
	return value
}
