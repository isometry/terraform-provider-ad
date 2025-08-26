package ldap

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// NormalizeDNCase normalizes the attribute type descriptors in a Distinguished Name
// to uppercase to match Active Directory's canonical format.
//
// Input:  "cn=john,ou=users,dc=example,dc=com"
// Output: "CN=john,OU=users,DC=example,DC=com"
//
// This function:
// 1. Parses the DN using go-ldap/ldap library for RFC 4514 compliance
// 2. Reconstructs the DN with uppercase attribute type descriptors
// 3. Preserves all other aspects of the DN (spacing, value case, etc.)
func NormalizeDNCase(dn string) (string, error) {
	if dn == "" {
		return "", nil
	}

	// Trim whitespace
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return "", nil
	}

	// Parse DN using go-ldap library for proper RFC 4514 handling
	parsedDN, err := ldap.ParseDN(dn)
	if err != nil {
		return "", fmt.Errorf("invalid DN syntax: %w", err)
	}

	// Reconstruct DN with uppercase attribute types
	return reconstructDNWithUppercaseTypes(parsedDN), nil
}

// reconstructDNWithUppercaseTypes rebuilds a DN from parsed components
// with attribute type descriptors in uppercase.
func reconstructDNWithUppercaseTypes(parsedDN *ldap.DN) string {
	var rdnStrings []string

	for _, rdn := range parsedDN.RDNs {
		var attrStrings []string

		for _, attr := range rdn.Attributes {
			// Convert attribute type to uppercase, keep value as-is
			attrType := strings.ToUpper(attr.Type)

			// The go-ldap library handles proper DN value escaping in ParseDN/String()
			attrString := fmt.Sprintf("%s=%s", attrType, attr.Value)
			attrStrings = append(attrStrings, attrString)
		}

		// Join multiple attributes in the same RDN with "+"
		rdnString := strings.Join(attrStrings, "+")
		rdnStrings = append(rdnStrings, rdnString)
	}

	// Join RDNs with ","
	return strings.Join(rdnStrings, ",")
}

// NormalizeDNCaseBatch normalizes the case of multiple DNs in a single operation.
func NormalizeDNCaseBatch(dns []string) ([]string, error) {
	if len(dns) == 0 {
		return dns, nil
	}

	normalizedDNs := make([]string, len(dns))
	for i, dn := range dns {
		normalizedDN, err := NormalizeDNCase(dn)
		if err != nil {
			return nil, fmt.Errorf("failed to normalize DN '%s': %w", dn, err)
		}
		normalizedDNs[i] = normalizedDN
	}

	return normalizedDNs, nil
}

// ValidateDNSyntax validates that a string is a properly formatted Distinguished Name.
func ValidateDNSyntax(dn string) error {
	if dn == "" {
		return fmt.Errorf("DN cannot be empty")
	}

	_, err := ldap.ParseDN(dn)
	if err != nil {
		return fmt.Errorf("invalid DN syntax: %w", err)
	}

	return nil
}

// ExtractRDNValue extracts the value of the first RDN component with the specified attribute type.
// For example, extracting "CN" from "CN=John Doe,OU=Users,DC=example,DC=com" returns "John Doe".
func ExtractRDNValue(dn, attrType string) (string, error) {
	if dn == "" {
		return "", fmt.Errorf("DN cannot be empty")
	}

	parsedDN, err := ldap.ParseDN(dn)
	if err != nil {
		return "", fmt.Errorf("invalid DN syntax: %w", err)
	}

	// Normalize the search attribute type to uppercase for comparison
	normalizedAttrType := strings.ToUpper(attrType)

	// Search through RDNs for the first matching attribute type
	for _, rdn := range parsedDN.RDNs {
		for _, attr := range rdn.Attributes {
			if strings.ToUpper(attr.Type) == normalizedAttrType {
				return attr.Value, nil
			}
		}
	}

	return "", fmt.Errorf("attribute type '%s' not found in DN '%s'", attrType, dn)
}

// GetDNParent returns the parent DN by removing the first RDN component.
// For example, "CN=John,OU=Users,DC=example,DC=com" becomes "OU=Users,DC=example,DC=com".
func GetDNParent(dn string) (string, error) {
	if dn == "" {
		return "", fmt.Errorf("DN cannot be empty")
	}

	parsedDN, err := ldap.ParseDN(dn)
	if err != nil {
		return "", fmt.Errorf("invalid DN syntax: %w", err)
	}

	if len(parsedDN.RDNs) <= 1 {
		return "", fmt.Errorf("DN has no parent: %s", dn)
	}

	// Create new DN with parent RDNs (skip first RDN)
	parentDN := &ldap.DN{
		RDNs: parsedDN.RDNs[1:],
	}

	return reconstructDNWithUppercaseTypes(parentDN), nil
}

// IsDNChild checks if childDN is a direct or indirect child of parentDN.
func IsDNChild(childDN, parentDN string) (bool, error) {
	if childDN == "" || parentDN == "" {
		return false, fmt.Errorf("DNs cannot be empty")
	}

	parsedChild, err := ldap.ParseDN(childDN)
	if err != nil {
		return false, fmt.Errorf("invalid child DN syntax: %w", err)
	}

	parsedParent, err := ldap.ParseDN(parentDN)
	if err != nil {
		return false, fmt.Errorf("invalid parent DN syntax: %w", err)
	}

	// Child must have more RDN components than parent
	if len(parsedChild.RDNs) <= len(parsedParent.RDNs) {
		return false, nil
	}

	// Extract the parent portion of the child DN
	childParentRDNs := parsedChild.RDNs[len(parsedChild.RDNs)-len(parsedParent.RDNs):]
	childParentDN := &ldap.DN{RDNs: childParentRDNs}

	// Compare normalized DN strings (case-insensitive)
	childParentNormalized := strings.ToLower(reconstructDNWithUppercaseTypes(childParentDN))
	parentNormalized := strings.ToLower(reconstructDNWithUppercaseTypes(parsedParent))

	return childParentNormalized == parentNormalized, nil
}
