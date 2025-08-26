package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeDNCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
			wantErr:  false,
		},
		{
			name:     "whitespace only",
			input:    "   ",
			expected: "",
			wantErr:  false,
		},
		{
			name:     "simple lowercase CN",
			input:    "cn=john",
			expected: "CN=john",
			wantErr:  false,
		},
		{
			name:     "simple uppercase CN (no change needed)",
			input:    "CN=john",
			expected: "CN=john",
			wantErr:  false,
		},
		{
			name:     "mixed case CN",
			input:    "Cn=john",
			expected: "CN=john",
			wantErr:  false,
		},
		{
			name:     "full DN with lowercase types",
			input:    "cn=john,ou=users,dc=example,dc=com",
			expected: "CN=john,OU=users,DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:     "full DN with mixed case types",
			input:    "Cn=john,Ou=users,Dc=example,Dc=com",
			expected: "CN=john,OU=users,DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:     "full DN already uppercase",
			input:    "CN=john,OU=users,DC=example,DC=com",
			expected: "CN=john,OU=users,DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:     "DN with spaces around equals",
			input:    "cn = john, ou = users, dc = example, dc = com",
			expected: "CN=john,OU=users,DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:     "DN with multi-valued RDN",
			input:    "cn=john+sn=doe,ou=users,dc=example,dc=com",
			expected: "CN=john+SN=doe,OU=users,DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:     "DN with special characters in value",
			input:    "cn=john\\, doe,ou=users,dc=example,dc=com",
			expected: "CN=john, doe,OU=users,DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:     "DN with numeric OID attribute type",
			input:    "2.5.4.3=john,ou=users,dc=example,dc=com",
			expected: "2.5.4.3=john,OU=users,DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:     "DN with Unicode value",
			input:    "cn=jöhn,ou=üsers,dc=example,dc=com",
			expected: "CN=jöhn,OU=üsers,DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:    "invalid DN syntax",
			input:   "invalid-dn",
			wantErr: true,
		},
		{
			name:    "DN with unescaped special character",
			input:   "cn=john,doe,ou=users,dc=example,dc=com",
			wantErr: true,
		},
		{
			name:     "DN with leading/trailing whitespace",
			input:    "  cn=john,ou=users,dc=example,dc=com  ",
			expected: "CN=john,OU=users,DC=example,DC=com",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeDNCase(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeDNCaseBatch(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
		wantErr  bool
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
			wantErr:  false,
		},
		{
			name:     "nil slice",
			input:    nil,
			expected: nil,
			wantErr:  false,
		},
		{
			name: "multiple valid DNs",
			input: []string{
				"cn=john,ou=users,dc=example,dc=com",
				"cn=jane,ou=admins,dc=example,dc=com",
				"ou=groups,dc=example,dc=com",
			},
			expected: []string{
				"CN=john,OU=users,DC=example,DC=com",
				"CN=jane,OU=admins,DC=example,DC=com",
				"OU=groups,DC=example,DC=com",
			},
			wantErr: false,
		},
		{
			name: "mixed valid and empty DNs",
			input: []string{
				"cn=john,ou=users,dc=example,dc=com",
				"",
				"cn=jane,ou=admins,dc=example,dc=com",
			},
			expected: []string{
				"CN=john,OU=users,DC=example,DC=com",
				"",
				"CN=jane,OU=admins,DC=example,DC=com",
			},
			wantErr: false,
		},
		{
			name: "invalid DN in batch",
			input: []string{
				"cn=john,ou=users,dc=example,dc=com",
				"invalid-dn",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeDNCaseBatch(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateDNSyntax(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "empty DN",
			input:   "",
			wantErr: true,
		},
		{
			name:    "valid simple DN",
			input:   "cn=john",
			wantErr: false,
		},
		{
			name:    "valid complex DN",
			input:   "cn=john,ou=users,dc=example,dc=com",
			wantErr: false,
		},
		{
			name:    "valid DN with multi-valued RDN",
			input:   "cn=john+sn=doe,ou=users,dc=example,dc=com",
			wantErr: false,
		},
		{
			name:    "invalid DN syntax",
			input:   "invalid-dn",
			wantErr: true,
		},
		{
			name:    "DN with unescaped comma",
			input:   "cn=john,doe,ou=users,dc=example,dc=com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDNSyntax(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractRDNValue(t *testing.T) {
	tests := []struct {
		name     string
		dn       string
		attrType string
		expected string
		wantErr  bool
	}{
		{
			name:     "extract CN from simple DN",
			dn:       "CN=john,OU=users,DC=example,DC=com",
			attrType: "CN",
			expected: "john",
			wantErr:  false,
		},
		{
			name:     "extract CN with lowercase search",
			dn:       "CN=john,OU=users,DC=example,DC=com",
			attrType: "cn",
			expected: "john",
			wantErr:  false,
		},
		{
			name:     "extract OU from DN",
			dn:       "CN=john,OU=users,DC=example,DC=com",
			attrType: "OU",
			expected: "users",
			wantErr:  false,
		},
		{
			name:     "extract DC from DN",
			dn:       "CN=john,OU=users,DC=example,DC=com",
			attrType: "DC",
			expected: "example",
			wantErr:  false,
		},
		{
			name:     "extract from multi-valued RDN",
			dn:       "CN=john+SN=doe,OU=users,DC=example,DC=com",
			attrType: "SN",
			expected: "doe",
			wantErr:  false,
		},
		{
			name:     "empty DN",
			dn:       "",
			attrType: "CN",
			wantErr:  true,
		},
		{
			name:     "invalid DN syntax",
			dn:       "invalid-dn",
			attrType: "CN",
			wantErr:  true,
		},
		{
			name:     "attribute not found",
			dn:       "CN=john,OU=users,DC=example,DC=com",
			attrType: "MAIL",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractRDNValue(tt.dn, tt.attrType)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetDNParent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple parent extraction",
			input:    "CN=john,OU=users,DC=example,DC=com",
			expected: "OU=users,DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:     "extract parent from OU",
			input:    "OU=users,DC=example,DC=com",
			expected: "DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:     "multi-valued RDN parent",
			input:    "CN=john+SN=doe,OU=users,DC=example,DC=com",
			expected: "OU=users,DC=example,DC=com",
			wantErr:  false,
		},
		{
			name:    "empty DN",
			input:   "",
			wantErr: true,
		},
		{
			name:    "single RDN (no parent)",
			input:   "DC=com",
			wantErr: true,
		},
		{
			name:    "invalid DN syntax",
			input:   "invalid-dn",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetDNParent(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsDNChild(t *testing.T) {
	tests := []struct {
		name     string
		childDN  string
		parentDN string
		expected bool
		wantErr  bool
	}{
		{
			name:     "direct child relationship",
			childDN:  "CN=john,OU=users,DC=example,DC=com",
			parentDN: "OU=users,DC=example,DC=com",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "indirect child relationship",
			childDN:  "CN=john,OU=users,DC=example,DC=com",
			parentDN: "DC=example,DC=com",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "case insensitive match",
			childDN:  "cn=john,ou=users,dc=example,dc=com",
			parentDN: "OU=USERS,DC=EXAMPLE,DC=COM",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "not a child relationship",
			childDN:  "CN=john,OU=admins,DC=example,DC=com",
			parentDN: "OU=users,DC=example,DC=com",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "same DN (not child)",
			childDN:  "OU=users,DC=example,DC=com",
			parentDN: "OU=users,DC=example,DC=com",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "child has fewer components (not child)",
			childDN:  "DC=example,DC=com",
			parentDN: "OU=users,DC=example,DC=com",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "empty child DN",
			childDN:  "",
			parentDN: "OU=users,DC=example,DC=com",
			wantErr:  true,
		},
		{
			name:     "empty parent DN",
			childDN:  "CN=john,OU=users,DC=example,DC=com",
			parentDN: "",
			wantErr:  true,
		},
		{
			name:     "invalid child DN syntax",
			childDN:  "invalid-dn",
			parentDN: "OU=users,DC=example,DC=com",
			wantErr:  true,
		},
		{
			name:     "invalid parent DN syntax",
			childDN:  "CN=john,OU=users,DC=example,DC=com",
			parentDN: "invalid-dn",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := IsDNChild(tt.childDN, tt.parentDN)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReconstructDNWithUppercaseTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple DN reconstruction",
			input:    "cn=john,ou=users,dc=example,dc=com",
			expected: "CN=john,OU=users,DC=example,DC=com",
		},
		{
			name:     "multi-valued RDN reconstruction",
			input:    "cn=john+sn=doe,ou=users,dc=example,dc=com",
			expected: "CN=john+SN=doe,OU=users,DC=example,DC=com",
		},
		{
			name:     "already uppercase",
			input:    "CN=john,OU=users,DC=example,DC=com",
			expected: "CN=john,OU=users,DC=example,DC=com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the input DN first
			parsedDN, err := ldap.ParseDN(tt.input)
			require.NoError(t, err)

			result := reconstructDNWithUppercaseTypes(parsedDN)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Benchmark tests for performance validation.
func BenchmarkNormalizeDNCase(b *testing.B) {
	testDN := "cn=john doe,ou=test users,dc=example,dc=com"

	for b.Loop() {
		_, err := NormalizeDNCase(testDN)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNormalizeDNCaseBatch(b *testing.B) {
	testDNs := []string{
		"cn=john doe,ou=test users,dc=example,dc=com",
		"cn=jane smith,ou=test admins,dc=example,dc=com",
		"ou=test groups,dc=example,dc=com",
		"cn=service account,ou=service accounts,dc=example,dc=com",
	}

	for b.Loop() {
		_, err := NormalizeDNCaseBatch(testDNs)
		if err != nil {
			b.Fatal(err)
		}
	}
}
