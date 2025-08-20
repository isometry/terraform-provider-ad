package ldap

import (
	"testing"
)

func TestConnectionConfig_GetAuthMethod(t *testing.T) {
	tests := []struct {
		name     string
		config   *ConnectionConfig
		expected AuthMethod
	}{
		{
			name: "simple bind with username and password",
			config: &ConnectionConfig{
				Username: "testuser",
				Password: "testpass",
			},
			expected: AuthMethodSimpleBind,
		},
		{
			name: "kerberos with realm and keytab",
			config: &ConnectionConfig{
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/path/to/keytab",
			},
			expected: AuthMethodKerberos,
		},
		{
			name: "kerberos with realm and username (password auth)",
			config: &ConnectionConfig{
				Username:      "testuser",
				Password:      "testpass",
				KerberosRealm: "EXAMPLE.COM",
			},
			expected: AuthMethodKerberos, // Kerberos takes precedence
		},
		{
			name: "external auth with client certificates",
			config: &ConnectionConfig{
				TLSClientCertFile: "/path/to/cert.pem",
				TLSClientKeyFile:  "/path/to/key.pem",
			},
			expected: AuthMethodExternal,
		},
		{
			name: "username only defaults to simple bind",
			config: &ConnectionConfig{
				Username: "testuser",
			},
			expected: AuthMethodSimpleBind,
		},
		{
			name:     "empty config defaults to simple bind",
			config:   &ConnectionConfig{},
			expected: AuthMethodSimpleBind,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetAuthMethod()
			if result != tt.expected {
				t.Errorf("GetAuthMethod() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestConnectionConfig_HasAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		config   *ConnectionConfig
		expected bool
	}{
		{
			name: "has password authentication",
			config: &ConnectionConfig{
				Username: "testuser",
				Password: "testpass",
			},
			expected: true,
		},
		{
			name: "has kerberos authentication with keytab",
			config: &ConnectionConfig{
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/path/to/keytab",
			},
			expected: true,
		},
		{
			name: "has kerberos authentication with username",
			config: &ConnectionConfig{
				Username:      "testuser",
				KerberosRealm: "EXAMPLE.COM",
			},
			expected: true,
		},
		{
			name: "has external authentication",
			config: &ConnectionConfig{
				TLSClientCertFile: "/path/to/cert.pem",
				TLSClientKeyFile:  "/path/to/key.pem",
			},
			expected: true,
		},
		{
			name: "username without password",
			config: &ConnectionConfig{
				Username: "testuser",
			},
			expected: false,
		},
		{
			name: "realm without keytab or username",
			config: &ConnectionConfig{
				KerberosRealm: "EXAMPLE.COM",
			},
			expected: false,
		},
		{
			name:     "empty config",
			config:   &ConnectionConfig{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.HasAuthentication()
			if result != tt.expected {
				t.Errorf("HasAuthentication() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestAuthMethod_String(t *testing.T) {
	tests := []struct {
		method   AuthMethod
		expected string
	}{
		{AuthMethodSimpleBind, "simple"},
		{AuthMethodKerberos, "kerberos"},
		{AuthMethodExternal, "external"},
		{AuthMethod(999), "unknown"}, // Invalid method
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.method.String()
			if result != tt.expected {
				t.Errorf("String() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
