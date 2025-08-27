package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareKerberosConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *ConnectionConfig
		expectError bool
		errorMsg    string
		expected    *ConnectionConfig
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
			errorMsg:    "configuration cannot be nil",
		},
		{
			name: "valid keytab config",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/path/to/test.keytab",
			},
			expectError: false,
			expected: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/path/to/test.keytab",
				KerberosConfig: "/etc/krb5.conf", // Should be set to default
			},
		},
		{
			name: "valid password config",
			config: &ConnectionConfig{
				Username:      "testuser",
				Password:      "testpass",
				KerberosRealm: "EXAMPLE.COM",
			},
			expectError: false,
			expected: &ConnectionConfig{
				Username:       "testuser",
				Password:       "testpass",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosConfig: "/etc/krb5.conf", // Should be set to default
			},
		},
		{
			name: "extract realm from username",
			config: &ConnectionConfig{
				Username:       "testuser@EXAMPLE.COM",
				KerberosKeytab: "/path/to/test.keytab",
			},
			expectError: false,
			expected: &ConnectionConfig{
				Username:       "testuser",    // Should be extracted
				KerberosRealm:  "EXAMPLE.COM", // Should be extracted
				KerberosKeytab: "/path/to/test.keytab",
				KerberosConfig: "/etc/krb5.conf",
			},
		},
		{
			name: "custom krb5.conf path",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/path/to/test.keytab",
				KerberosConfig: "/custom/krb5.conf",
			},
			expectError: false,
			expected: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/path/to/test.keytab",
				KerberosConfig: "/custom/krb5.conf", // Should preserve custom path
			},
		},
		{
			name: "missing realm",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosKeytab: "/path/to/test.keytab",
			},
			expectError: true,
			errorMsg:    "kerberos realm is required",
		},
		{
			name: "missing username",
			config: &ConnectionConfig{
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/path/to/test.keytab",
			},
			expectError: true,
			errorMsg:    "username (principal) is required",
		},
		{
			name: "missing credentials",
			config: &ConnectionConfig{
				Username:      "testuser",
				KerberosRealm: "EXAMPLE.COM",
			},
			expectError: true,
			errorMsg:    "either keytab (kerberos_keytab) or password is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := prepareKerberosConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				if tt.expected != nil {
					assert.Equal(t, tt.expected.Username, tt.config.Username)
					assert.Equal(t, tt.expected.KerberosRealm, tt.config.KerberosRealm)
					assert.Equal(t, tt.expected.KerberosConfig, tt.config.KerberosConfig)
				}
			}
		})
	}
}

func TestBuildServicePrincipal(t *testing.T) {
	tests := []struct {
		name        string
		serverInfo  *ServerInfo
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil server info",
			serverInfo:  nil,
			expectError: true,
			errorMsg:    "server info is required",
		},
		{
			name: "empty hostname",
			serverInfo: &ServerInfo{
				Host: "",
				Port: 636,
			},
			expectError: true,
			errorMsg:    "hostname is required",
		},
		{
			name: "simple hostname",
			serverInfo: &ServerInfo{
				Host: "dc1.example.com",
				Port: 636,
			},
			expected:    "ldap/dc1.example.com",
			expectError: false,
		},
		{
			name: "hostname with port",
			serverInfo: &ServerInfo{
				Host: "dc1.example.com:636",
				Port: 636,
			},
			expected:    "ldap/dc1.example.com", // Port should be stripped
			expectError: false,
		},
		{
			name: "IP address",
			serverInfo: &ServerInfo{
				Host: "192.168.1.100",
				Port: 389,
			},
			expected:    "ldap/192.168.1.100",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildServicePrincipal(tt.serverInfo)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestExtractHostFromURL(t *testing.T) {
	tests := []struct {
		name        string
		ldapURL     string
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty URL",
			ldapURL:     "",
			expectError: true,
			errorMsg:    "LDAP URL cannot be empty",
		},
		{
			name:        "invalid URL",
			ldapURL:     "not-a-url",
			expectError: true,
			errorMsg:    "no hostname found in URL",
		},
		{
			name:     "ldap URL",
			ldapURL:  "ldap://dc1.example.com:389",
			expected: "dc1.example.com",
		},
		{
			name:     "ldaps URL",
			ldapURL:  "ldaps://dc1.example.com:636",
			expected: "dc1.example.com",
		},
		{
			name:     "URL without port",
			ldapURL:  "ldap://dc1.example.com",
			expected: "dc1.example.com",
		},
		{
			name:     "URL with IP",
			ldapURL:  "ldaps://192.168.1.100:636",
			expected: "192.168.1.100",
		},
		{
			name:        "URL without hostname",
			ldapURL:     "ldap://:389",
			expectError: true,
			errorMsg:    "no hostname found in URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractHostFromURL(tt.ldapURL)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestKerberosAuthenticationMethod(t *testing.T) {
	tests := []struct {
		name     string
		config   *ConnectionConfig
		expected AuthMethod
	}{
		{
			name: "kerberos with keytab",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/path/to/test.keytab",
			},
			expected: AuthMethodKerberos,
		},
		{
			name: "kerberos with password",
			config: &ConnectionConfig{
				Username:      "testuser",
				Password:      "testpass",
				KerberosRealm: "EXAMPLE.COM",
			},
			expected: AuthMethodKerberos,
		},
		{
			name: "simple bind (no kerberos)",
			config: &ConnectionConfig{
				Username: "testuser",
				Password: "testpass",
			},
			expected: AuthMethodSimpleBind,
		},
		{
			name: "kerberos realm only (insufficient)",
			config: &ConnectionConfig{
				Username:      "testuser",
				KerberosRealm: "EXAMPLE.COM",
			},
			expected: AuthMethodKerberos, // GetAuthMethod returns Kerberos if KerberosRealm + Username
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetAuthMethod()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestCreateGSSAPIClient tests the client creation logic indirectly
// by testing the configuration validation that would occur before client creation.
func TestCreateGSSAPIClientConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *ConnectionConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid keytab config",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/path/to/test.keytab",
				KerberosConfig: "/etc/krb5.conf",
			},
			expectError: false,
		},
		{
			name: "valid password config",
			config: &ConnectionConfig{
				Username:       "testuser",
				Password:       "testpass",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosConfig: "/etc/krb5.conf",
			},
			expectError: false,
		},
		{
			name: "missing keytab and password",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosConfig: "/etc/krb5.conf",
			},
			expectError: true,
			errorMsg:    "either keytab (kerberos_keytab) or password is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := prepareKerberosConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)

				// Verify the config would be suitable for client creation
				require.NotEmpty(t, tt.config.Username)
				require.NotEmpty(t, tt.config.KerberosRealm)
				require.NotEmpty(t, tt.config.KerberosConfig)

				// Should have either keytab or password
				hasCredentials := tt.config.KerberosKeytab != "" || tt.config.Password != ""
				assert.True(t, hasCredentials, "should have either keytab or password")
			}
		})
	}
}
