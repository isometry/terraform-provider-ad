package ldap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareKerberosConfig(t *testing.T) {
	// Create temporary files for testing
	tempDir := t.TempDir()
	testKeytab := filepath.Join(tempDir, "test.keytab")
	testKrb5Conf := filepath.Join(tempDir, "krb5.conf")
	customKrb5Conf := filepath.Join(tempDir, "custom-krb5.conf")

	// Create test files
	for _, file := range []string{testKeytab, testKrb5Conf, customKrb5Conf} {
		f, err := os.Create(file)
		require.NoError(t, err)
		f.Close()
	}

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
				KerberosKeytab: testKeytab,
			},
			expectError: false,
			expected: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: testKeytab,
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
				KerberosKeytab: testKeytab,
			},
			expectError: false,
			expected: &ConnectionConfig{
				Username:       "testuser",    // Should be extracted
				KerberosRealm:  "EXAMPLE.COM", // Should be extracted
				KerberosKeytab: testKeytab,
				KerberosConfig: "/etc/krb5.conf",
			},
		},
		{
			name: "custom krb5.conf path",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: testKeytab,
				KerberosConfig: customKrb5Conf,
			},
			expectError: false,
			expected: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: testKeytab,
				KerberosConfig: customKrb5Conf, // Should preserve custom path
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
			name: "missing credentials (with invalid paths)",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/nonexistent/path/keytab",
				KerberosCCache: "/nonexistent/path/ccache",
			},
			expectError: true,
			errorMsg:    "no suitable Kerberos credentials found",
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
		cfg         *ConnectionConfig
		serverInfo  *ServerInfo
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil config",
			cfg:         nil,
			serverInfo:  &ServerInfo{Host: "dc1.example.com", Port: 636},
			expectError: true,
			errorMsg:    "configuration is required",
		},
		{
			name:        "SPN override provided",
			cfg:         &ConnectionConfig{KerberosSPN: "ldap/custom.spn.com"},
			serverInfo:  &ServerInfo{Host: "192.168.1.100", Port: 636},
			expected:    "ldap/custom.spn.com",
			expectError: false,
		},
		{
			name:        "empty SPN override with nil server info",
			cfg:         &ConnectionConfig{KerberosSPN: ""},
			serverInfo:  nil,
			expectError: true,
			errorMsg:    "server info is required",
		},
		{
			name: "empty SPN override with empty hostname",
			cfg:  &ConnectionConfig{KerberosSPN: ""},
			serverInfo: &ServerInfo{
				Host: "",
				Port: 636,
			},
			expectError: true,
			errorMsg:    "hostname is required",
		},
		{
			name: "empty SPN override with simple hostname",
			cfg:  &ConnectionConfig{KerberosSPN: ""},
			serverInfo: &ServerInfo{
				Host: "dc1.example.com",
				Port: 636,
			},
			expected:    "ldap/dc1.example.com",
			expectError: false,
		},
		{
			name: "empty SPN override with hostname with port",
			cfg:  &ConnectionConfig{KerberosSPN: ""},
			serverInfo: &ServerInfo{
				Host: "dc1.example.com:636",
				Port: 636,
			},
			expected:    "ldap/dc1.example.com", // Port should be stripped
			expectError: false,
		},
		{
			name: "empty SPN override with IP address",
			cfg:  &ConnectionConfig{KerberosSPN: ""},
			serverInfo: &ServerInfo{
				Host: "192.168.1.100",
				Port: 389,
			},
			expected:    "ldap/192.168.1.100",
			expectError: false,
		},
		{
			name:        "SPN override for IP address scenario",
			cfg:         &ConnectionConfig{KerberosSPN: "ldap/dc1.example.com"},
			serverInfo:  &ServerInfo{Host: "192.168.1.100", Port: 636},
			expected:    "ldap/dc1.example.com",
			expectError: false,
		},
		{
			name:        "SPN override with different service",
			cfg:         &ConnectionConfig{KerberosSPN: "host/server.example.com"},
			serverInfo:  &ServerInfo{Host: "dc1.example.com", Port: 636},
			expected:    "host/server.example.com",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildServicePrincipal(tt.cfg, tt.serverInfo)

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
	// Create temporary files for testing
	tempDir := t.TempDir()
	testKeytab := filepath.Join(tempDir, "test.keytab")
	testKrb5Conf := filepath.Join(tempDir, "krb5.conf")

	// Create test files
	for _, file := range []string{testKeytab, testKrb5Conf} {
		f, err := os.Create(file)
		require.NoError(t, err)
		f.Close()
	}

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
				KerberosKeytab: testKeytab,
				KerberosConfig: testKrb5Conf,
			},
			expectError: false,
		},
		{
			name: "valid password config",
			config: &ConnectionConfig{
				Username:       "testuser",
				Password:       "testpass",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosConfig: testKrb5Conf,
			},
			expectError: false,
		},
		{
			name: "missing keytab and password (with invalid paths)",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosConfig: "/etc/krb5.conf",
				KerberosKeytab: "/nonexistent/path/keytab",
				KerberosCCache: "/nonexistent/path/ccache",
			},
			expectError: true,
			errorMsg:    "no suitable Kerberos credentials found",
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

func TestGetDefaultCCachePath(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "no environment variable",
			envValue: "",
			expected: "/tmp/krb5cc_", // Will be calculated dynamically
		},
		{
			name:     "environment variable with FILE prefix",
			envValue: "FILE:/tmp/custom_ccache",
			expected: "/tmp/custom_ccache",
		},
		{
			name:     "environment variable without prefix",
			envValue: "/custom/path/ccache",
			expected: "/custom/path/ccache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				t.Setenv("KRB5CCNAME", tt.envValue)
			}

			result := getDefaultCCachePath()
			if tt.name == "no environment variable" {
				// Dynamic expectation for default path
				assert.Contains(t, result, "/tmp/krb5cc_")
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetDefaultKeytabPath(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "no environment variable",
			envValue: "",
			expected: "/etc/krb5.keytab",
		},
		{
			name:     "environment variable with FILE prefix",
			envValue: "FILE:/custom/path/keytab",
			expected: "/custom/path/keytab",
		},
		{
			name:     "environment variable without prefix",
			envValue: "/custom/keytab.kt",
			expected: "/custom/keytab.kt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				t.Setenv("KRB5_KTNAME", tt.envValue)
			}

			result := getDefaultKeytabPath()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFileExists(t *testing.T) {
	// Create a temporary file for testing
	tempDir := t.TempDir()
	existingFile := filepath.Join(tempDir, "existing.txt")
	missingFile := filepath.Join(tempDir, "missing.txt")

	// Create the existing file
	f, err := os.Create(existingFile)
	require.NoError(t, err)
	f.Close()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "existing file",
			path:     existingFile,
			expected: true,
		},
		{
			name:     "missing file",
			path:     missingFile,
			expected: false,
		},
		{
			name:     "empty path",
			path:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fileExists(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPrepareKerberosConfigEnhanced tests the enhanced validation logic.
func TestPrepareKerberosConfigEnhanced(t *testing.T) {
	tempDir := t.TempDir()
	existingKeytab := filepath.Join(tempDir, "test.keytab")
	existingCCache := filepath.Join(tempDir, "ccache")

	// Create test files
	f1, err := os.Create(existingKeytab)
	require.NoError(t, err)
	f1.Close()

	f2, err := os.Create(existingCCache)
	require.NoError(t, err)
	f2.Close()

	tests := []struct {
		name        string
		config      *ConnectionConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid credential cache config",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosCCache: existingCCache,
			},
			expectError: false,
		},
		{
			name: "valid keytab config",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: existingKeytab,
			},
			expectError: false,
		},
		{
			name: "valid password config",
			config: &ConnectionConfig{
				Username:      "testuser",
				Password:      "testpass",
				KerberosRealm: "EXAMPLE.COM",
			},
			expectError: false,
		},
		{
			name: "missing files and password",
			config: &ConnectionConfig{
				Username:       "testuser",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosKeytab: "/nonexistent/keytab",
				KerberosCCache: "/nonexistent/ccache",
			},
			expectError: true,
			errorMsg:    "no suitable Kerberos credentials found",
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
			}
		})
	}
}
