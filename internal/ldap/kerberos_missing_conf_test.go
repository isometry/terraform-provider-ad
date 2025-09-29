package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCreateGSSAPIClientMissingKrb5Conf tests handling of missing krb5.conf files.
func TestCreateGSSAPIClientMissingKrb5Conf(t *testing.T) {
	tests := []struct {
		name        string
		config      *ConnectionConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "password auth with missing krb5.conf should return helpful error",
			config: &ConnectionConfig{
				Username:       "testuser",
				Password:       "testpass",
				KerberosRealm:  "EXAMPLE.COM",
				KerberosConfig: "/nonexistent/krb5.conf",
			},
			expectError: true,
			errorMsg:    "kerberos configuration file not found at /nonexistent/krb5.conf",
		},
		{
			name: "password auth with no krb5.conf config should trigger auto-discovery",
			config: &ConnectionConfig{
				Username:      "testuser",
				Password:      "testpass",
				KerberosRealm: "EXAMPLE.COM",
				// KerberosConfig left empty, will trigger auto-discovery mode
			},
			expectError: false, // Now succeeds with auto-discovery - generates runtime krb5.conf
			errorMsg:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := createGSSAPIClient(tt.config)

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
