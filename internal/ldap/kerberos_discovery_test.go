package ldap

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRuntimeKrb5Conf(t *testing.T) {
	ctx := context.Background()

	t.Run("valid configuration", func(t *testing.T) {
		cfg := &ConnectionConfig{
			Domain:                 "example.com",
			KerberosRealm:          "EXAMPLE.COM",
			KerberosDNSLookupKDC:   true,
			KerberosDNSLookupRealm: true,
		}

		config, err := generateRuntimeKrb5Conf(ctx, cfg)
		require.NoError(t, err)
		assert.NotEmpty(t, config)

		// Check that the configuration contains expected sections and values
		assert.Contains(t, config, "[libdefaults]")
		assert.Contains(t, config, "default_realm = EXAMPLE.COM")
		assert.Contains(t, config, "dns_lookup_kdc = true")
		assert.Contains(t, config, "dns_lookup_realm = true")
		assert.Contains(t, config, "[realms]")
		assert.Contains(t, config, "EXAMPLE.COM = {")
		assert.Contains(t, config, "[domain_realm]")
		assert.Contains(t, config, ".example.com = EXAMPLE.COM")
		assert.Contains(t, config, "example.com = EXAMPLE.COM")
	})

	t.Run("missing realm", func(t *testing.T) {
		cfg := &ConnectionConfig{
			Domain: "example.com",
			// KerberosRealm is missing
		}

		_, err := generateRuntimeKrb5Conf(ctx, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kerberos realm is required")
	})

	t.Run("DNS lookups disabled", func(t *testing.T) {
		cfg := &ConnectionConfig{
			Domain:                 "example.com",
			KerberosRealm:          "EXAMPLE.COM",
			KerberosDNSLookupKDC:   false,
			KerberosDNSLookupRealm: false,
		}

		config, err := generateRuntimeKrb5Conf(ctx, cfg)
		require.NoError(t, err)
		assert.Contains(t, config, "dns_lookup_kdc = false")
		assert.Contains(t, config, "dns_lookup_realm = false")
	})

	t.Run("realm case conversion", func(t *testing.T) {
		cfg := &ConnectionConfig{
			Domain:                 "Example.Com",
			KerberosRealm:          "example.com",
			KerberosDNSLookupKDC:   true,
			KerberosDNSLookupRealm: true,
		}

		config, err := generateRuntimeKrb5Conf(ctx, cfg)
		require.NoError(t, err)

		// Realm should be uppercase
		assert.Contains(t, config, "default_realm = EXAMPLE.COM")
		assert.Contains(t, config, "EXAMPLE.COM = {")

		// Domain should be lowercase in domain_realm
		assert.Contains(t, config, ".example.com = EXAMPLE.COM")
		assert.Contains(t, config, "example.com = EXAMPLE.COM")
	})
}

func TestExtractRealmFromDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "simple domain",
			domain:   "example.com",
			expected: "EXAMPLE.COM",
		},
		{
			name:     "subdomain",
			domain:   "sub.example.com",
			expected: "SUB.EXAMPLE.COM",
		},
		{
			name:     "already uppercase",
			domain:   "EXAMPLE.COM",
			expected: "EXAMPLE.COM",
		},
		{
			name:     "mixed case",
			domain:   "Example.Com",
			expected: "EXAMPLE.COM",
		},
		{
			name:     "empty domain",
			domain:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRealmFromDomain(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateKerberosAutoDiscoveryConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("valid config with explicit realm", func(t *testing.T) {
		cfg := &ConnectionConfig{
			KerberosRealm: "EXAMPLE.COM",
			Password:      "testpass",
			Username:      "testuser",
		}

		err := validateKerberosAutoDiscoveryConfig(ctx, cfg)
		assert.NoError(t, err)
		assert.Equal(t, "EXAMPLE.COM", cfg.KerberosRealm)
	})

	t.Run("valid config with domain-derived realm", func(t *testing.T) {
		cfg := &ConnectionConfig{
			Domain:   "example.com",
			Password: "testpass",
			Username: "testuser",
		}

		err := validateKerberosAutoDiscoveryConfig(ctx, cfg)
		assert.NoError(t, err)
		assert.Equal(t, "EXAMPLE.COM", cfg.KerberosRealm) // Should be derived
	})

	t.Run("nil config", func(t *testing.T) {
		err := validateKerberosAutoDiscoveryConfig(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "configuration cannot be nil")
	})

	t.Run("missing realm and domain", func(t *testing.T) {
		cfg := &ConnectionConfig{
			Password: "testpass",
			Username: "testuser",
		}

		err := validateKerberosAutoDiscoveryConfig(ctx, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "either kerberos_realm or domain must be specified")
	})

	t.Run("no credentials", func(t *testing.T) {
		cfg := &ConnectionConfig{
			KerberosRealm: "EXAMPLE.COM",
			// No password, keytab, or credential cache
		}

		err := validateKerberosAutoDiscoveryConfig(ctx, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no suitable Kerberos credentials found")
	})
}

func TestBoolToString(t *testing.T) {
	assert.Equal(t, "true", boolToString(true))
	assert.Equal(t, "false", boolToString(false))
}

func TestGeneratedConfigStructure(t *testing.T) {
	ctx := context.Background()
	cfg := &ConnectionConfig{
		Domain:                 "example.com",
		KerberosRealm:          "EXAMPLE.COM",
		KerberosDNSLookupKDC:   true,
		KerberosDNSLookupRealm: true,
	}

	config, err := generateRuntimeKrb5Conf(ctx, cfg)
	require.NoError(t, err)

	// Test that the generated config has all required sections
	sections := []string{
		"[libdefaults]",
		"[realms]",
		"[domain_realm]",
		"[logging]",
	}

	for _, section := range sections {
		assert.Contains(t, config, section, "Config should contain section %s", section)
	}

	// Test that libdefaults contains required settings
	libdefaultsSettings := []string{
		"default_realm = EXAMPLE.COM",
		"dns_lookup_kdc = true",
		"dns_lookup_realm = true",
		"rdns = false",
		"forwardable = true",
		"ticket_lifetime = 24h",
		"renew_lifetime = 7d",
	}

	for _, setting := range libdefaultsSettings {
		assert.Contains(t, config, setting, "Config should contain libdefaults setting: %s", setting)
	}

	// Check line structure (should not have leading tabs in the output)
	lines := strings.Split(config, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue // Skip empty lines
		}
		if strings.HasPrefix(line, "[") {
			// Section headers should not be indented
			assert.False(t, strings.HasPrefix(line, "\t"), "Section header should not be indented: line %d: %s", i+1, line)
		} else {
			// Non-section lines should be indented with spaces
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				assert.True(t, strings.HasPrefix(line, "    "), "Setting should be indented with 4 spaces: line %d: %s", i+1, line)
			}
		}
	}
}
