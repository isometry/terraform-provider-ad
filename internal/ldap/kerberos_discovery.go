package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// generateRuntimeKrb5Conf generates a krb5.conf configuration string for DNS-based discovery.
func generateRuntimeKrb5Conf(ctx context.Context, cfg *ConnectionConfig) (string, error) {
	if cfg.KerberosRealm == "" {
		return "", fmt.Errorf("kerberos realm is required for auto-discovery")
	}

	realm := strings.ToUpper(cfg.KerberosRealm)
	domain := strings.ToLower(cfg.KerberosRealm)

	// If we have a domain configured, use it for domain_realm mapping
	if cfg.Domain != "" {
		domain = strings.ToLower(cfg.Domain)
	}

	// Determine DNS lookup settings
	// For auto-discovery mode (no config file), default to true unless explicitly disabled
	dnsLookupKDC := cfg.KerberosDNSLookupKDC
	dnsLookupRealm := cfg.KerberosDNSLookupRealm

	// Only apply defaults in auto-discovery mode (when KerberosConfig is empty)
	// We need to differentiate between "not set" and "explicitly set to false"
	// Since the config struct uses bool (not *bool), we can't distinguish, so we
	// rely on the provider Configure method to set appropriate defaults

	tflog.SubsystemDebug(ctx, "ldap", "Generating runtime krb5.conf", map[string]any{
		"realm":            realm,
		"domain":           domain,
		"dns_lookup_kdc":   dnsLookupKDC,
		"dns_lookup_realm": dnsLookupRealm,
	})

	config := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = %s
    dns_lookup_realm = %s
    rdns = false
    forwardable = true
    ticket_lifetime = 24h
    renew_lifetime = 7d

[realms]
    %s = {
        # KDCs will be discovered via DNS SRV records
    }

[domain_realm]
    .%s = %s
    %s = %s

[logging]
    default = FILE:/dev/stdout
    kdc = FILE:/dev/stdout
    admin_server = FILE:/dev/stdout
`,
		realm,
		boolToString(dnsLookupKDC),
		boolToString(dnsLookupRealm),
		realm,
		domain, realm,
		domain, realm,
	)

	tflog.SubsystemDebug(ctx, "ldap", "Generated runtime krb5.conf configuration", map[string]any{
		"config_length": len(config),
	})

	return config, nil
}

// boolToString converts a boolean to a string for krb5.conf.
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// extractRealmFromDomain attempts to derive a Kerberos realm from a domain name.
func extractRealmFromDomain(domain string) string {
	if domain == "" {
		return ""
	}

	// Simple heuristic: uppercase the domain name
	return strings.ToUpper(domain)
}

// validateKerberosAutoDiscoveryConfig validates the configuration for auto-discovery.
func validateKerberosAutoDiscoveryConfig(ctx context.Context, cfg *ConnectionConfig) error {
	if cfg == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Auto-discovery requires either explicit realm or domain to derive realm from
	if cfg.KerberosRealm == "" && cfg.Domain == "" {
		return fmt.Errorf("either kerberos_realm or domain must be specified for auto-discovery")
	}

	// If realm is not specified, try to derive it from domain
	if cfg.KerberosRealm == "" && cfg.Domain != "" {
		cfg.KerberosRealm = extractRealmFromDomain(cfg.Domain)
		tflog.SubsystemDebug(ctx, "ldap", "Derived Kerberos realm from domain", map[string]any{
			"domain": cfg.Domain,
			"realm":  cfg.KerberosRealm,
		})
	}

	// Validate that we have authentication credentials
	hasExplicitCCache := cfg.KerberosCCache != "" && fileExists(cfg.KerberosCCache)
	hasDefaultCCache := fileExists(getDefaultCCachePath())
	hasExplicitKeytab := cfg.KerberosKeytab != "" && fileExists(cfg.KerberosKeytab)
	hasDefaultKeytab := fileExists(getDefaultKeytabPath())
	hasPassword := cfg.Password != ""

	if !hasExplicitCCache && !hasDefaultCCache && !hasExplicitKeytab && !hasDefaultKeytab && !hasPassword {
		return fmt.Errorf("no suitable Kerberos credentials found for auto-discovery: provide kerberos_ccache, kerberos_keytab, password, or ensure default credential cache/keytab exists")
	}

	tflog.SubsystemDebug(ctx, "ldap", "Kerberos auto-discovery configuration validated", map[string]any{
		"realm":               cfg.KerberosRealm,
		"has_explicit_ccache": hasExplicitCCache,
		"has_default_ccache":  hasDefaultCCache,
		"has_explicit_keytab": hasExplicitKeytab,
		"has_default_keytab":  hasDefaultKeytab,
		"has_password":        hasPassword,
		"dns_lookup_kdc":      cfg.KerberosDNSLookupKDC,
		"dns_lookup_realm":    cfg.KerberosDNSLookupRealm,
	})

	return nil
}
