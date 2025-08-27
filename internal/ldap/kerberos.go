package ldap

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	krb5client "github.com/jcmturner/gokrb5/v8/client"
)

// performKerberosAuth performs Kerberos authentication on an LDAP connection.
// This can be shared by both client and pool implementations.
func performKerberosAuth(conn *ldap.Conn, cfg *ConnectionConfig, serverInfo *ServerInfo) error {
	// Validate Kerberos configuration
	if err := prepareKerberosConfig(cfg); err != nil {
		return fmt.Errorf("kerberos configuration error: %w", err)
	}

	// Create GSSAPI client based on available credentials
	gssapiClient, err := createGSSAPIClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create GSSAPI client: %w", err)
	}
	defer func() {
		_ = gssapiClient.DeleteSecContext()
	}()

	// Build service principal name from connection info
	spn, err := buildServicePrincipal(cfg, serverInfo)
	if err != nil {
		return fmt.Errorf("failed to build service principal: %w", err)
	}

	// Perform the GSSAPI bind
	err = conn.GSSAPIBind(gssapiClient, spn, "")
	if err != nil {
		return fmt.Errorf("GSSAPI bind failed: %w", err)
	}

	return nil
}

// createGSSAPIClient creates a GSSAPI client based on the configuration.
// Priority order: credential cache → keytab → password.
func createGSSAPIClient(cfg *ConnectionConfig) (ldap.GSSAPIClient, error) {
	// Default krb5.conf path if not specified
	krb5confPath := cfg.KerberosConfig
	if krb5confPath == "" {
		krb5confPath = "/etc/krb5.conf"
	}

	// Check if the krb5.conf file exists before proceeding
	if !fileExists(krb5confPath) {
		return nil, fmt.Errorf("Kerberos configuration file not found at %s. "+
			"For Kerberos authentication, you must provide a valid krb5.conf file. "+
			"Either create %s or specify a custom path using 'kerberos_config'. "+
			"Example minimal configuration:\n%s",
			krb5confPath, krb5confPath, generateExampleKrb5Conf(cfg))
	}

	// Priority 1: Explicit credential cache
	if cfg.KerberosCCache != "" && fileExists(cfg.KerberosCCache) {
		return gssapi.NewClientFromCCache(cfg.KerberosCCache, krb5confPath, krb5client.DisablePAFXFAST(true))
	}

	// Priority 2: Default credential cache (if exists)
	defaultCCache := getDefaultCCachePath()
	if fileExists(defaultCCache) {
		log.Printf("[DEBUG] Using default credential cache: %s", defaultCCache)
		return gssapi.NewClientFromCCache(defaultCCache, krb5confPath, krb5client.DisablePAFXFAST(true))
	}

	// Priority 3: Explicit keytab
	if cfg.KerberosKeytab != "" && fileExists(cfg.KerberosKeytab) {
		return gssapi.NewClientWithKeytab(cfg.Username, cfg.KerberosRealm, cfg.KerberosKeytab, krb5confPath, krb5client.DisablePAFXFAST(true))
	}

	// Priority 4: Default keytab (if exists and username provided)
	if cfg.Username != "" {
		defaultKeytab := getDefaultKeytabPath()
		if fileExists(defaultKeytab) {
			return gssapi.NewClientWithKeytab(cfg.Username, cfg.KerberosRealm, defaultKeytab, krb5confPath, krb5client.DisablePAFXFAST(true))
		}
	}

	// Priority 5: Password authentication
	if cfg.Username != "" && cfg.Password != "" {
		return gssapi.NewClientWithPassword(cfg.Username, cfg.KerberosRealm, cfg.Password, krb5confPath, krb5client.DisablePAFXFAST(true))
	}

	return nil, fmt.Errorf("no suitable credentials found for Kerberos authentication")
}

// buildServicePrincipal constructs the LDAP service principal name from server info.
// If cfg.KerberosSPN is set, it overrides the automatic SPN construction.
func buildServicePrincipal(cfg *ConnectionConfig, serverInfo *ServerInfo) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("configuration is required for service principal")
	}

	// Use explicit SPN override if provided
	if cfg.KerberosSPN != "" {
		return cfg.KerberosSPN, nil
	}

	if serverInfo == nil {
		return "", fmt.Errorf("server info is required for service principal")
	}

	hostname := serverInfo.Host
	if hostname == "" {
		return "", fmt.Errorf("hostname is required for service principal")
	}

	// Remove port if present (SPN should not include port)
	if colonPos := strings.Index(hostname, ":"); colonPos != -1 {
		hostname = hostname[:colonPos]
	}

	return fmt.Sprintf("ldap/%s", hostname), nil
}

// extractHostFromURL extracts hostname from LDAP URL for backward compatibility.
func extractHostFromURL(ldapURL string) (string, error) {
	if ldapURL == "" {
		return "", fmt.Errorf("LDAP URL cannot be empty")
	}

	parsedURL, err := url.Parse(ldapURL)
	if err != nil {
		return "", fmt.Errorf("invalid LDAP URL: %w", err)
	}

	hostname := parsedURL.Hostname()
	if hostname == "" {
		return "", fmt.Errorf("no hostname found in URL: %s", ldapURL)
	}

	return hostname, nil
}

// prepareKerberosConfig validates and prepares Kerberos configuration.
func prepareKerberosConfig(cfg *ConnectionConfig) error {
	if cfg == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Set default krb5.conf path if not specified
	if cfg.KerberosConfig == "" {
		cfg.KerberosConfig = "/etc/krb5.conf"
	}

	// Extract realm from username if not specified and username contains @
	if cfg.KerberosRealm == "" && strings.Contains(cfg.Username, "@") {
		parts := strings.Split(cfg.Username, "@")
		if len(parts) == 2 {
			cfg.KerberosRealm = parts[1]
			cfg.Username = parts[0]
		}
	}

	// Validate required configuration
	if cfg.KerberosRealm == "" {
		return fmt.Errorf("kerberos realm is required (set kerberos_realm or include realm in username)")
	}

	if cfg.Username == "" {
		return fmt.Errorf("username (principal) is required for Kerberos authentication")
	}

	// Validate that we have some form of credentials
	hasExplicitCCache := cfg.KerberosCCache != "" && fileExists(cfg.KerberosCCache)
	hasDefaultCCache := fileExists(getDefaultCCachePath())
	hasExplicitKeytab := cfg.KerberosKeytab != "" && fileExists(cfg.KerberosKeytab)
	hasDefaultKeytab := fileExists(getDefaultKeytabPath())
	hasPassword := cfg.Password != ""

	if !hasExplicitCCache && !hasDefaultCCache && !hasExplicitKeytab && !hasDefaultKeytab && !hasPassword {
		return fmt.Errorf("no suitable Kerberos credentials found: provide kerberos_ccache, kerberos_keytab, password, or ensure default credential cache/keytab exists")
	}

	return nil
}

// getDefaultCCachePath returns the default credential cache location.
func getDefaultCCachePath() string {
	if ccache := os.Getenv("KRB5CCNAME"); ccache != "" {
		// Handle FILE: prefix
		if strings.HasPrefix(ccache, "FILE:") {
			return strings.TrimPrefix(ccache, "FILE:")
		}
		return ccache
	}
	// Default: /tmp/krb5cc_${UID}
	return fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
}

// getDefaultKeytabPath returns the default keytab location.
func getDefaultKeytabPath() string {
	if keytab := os.Getenv("KRB5_KTNAME"); keytab != "" {
		// Handle FILE: prefix
		if strings.HasPrefix(keytab, "FILE:") {
			return strings.TrimPrefix(keytab, "FILE:")
		}
		return keytab
	}
	return "/etc/krb5.keytab"
}

// fileExists checks if a file exists and is readable.
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	// Try to open the file to check if it's actually accessible
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

// generateExampleKrb5Conf generates example krb5.conf content for error messages.
func generateExampleKrb5Conf(cfg *ConnectionConfig) string {
	if cfg == nil || cfg.KerberosRealm == "" {
		return "[libdefaults]\n    default_realm = YOUR.REALM.COM\n\n[realms]\n    YOUR.REALM.COM = {\n        kdc = your-dc.realm.com:88\n    }"
	}

	realm := cfg.KerberosRealm
	// Try to extract hostname from LDAP URLs if available
	var kdcHost string

	// Look for domain in the config to build a reasonable example
	kdcHost = fmt.Sprintf("dc.%s", strings.ToLower(strings.ReplaceAll(realm, ".", ".")))

	// If we have LDAP URLs in the parent config, we could potentially extract from there
	// but for now, we'll generate a reasonable example

	return fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    %s = {
        kdc = %s:88
        admin_server = %s:749
    }

[domain_realm]
    .%s = %s
    %s = %s`,
		realm,
		realm,
		kdcHost, kdcHost,
		strings.ToLower(strings.ReplaceAll(realm, ".", ".")), realm,
		strings.ToLower(strings.ReplaceAll(realm, ".", ".")), realm)
}
