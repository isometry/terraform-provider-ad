package ldap

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
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
	spn, err := buildServicePrincipal(serverInfo)
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
func createGSSAPIClient(cfg *ConnectionConfig) (ldap.GSSAPIClient, error) {
	// Default krb5.conf path if not specified
	krb5confPath := cfg.KerberosConfig
	if krb5confPath == "" {
		krb5confPath = "/etc/krb5.conf"
	}

	// Create client based on available credentials
	if cfg.KerberosKeytab != "" {
		// Use keytab authentication
		return gssapi.NewClientWithKeytab(cfg.Username, cfg.KerberosRealm, cfg.KerberosKeytab, krb5confPath)
	} else if cfg.Password != "" {
		// Use password authentication
		return gssapi.NewClientWithPassword(cfg.Username, cfg.KerberosRealm, cfg.Password, krb5confPath)
	}

	return nil, fmt.Errorf("no suitable credentials found for Kerberos authentication")
}

// buildServicePrincipal constructs the LDAP service principal name from server info.
func buildServicePrincipal(serverInfo *ServerInfo) (string, error) {
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

	// Validate that we have credentials
	if cfg.KerberosKeytab == "" && cfg.Password == "" {
		return fmt.Errorf("either keytab (kerberos_keytab) or password is required for Kerberos authentication")
	}

	return nil
}
