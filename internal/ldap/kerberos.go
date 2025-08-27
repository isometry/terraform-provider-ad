package ldap

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	krb5client "github.com/jcmturner/gokrb5/v8/client"
)

// performKerberosAuth performs Kerberos authentication on an LDAP connection.
// This can be shared by both client and pool implementations.
func performKerberosAuth(conn *ldap.Conn, cfg *ConnectionConfig, serverInfo *ServerInfo) error {
	return performKerberosAuthWithContext(context.Background(), conn, cfg, serverInfo)
}

// performKerberosAuthWithContext performs Kerberos authentication with logging context.
func performKerberosAuthWithContext(ctx context.Context, conn *ldap.Conn, cfg *ConnectionConfig, serverInfo *ServerInfo) error {
	start := time.Now()

	kerberosFields := map[string]any{
		"realm":    cfg.KerberosRealm,
		"username": cfg.Username,
		"host":     serverInfo.Host,
	}

	tflog.Info(ctx, "Kerberos authentication attempt", kerberosFields)

	// Validate Kerberos configuration
	tflog.Debug(ctx, "Validating Kerberos configuration", kerberosFields)
	if err := prepareKerberosConfigWithContext(ctx, cfg); err != nil {
		tflog.Error(ctx, "Kerberos configuration validation failed", map[string]any{
			"error": err.Error(),
		})
		return fmt.Errorf("kerberos configuration error: %w", err)
	}

	// Create GSSAPI client based on available credentials
	tflog.Debug(ctx, "Creating GSSAPI client", kerberosFields)
	gssapiClient, err := createGSSAPIClientWithContext(ctx, cfg)
	if err != nil {
		tflog.Error(ctx, "Kerberos GSSAPI client creation failed", map[string]any{
			"error":       err.Error(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
		return fmt.Errorf("failed to create GSSAPI client: %w", err)
	}
	defer func() {
		tflog.Debug(ctx, "Cleaning up GSSAPI security context")
		if deleteErr := gssapiClient.DeleteSecContext(); deleteErr != nil {
			tflog.Warn(ctx, "Failed to delete security context", map[string]any{
				"error": deleteErr.Error(),
			})
		}
	}()

	tflog.Debug(ctx, "Kerberos GSSAPI client created", map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
	})

	// Build service principal name from connection info
	spn, err := buildServicePrincipalWithContext(ctx, cfg, serverInfo)
	if err != nil {
		tflog.Error(ctx, "Kerberos SPN build failed", map[string]any{
			"error":       err.Error(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
		return fmt.Errorf("failed to build service principal: %w", err)
	}

	kerberosFields["spn"] = spn
	tflog.Info(ctx, "Attempting GSSAPI bind", kerberosFields)

	// Perform the GSSAPI bind
	bindStart := time.Now()
	err = conn.GSSAPIBind(gssapiClient, spn, "")
	bindDuration := time.Since(bindStart)

	kerberosFields["bind_duration_ms"] = bindDuration.Milliseconds()
	kerberosFields["total_duration_ms"] = time.Since(start).Milliseconds()

	if err != nil {
		kerberosFields["error"] = err.Error()
		tflog.Error(ctx, "Kerberos authentication failed", kerberosFields)
		return fmt.Errorf("GSSAPI bind failed: %w", err)
	}

	tflog.Info(ctx, "Kerberos authentication successful", kerberosFields)
	return nil
}

// createGSSAPIClient creates a GSSAPI client based on the configuration.
// Priority order: credential cache → keytab → password.
func createGSSAPIClient(cfg *ConnectionConfig) (ldap.GSSAPIClient, error) {
	return createGSSAPIClientWithContext(context.Background(), cfg)
}

// createGSSAPIClientWithContext creates a GSSAPI client with logging context.
func createGSSAPIClientWithContext(ctx context.Context, cfg *ConnectionConfig) (ldap.GSSAPIClient, error) {
	// Default krb5.conf path if not specified
	krb5confPath := cfg.KerberosConfig
	if krb5confPath == "" {
		krb5confPath = "/etc/krb5.conf"
	}

	tflog.Debug(ctx, "Checking Kerberos configuration file", map[string]any{
		"krb5_conf_path": krb5confPath,
	})

	// Check if the krb5.conf file exists before proceeding
	if !fileExists(krb5confPath) {
		tflog.Error(ctx, "Kerberos krb5.conf not found", map[string]any{
			"path": krb5confPath,
		})
		return nil, fmt.Errorf("kerberos configuration file not found at %s. "+
			"For Kerberos authentication, you must provide a valid krb5.conf file. "+
			"Either create %s or specify a custom path using 'kerberos_config'. "+
			"Example minimal configuration:\n%s",
			krb5confPath, krb5confPath, generateExampleKrb5Conf(cfg))
	}

	tflog.Debug(ctx, "Kerberos krb5.conf found", map[string]any{
		"path": krb5confPath,
	})

	// Priority 1: Explicit credential cache
	if cfg.KerberosCCache != "" && fileExists(cfg.KerberosCCache) {
		tflog.Debug(ctx, "Kerberos credentials selected", map[string]any{
			"method": "explicit_ccache",
			"path":   cfg.KerberosCCache,
		})
		client, err := gssapi.NewClientFromCCache(cfg.KerberosCCache, krb5confPath, krb5client.DisablePAFXFAST(true))
		if err != nil {
			tflog.Error(ctx, "Kerberos credential cache failed", map[string]any{
				"path":  cfg.KerberosCCache,
				"error": err.Error(),
			})
			return nil, err
		}
		tflog.Debug(ctx, "Kerberos credential cache loaded", map[string]any{
			"path": cfg.KerberosCCache,
		})
		return client, nil
	}

	// Priority 2: Default credential cache (if exists)
	defaultCCache := getDefaultCCachePath()
	if fileExists(defaultCCache) {
		tflog.Debug(ctx, "Kerberos credentials selected", map[string]any{
			"method": "default_ccache",
			"path":   defaultCCache,
		})
		client, err := gssapi.NewClientFromCCache(defaultCCache, krb5confPath, krb5client.DisablePAFXFAST(true))
		if err != nil {
			tflog.Error(ctx, "Kerberos credential cache failed", map[string]any{
				"path":  defaultCCache,
				"error": err.Error(),
			})
			return nil, err
		}
		tflog.Debug(ctx, "Kerberos credential cache loaded", map[string]any{
			"path": defaultCCache,
		})
		return client, nil
	}

	// Priority 3: Explicit keytab
	if cfg.KerberosKeytab != "" && fileExists(cfg.KerberosKeytab) {
		tflog.Debug(ctx, "Kerberos credentials selected", map[string]any{
			"method":   "explicit_keytab",
			"path":     cfg.KerberosKeytab,
			"username": cfg.Username,
			"realm":    cfg.KerberosRealm,
		})
		client, err := gssapi.NewClientWithKeytab(cfg.Username, cfg.KerberosRealm, cfg.KerberosKeytab, krb5confPath, krb5client.DisablePAFXFAST(true))
		if err != nil {
			tflog.Error(ctx, "Kerberos keytab failed", map[string]any{
				"path":  cfg.KerberosKeytab,
				"error": err.Error(),
			})
			return nil, err
		}
		tflog.Debug(ctx, "Kerberos keytab loaded", map[string]any{
			"path": cfg.KerberosKeytab,
		})
		return client, nil
	}

	// Priority 4: Default keytab (if exists and username provided)
	if cfg.Username != "" {
		defaultKeytab := getDefaultKeytabPath()
		if fileExists(defaultKeytab) {
			tflog.Debug(ctx, "Kerberos credentials selected", map[string]any{
				"method":   "default_keytab",
				"path":     defaultKeytab,
				"username": cfg.Username,
				"realm":    cfg.KerberosRealm,
			})
			client, err := gssapi.NewClientWithKeytab(cfg.Username, cfg.KerberosRealm, defaultKeytab, krb5confPath, krb5client.DisablePAFXFAST(true))
			if err != nil {
				tflog.Error(ctx, "Kerberos keytab failed", map[string]any{
					"path":  defaultKeytab,
					"error": err.Error(),
				})
				return nil, err
			}
			tflog.Debug(ctx, "Kerberos keytab loaded", map[string]any{
				"path": defaultKeytab,
			})
			return client, nil
		}
	}

	// Priority 5: Password authentication
	if cfg.Username != "" && cfg.Password != "" {
		tflog.Debug(ctx, "Kerberos credentials selected", map[string]any{
			"method":   "password",
			"username": cfg.Username,
			"realm":    cfg.KerberosRealm,
		})
		client, err := gssapi.NewClientWithPassword(cfg.Username, cfg.KerberosRealm, cfg.Password, krb5confPath, krb5client.DisablePAFXFAST(true))
		if err != nil {
			tflog.Error(ctx, "Kerberos password auth failed", map[string]any{
				"username": cfg.Username,
				"realm":    cfg.KerberosRealm,
				"error":    err.Error(),
			})
			return nil, err
		}
		tflog.Debug(ctx, "Kerberos password auth success", map[string]any{
			"username": cfg.Username,
			"realm":    cfg.KerberosRealm,
		})
		return client, nil
	}

	tflog.Error(ctx, "Kerberos no credentials found", map[string]any{
		"checked_explicit_ccache": cfg.KerberosCCache != "",
		"checked_default_ccache":  fileExists(getDefaultCCachePath()),
		"checked_explicit_keytab": cfg.KerberosKeytab != "",
		"checked_default_keytab":  cfg.Username != "" && fileExists(getDefaultKeytabPath()),
		"has_password":            cfg.Password != "",
	})

	return nil, fmt.Errorf("no suitable credentials found for Kerberos authentication")
}

// buildServicePrincipal constructs the LDAP service principal name from server info.
// If cfg.KerberosSPN is set, it overrides the automatic SPN construction.
func buildServicePrincipal(cfg *ConnectionConfig, serverInfo *ServerInfo) (string, error) {
	return buildServicePrincipalWithContext(context.Background(), cfg, serverInfo)
}

// buildServicePrincipalWithContext constructs the LDAP service principal name with logging context.
func buildServicePrincipalWithContext(ctx context.Context, cfg *ConnectionConfig, serverInfo *ServerInfo) (string, error) {
	if cfg == nil {
		tflog.Error(ctx, "Configuration is required for service principal")
		return "", fmt.Errorf("configuration is required for service principal")
	}

	// Use explicit SPN override if provided
	if cfg.KerberosSPN != "" {
		tflog.Debug(ctx, "Using explicit SPN override", map[string]any{
			"spn": cfg.KerberosSPN,
		})
		return cfg.KerberosSPN, nil
	}

	if serverInfo == nil {
		tflog.Error(ctx, "Server info is required for service principal")
		return "", fmt.Errorf("server info is required for service principal")
	}

	hostname := serverInfo.Host
	if hostname == "" {
		tflog.Error(ctx, "Hostname is required for service principal")
		return "", fmt.Errorf("hostname is required for service principal")
	}

	// Remove port if present (SPN should not include port)
	if colonPos := strings.Index(hostname, ":"); colonPos != -1 {
		originalHostname := hostname
		hostname = hostname[:colonPos]
		tflog.Debug(ctx, "Removed port from hostname for SPN", map[string]any{
			"original_hostname": originalHostname,
			"cleaned_hostname":  hostname,
		})
	}

	spn := fmt.Sprintf("ldap/%s", hostname)
	tflog.Debug(ctx, "Built service principal name", map[string]any{
		"spn":      spn,
		"hostname": hostname,
	})

	return spn, nil
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
	return prepareKerberosConfigWithContext(context.Background(), cfg)
}

// prepareKerberosConfigWithContext validates and prepares Kerberos configuration with logging context.
func prepareKerberosConfigWithContext(ctx context.Context, cfg *ConnectionConfig) error {
	_ = ctx // Context reserved for future logging enhancements
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
		if after, ok := strings.CutPrefix(ccache, "FILE:"); ok {
			return after
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
		if after, ok := strings.CutPrefix(keytab, "FILE:"); ok {
			return after
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
	// Look for domain in the config to build a reasonable example
	kdcHost := fmt.Sprintf("dc.%s", strings.ToLower(strings.ReplaceAll(realm, ".", ".")))

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
