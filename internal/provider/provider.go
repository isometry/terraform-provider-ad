package provider

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/providervalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// Ensure ActiveDirectoryProvider satisfies various provider interfaces.
var _ provider.Provider = &ActiveDirectoryProvider{}
var _ provider.ProviderWithFunctions = &ActiveDirectoryProvider{}
var _ provider.ProviderWithEphemeralResources = &ActiveDirectoryProvider{}
var _ provider.ProviderWithConfigValidators = &ActiveDirectoryProvider{}

// ActiveDirectoryProvider defines the provider implementation.
type ActiveDirectoryProvider struct {
	// Version is set to the provider Version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	Version      string
	cacheManager *ldapclient.CacheManager
}

// ActiveDirectoryProviderModel describes the provider data model.
type ActiveDirectoryProviderModel struct {
	// Connection settings - mutually exclusive
	Domain  types.String `tfsdk:"domain"`
	LdapURL types.String `tfsdk:"ldap_url"`
	BaseDN  types.String `tfsdk:"base_dn"`

	// Authentication settings
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`

	// Kerberos settings (optional)
	KerberosRealm          types.String `tfsdk:"kerberos_realm"`
	KerberosKeytab         types.String `tfsdk:"kerberos_keytab"`
	KerberosConfig         types.String `tfsdk:"kerberos_config"`
	KerberosCCache         types.String `tfsdk:"kerberos_ccache"`
	KerberosSPN            types.String `tfsdk:"kerberos_spn"`
	KerberosDNSLookupKDC   types.Bool   `tfsdk:"kerberos_dns_lookup_kdc"`
	KerberosDNSLookupRealm types.Bool   `tfsdk:"kerberos_dns_lookup_realm"`

	// TLS settings
	UseTLS            types.Bool   `tfsdk:"use_tls"`
	SkipTLSVerify     types.Bool   `tfsdk:"skip_tls_verify"`
	TLSCACertFile     types.String `tfsdk:"tls_ca_cert_file"`
	TLSCACert         types.String `tfsdk:"tls_ca_cert"`
	TLSClientCertFile types.String `tfsdk:"tls_client_cert_file"`
	TLSClientKeyFile  types.String `tfsdk:"tls_client_key_file"`

	// Connection pool settings
	MaxConnections types.Int64 `tfsdk:"max_connections"`
	MaxIdleTime    types.Int64 `tfsdk:"max_idle_time"`
	ConnectTimeout types.Int64 `tfsdk:"connect_timeout"`

	// Retry settings
	MaxRetries     types.Int64 `tfsdk:"max_retries"`
	InitialBackoff types.Int64 `tfsdk:"initial_backoff"`
	MaxBackoff     types.Int64 `tfsdk:"max_backoff"`

	// Cache settings
	WarmCache types.Bool `tfsdk:"warm_cache"`
}

// Metadata returns the provider type name and version.
func (p *ActiveDirectoryProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ad"
	resp.Version = p.Version
}

// Schema defines the provider configuration schema.
func (p *ActiveDirectoryProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The Active Directory provider enables management of Active Directory resources via LDAP/LDAPS. " +
			"It supports SRV-based domain controller discovery, connection pooling, and multiple authentication methods.",
		Attributes: map[string]schema.Attribute{
			// Connection settings - mutually exclusive
			"domain": schema.StringAttribute{
				MarkdownDescription: "Active Directory domain name for SRV-based discovery (e.g., `example.com`). " +
					"Mutually exclusive with `ldap_url`. Can be set via the `AD_DOMAIN` environment variable.",
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"ldap_url": schema.StringAttribute{
				MarkdownDescription: "Direct LDAP/LDAPS URL (e.g., `ldaps://dc1.example.com:636`). " +
					"Mutually exclusive with `domain`. Can be set via the `AD_LDAP_URL` environment variable.",
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"base_dn": schema.StringAttribute{
				MarkdownDescription: "Base DN for LDAP searches (e.g., `dc=example,dc=com`). " +
					"If not specified, will be automatically discovered from the root DSE. " +
					"Can be set via the `AD_BASE_DN` environment variable.",
				Optional: true,
			},

			// Authentication settings
			"username": schema.StringAttribute{
				MarkdownDescription: "Username for LDAP authentication. Supports DN, UPN, or SAM account name formats. " +
					"Can be set via the `AD_USERNAME` or `AD_USER` environment variables.",
				Optional: true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Password for LDAP authentication. " +
					"Can be set via the `AD_PASSWORD` environment variable.",
				Optional:  true,
				Sensitive: true,
			},

			// Kerberos settings
			"kerberos_realm": schema.StringAttribute{
				MarkdownDescription: "Kerberos realm for GSSAPI authentication (e.g., `EXAMPLE.COM`). " +
					"Can be set via the `AD_KERBEROS_REALM` environment variable.",
				Optional: true,
			},
			"kerberos_keytab": schema.StringAttribute{
				MarkdownDescription: "Path to Kerberos keytab file for authentication. " +
					"Can be set via the `AD_KERBEROS_KEYTAB` environment variable.",
				Optional: true,
			},
			"kerberos_config": schema.StringAttribute{
				MarkdownDescription: "Path to Kerberos configuration file (krb5.conf). If not specified but " +
					"`kerberos_realm` is set, DNS-based auto-discovery will be used to locate KDCs. " +
					"Can be set via the `AD_KERBEROS_CONFIG` environment variable.",
				Optional: true,
			},
			"kerberos_ccache": schema.StringAttribute{
				MarkdownDescription: "Path to Kerberos credential cache file for authentication. " +
					"When specified, existing Kerberos tickets will be used for authentication. " +
					"Can be set via the `AD_KERBEROS_CCACHE` environment variable.",
				Optional: true,
			},
			"kerberos_spn": schema.StringAttribute{
				MarkdownDescription: "Override Service Principal Name (SPN) for Kerberos authentication. " +
					"Use when connecting to a domain controller by IP address where the SPN doesn't match the IP. " +
					"Format: `ldap/<hostname>` (e.g., `ldap/dc1.example.com`). " +
					"Can be set via the `AD_KERBEROS_SPN` environment variable.",
				Optional: true,
			},
			"kerberos_dns_lookup_kdc": schema.BoolAttribute{
				MarkdownDescription: "Enable DNS-based KDC discovery for Kerberos authentication. " +
					"Defaults to `true` when `kerberos_config` is not specified but `kerberos_realm` is set. " +
					"Can be set via the `AD_KERBEROS_DNS_LOOKUP_KDC` environment variable.",
				Optional: true,
			},
			"kerberos_dns_lookup_realm": schema.BoolAttribute{
				MarkdownDescription: "Enable DNS-based realm discovery for Kerberos authentication. " +
					"Defaults to `true` when `kerberos_config` is not specified but `kerberos_realm` is set. " +
					"Can be set via the `AD_KERBEROS_DNS_LOOKUP_REALM` environment variable.",
				Optional: true,
			},

			// TLS settings
			"use_tls": schema.BoolAttribute{
				MarkdownDescription: "Force TLS/LDAPS connection. Defaults to `true`. " +
					"Can be set via the `AD_USE_TLS` environment variable.",
				Optional: true,
			},
			"skip_tls_verify": schema.BoolAttribute{
				MarkdownDescription: "Skip TLS certificate verification. Not recommended for production. Defaults to `false`. " +
					"Can be set via the `AD_SKIP_TLS_VERIFY` environment variable.",
				Optional: true,
			},
			"tls_ca_cert_file": schema.StringAttribute{
				MarkdownDescription: "Path to custom CA certificate file for TLS verification. " +
					"Can be set via the `AD_TLS_CA_CERT_FILE` environment variable.",
				Optional: true,
			},
			"tls_ca_cert": schema.StringAttribute{
				MarkdownDescription: "Custom CA certificate content for TLS verification. " +
					"Can be set via the `AD_TLS_CA_CERT` environment variable.",
				Optional:  true,
				Sensitive: true,
			},
			"tls_client_cert_file": schema.StringAttribute{
				MarkdownDescription: "Path to client certificate file for mutual TLS authentication. " +
					"Can be set via the `AD_TLS_CLIENT_CERT_FILE` environment variable.",
				Optional: true,
			},
			"tls_client_key_file": schema.StringAttribute{
				MarkdownDescription: "Path to client private key file for mutual TLS authentication. " +
					"Can be set via the `AD_TLS_CLIENT_KEY_FILE` environment variable.",
				Optional:  true,
				Sensitive: true,
			},

			// Connection pool settings
			"max_connections": schema.Int64Attribute{
				MarkdownDescription: "Maximum number of connections in the connection pool. Defaults to `10`. " +
					"Valid range: 1–100. " +
					"Can be set via the `AD_MAX_CONNECTIONS` environment variable.",
				Optional: true,
				Validators: []validator.Int64{
					int64validator.Between(minMaxConnections, int64(ldapclient.MaxConnectionPoolLimit)),
				},
			},
			"max_idle_time": schema.Int64Attribute{
				MarkdownDescription: "Maximum idle time for connections in seconds. Defaults to `300` (5 minutes). " +
					"Valid range: 1–2147483647 seconds. " +
					"Can be set via the `AD_MAX_IDLE_TIME` environment variable.",
				Optional: true,
				Validators: []validator.Int64{
					int64validator.Between(minMaxIdleTime, math.MaxInt32),
				},
			},
			"connect_timeout": schema.Int64Attribute{
				MarkdownDescription: "Connection timeout in seconds. Defaults to `30`. " +
					"Valid range: 1–2147483647 seconds. " +
					"Can be set via the `AD_CONNECT_TIMEOUT` environment variable.",
				Optional: true,
				Validators: []validator.Int64{
					int64validator.Between(minConnectTimeout, math.MaxInt32),
				},
			},

			// Retry settings
			"max_retries": schema.Int64Attribute{
				MarkdownDescription: "Maximum number of retry attempts for failed operations. Defaults to `3`. " +
					"Valid range: 0–2147483647. " +
					"Can be set via the `AD_MAX_RETRIES` environment variable.",
				Optional: true,
				Validators: []validator.Int64{
					int64validator.Between(minMaxRetries, math.MaxInt32),
				},
			},
			"initial_backoff": schema.Int64Attribute{
				MarkdownDescription: "Initial backoff delay in milliseconds for retry attempts. Defaults to `500`. " +
					"Valid range: 1–2147483647 milliseconds. " +
					"Can be set via the `AD_INITIAL_BACKOFF` environment variable.",
				Optional: true,
				Validators: []validator.Int64{
					int64validator.Between(minInitialBackoff, math.MaxInt32),
				},
			},
			"max_backoff": schema.Int64Attribute{
				MarkdownDescription: "Maximum backoff delay in seconds for retry attempts. Defaults to `30`. " +
					"Valid range: 1–2147483647 seconds. " +
					"Can be set via the `AD_MAX_BACKOFF` environment variable.",
				Optional: true,
				Validators: []validator.Int64{
					int64validator.Between(minMaxBackoff, math.MaxInt32),
				},
			},

			// Cache settings
			"warm_cache": schema.BoolAttribute{
				MarkdownDescription: "Pre-populate cache with all users and groups on provider initialization. " +
					"Significantly improves performance for large group memberships. Defaults to `false`. " +
					"Can be set via the `AD_WARM_CACHE` environment variable.",
				Optional: true,
			},
		},
	}
}

// ConfigValidators implements provider.ProviderWithConfigValidators.
func (p *ActiveDirectoryProvider) ConfigValidators(ctx context.Context) []provider.ConfigValidator {
	return []provider.ConfigValidator{
		// Domain and ldap_url are mutually exclusive
		providervalidator.Conflicting(
			path.MatchRoot("domain"),
			path.MatchRoot("ldap_url"),
		),
		// At least one connection method must be specified
		providervalidator.AtLeastOneOf(
			path.MatchRoot("domain"),
			path.MatchRoot("ldap_url"),
		),
		// TLS cert file and cert content are mutually exclusive
		providervalidator.Conflicting(
			path.MatchRoot("tls_ca_cert_file"),
			path.MatchRoot("tls_ca_cert"),
		),
	}
}

func (p *ActiveDirectoryProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data ActiveDirectoryProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Configure logging subsystems and set up provider context
	ctx = p.configureLogging(ctx)

	// Log provider initialization
	tflog.Info(ctx, "Configuring Active Directory provider", map[string]any{
		"version": p.Version,
	})

	// Build configuration from provider config and environment variables
	config := p.buildLDAPConfig(&data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create LDAP client with logging context
	start := time.Now()
	client, err := ldapclient.NewClient(ctx, config)
	if err != nil {
		tflog.Error(ctx, "Failed to create LDAP client", map[string]any{
			"error":       err.Error(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
		resp.Diagnostics.AddError(
			"Unable to Create LDAP Client",
			"An unexpected error occurred when creating the LDAP client. "+
				"If the error is not clear, please contact the provider developers.\n\n"+
				"LDAP Client Error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "LDAP client created successfully", map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
	})

	// Test connection
	start = time.Now()
	if err := client.Connect(ctx); err != nil {
		tflog.Error(ctx, "Connection test failed", map[string]any{
			"error":       err.Error(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
		resp.Diagnostics.AddError(
			"Unable to Connect to Active Directory",
			"The provider could not establish a connection to Active Directory. "+
				"Please verify your configuration settings.\n\n"+
				"Connection Error: "+err.Error(),
		)
		return
	}

	tflog.Info(ctx, "Connection established successfully", map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
	})

	// Test authentication
	start = time.Now()
	if err := client.BindWithConfig(ctx); err != nil {
		tflog.Error(ctx, "Authentication test failed", map[string]any{
			"error":       err.Error(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
		resp.Diagnostics.AddError(
			"Authentication Failed",
			"The provider could not authenticate with Active Directory. "+
				"Please verify your authentication credentials and settings.\n\n"+
				"Authentication Error: "+err.Error(),
		)
		return
	}

	tflog.Info(ctx, "Authentication successful", map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
	})

	// Initialize cache manager
	p.cacheManager = ldapclient.NewCacheManager()

	// Check if cache warming is enabled
	warmCache := p.getBoolValue(data.WarmCache, "AD_WARM_CACHE", false)
	if warmCache {
		tflog.Info(ctx, "Cache warming enabled, starting cache warming operation")

		// Get base DN for cache warming
		baseDN, err := client.GetBaseDN(ctx)
		if err != nil {
			tflog.Warn(ctx, "Could not determine base DN for cache warming, will attempt with configured base DN", map[string]any{
				"error": err.Error(),
			})
			baseDN = config.BaseDN // Use configured base DN as fallback
		}

		if baseDN == "" {
			tflog.Warn(ctx, "No base DN available for cache warming, skipping cache warming")
		} else {
			// Perform cache warming with progress logging
			start = time.Now()
			if err := p.cacheManager.WarmCache(ctx, client, baseDN); err != nil {
				tflog.Error(ctx, "Cache warming failed but will continue", map[string]any{
					"error":       err.Error(),
					"duration_ms": time.Since(start).Milliseconds(),
				})
				// Add warning diagnostic but don't fail provider initialization
				resp.Diagnostics.AddWarning(
					"Cache Warming Failed",
					"Cache warming was enabled but failed to complete successfully. "+
						"The provider will function normally but performance may be reduced. "+
						"Cache Warming Error: "+err.Error(),
				)
			} else {
				stats := p.cacheManager.GetStats()
				tflog.Info(ctx, "Cache warming completed successfully", map[string]any{
					"duration_ms":    time.Since(start).Milliseconds(),
					"entries_cached": stats.Entries,
					"base_dn":        baseDN,
				})
			}
		}
	} else {
		tflog.Debug(ctx, "Cache warming disabled")
	}

	tflog.Info(ctx, "Active Directory provider configured successfully")

	// Create provider data wrapper with both client and cache manager
	providerData := ldapclient.NewProviderData(client, p.cacheManager)

	// Make provider data available to resources and data sources
	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

// configureLogging sets up logging configuration based on environment variables.
func (p *ActiveDirectoryProvider) configureLogging(ctx context.Context) context.Context {
	// Add persistent fields for all logs
	ctx = tflog.SetField(ctx, "provider", "ad")
	ctx = tflog.SetField(ctx, "provider_version", p.Version)

	tflog.Debug(ctx, "Active Directory provider logging configured")

	return ctx
}

// buildLDAPConfig constructs the LDAP client configuration from provider config and environment variables.
func (p *ActiveDirectoryProvider) buildLDAPConfig(data *ActiveDirectoryProviderModel, diags *diag.Diagnostics) *ldapclient.ConnectionConfig {
	config := ldapclient.DefaultConfig()

	// Connection settings
	if domain := p.getStringValue(data.Domain, "AD_DOMAIN"); domain != "" {
		config.Domain = domain
	}

	if ldapURL := p.getStringValue(data.LdapURL, "AD_LDAP_URL"); ldapURL != "" {
		config.LDAPURLs = []string{ldapURL}
	}

	if baseDN := p.getStringValue(data.BaseDN, "AD_BASE_DN"); baseDN != "" {
		config.BaseDN = baseDN
	}

	// Authentication settings - validate that we have credentials
	username := p.getStringValue(data.Username, "AD_USERNAME", "AD_USER")
	password := p.getStringValue(data.Password, "AD_PASSWORD")
	kerberosRealm := p.getStringValue(data.KerberosRealm, "AD_KERBEROS_REALM")
	kerberosKeytab := p.getStringValue(data.KerberosKeytab, "AD_KERBEROS_KEYTAB")
	kerberosConfig := p.getStringValue(data.KerberosConfig, "AD_KERBEROS_CONFIG")
	kerberosCCache := p.getStringValue(data.KerberosCCache, "AD_KERBEROS_CCACHE")
	kerberosSPN := p.getStringValue(data.KerberosSPN, "AD_KERBEROS_SPN")

	// Check that we have some form of authentication
	hasPasswordAuth := username != "" && password != ""
	hasKerberosAuth := kerberosRealm != ""

	if !hasPasswordAuth && !hasKerberosAuth {
		diags.AddError(
			"Missing Authentication Configuration",
			"Either username/password authentication or Kerberos authentication must be configured. "+
				"For username/password: provide 'username' and 'password' attributes or set AD_USERNAME|AD_USER and AD_PASSWORD environment variables. "+
				"For Kerberos: provide 'kerberos_realm' and optionally 'username'/'password' (for password auth), 'kerberos_keytab' (for keytab auth), or 'kerberos_ccache' (for credential cache auth).",
		)
		return config
	}

	// Set authentication fields in ConnectionConfig
	config.Username = username
	config.Password = password
	config.KerberosRealm = kerberosRealm
	config.KerberosKeytab = kerberosKeytab
	config.KerberosConfig = kerberosConfig
	config.KerberosCCache = kerberosCCache
	config.KerberosSPN = kerberosSPN

	// Set Kerberos DNS lookup settings
	config.KerberosDNSLookupKDC = p.getBoolValue(data.KerberosDNSLookupKDC, "AD_KERBEROS_DNS_LOOKUP_KDC", false)
	config.KerberosDNSLookupRealm = p.getBoolValue(data.KerberosDNSLookupRealm, "AD_KERBEROS_DNS_LOOKUP_REALM", false)

	// If using auto-discovery (realm set but no config), enable DNS lookups by default
	if kerberosRealm != "" && kerberosConfig == "" {
		if data.KerberosDNSLookupKDC.IsNull() { // Only set default if not explicitly configured
			config.KerberosDNSLookupKDC = true
		}
		if data.KerberosDNSLookupRealm.IsNull() { // Only set default if not explicitly configured
			config.KerberosDNSLookupRealm = true
		}
	}

	// TLS settings
	if useTLS := p.getBoolValue(data.UseTLS, "AD_USE_TLS", true); !useTLS {
		config.UseTLS = false
	}

	if skipTLSVerify := p.getBoolValue(data.SkipTLSVerify, "AD_SKIP_TLS_VERIFY", false); skipTLSVerify {
		if config.TLSConfig == nil {
			config.TLSConfig = &tls.Config{}
		}
		config.TLSConfig.InsecureSkipVerify = true
	}

	// Set TLS certificate fields in ConnectionConfig
	config.TLSCACertFile = p.getStringValue(data.TLSCACertFile, "AD_TLS_CA_CERT_FILE")
	config.TLSCACert = p.getStringValue(data.TLSCACert, "AD_TLS_CA_CERT")
	config.TLSClientCertFile = p.getStringValue(data.TLSClientCertFile, "AD_TLS_CLIENT_CERT_FILE")
	config.TLSClientKeyFile = p.getStringValue(data.TLSClientKeyFile, "AD_TLS_CLIENT_KEY_FILE")

	// Connection pool settings
	config.MaxConnections = p.getIntBounded(data.MaxConnections, "AD_MAX_CONNECTIONS", "max_connections",
		defaultMaxConnections, minMaxConnections, int64(ldapclient.MaxConnectionPoolLimit), diags)

	config.MaxIdleTime = time.Duration(p.getInt64Bounded(data.MaxIdleTime, "AD_MAX_IDLE_TIME", "max_idle_time",
		defaultMaxIdleTime, minMaxIdleTime, math.MaxInt32, diags)) * time.Second

	config.Timeout = time.Duration(p.getInt64Bounded(data.ConnectTimeout, "AD_CONNECT_TIMEOUT", "connect_timeout",
		defaultConnectTimeout, minConnectTimeout, math.MaxInt32, diags)) * time.Second

	// Retry settings
	config.MaxRetries = p.getIntBounded(data.MaxRetries, "AD_MAX_RETRIES", "max_retries",
		defaultMaxRetries, minMaxRetries, math.MaxInt32, diags)

	config.InitialBackoff = time.Duration(p.getInt64Bounded(data.InitialBackoff, "AD_INITIAL_BACKOFF", "initial_backoff",
		defaultInitialBackoff, minInitialBackoff, math.MaxInt32, diags)) * time.Millisecond

	config.MaxBackoff = time.Duration(p.getInt64Bounded(data.MaxBackoff, "AD_MAX_BACKOFF", "max_backoff",
		defaultMaxBackoff, minMaxBackoff, math.MaxInt32, diags)) * time.Second

	return config
}

// Helper functions for configuration value resolution

func (p *ActiveDirectoryProvider) getStringValue(configValue types.String, envVars ...string) string {
	if !configValue.IsNull() && configValue.ValueString() != "" {
		return configValue.ValueString()
	}

	// Check environment variables in order, return first non-empty value
	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			return value
		}
	}

	return ""
}

func (p *ActiveDirectoryProvider) getBoolValue(configValue types.Bool, envVar string, defaultValue bool) bool {
	if !configValue.IsNull() {
		return configValue.ValueBool()
	}
	if envValue := os.Getenv(envVar); envValue != "" {
		if parsed, err := strconv.ParseBool(envValue); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func (p *ActiveDirectoryProvider) getInt64Value(configValue types.Int64, envVar string, defaultValue int64) int64 {
	if !configValue.IsNull() {
		return configValue.ValueInt64()
	}
	if envValue := os.Getenv(envVar); envValue != "" {
		if parsed, err := strconv.ParseInt(envValue, 10, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// Per-field defaults and lower bounds for the provider's numeric configuration
// attributes. Schema validators (Int64Attribute.Validators) and runtime helpers
// (getInt64Bounded / getIntBounded) read these so the bounds are declared once.
// Upper bounds use math.MaxInt32 for duration fields (platform safety; also
// prevents time.Duration overflow when multiplied by time.Second/Millisecond)
// and ldapclient.MaxConnectionPoolLimit for max_connections (domain policy).
const (
	defaultMaxConnections = 10
	minMaxConnections     = 1

	defaultMaxIdleTime = 300
	minMaxIdleTime     = 1

	defaultConnectTimeout = 30
	minConnectTimeout     = 1

	defaultMaxRetries = 3
	minMaxRetries     = 0

	defaultInitialBackoff = 500
	minInitialBackoff     = 1

	defaultMaxBackoff = 30
	minMaxBackoff     = 1
)

// getInt64Bounded resolves a configuration value as int64 from schema, env-var,
// or default, then validates the result is within [min, max]. On out-of-range
// it adds a configuration error to diags naming the attribute, env var, value,
// and supported range, then returns defaultValue. The caller is expected to
// abort configuration on any diagnostic error before the returned value is
// consumed (Configure exits early via resp.Diagnostics.HasError()).
func (p *ActiveDirectoryProvider) getInt64Bounded(configValue types.Int64, envVar, fieldName string, defaultValue, lo, hi int64, diags *diag.Diagnostics) int64 {
	v := p.getInt64Value(configValue, envVar, defaultValue)
	if v < lo || v > hi {
		diags.AddError(
			fmt.Sprintf("%s value out of range", fieldName),
			fmt.Sprintf("Value %d for %s (or %s) is outside the supported range [%d, %d].",
				v, fieldName, envVar, lo, hi),
		)
		return defaultValue
	}
	return v
}

// getIntBounded is getInt64Bounded plus a platform-narrowing guard that makes
// the returned int safe on 32-bit Go targets. The in-function comparison
// against math.MaxInt32 / math.MinInt32 is the standard CodeQL
// `go/incorrect-integer-conversion` sanitizer pattern. The guard is
// unreachable when callers pass max <= math.MaxInt32 (which all current
// callers do); it remains for static-analysis safety.
func (p *ActiveDirectoryProvider) getIntBounded(configValue types.Int64, envVar, fieldName string, defaultValue int, lo, hi int64, diags *diag.Diagnostics) int {
	v := p.getInt64Bounded(configValue, envVar, fieldName, int64(defaultValue), lo, hi, diags)
	if v > math.MaxInt32 || v < math.MinInt32 {
		return defaultValue
	}
	return int(v)
}

func (p *ActiveDirectoryProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewGroupResource,
		NewGroupMembershipResource,
		NewOUResource,
		NewUserResource,
	}
}

func (p *ActiveDirectoryProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		// No ephemeral resources defined yet
	}
}

func (p *ActiveDirectoryProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewGroupDataSource,
		NewGroupsDataSource,
		NewOUDataSource,
		NewRootDSEDataSource,
		NewUserDataSource,
		NewUsersDataSource,
		NewWhoAmIDataSource,
	}
}

func (p *ActiveDirectoryProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{
		NewBuildHierarchyFunction,
		NewNormalizeRolesFunction,
	}
}

// New returns a factory function for creating new ActiveDirectoryProvider instances.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &ActiveDirectoryProvider{
			Version:      version,
			cacheManager: nil, // Will be initialized during Configure()
		}
	}
}
