package provider

import (
	"context"
	"crypto/tls"
	"os"
	"strconv"
	"time"

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
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version      string
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
	KerberosRealm  types.String `tfsdk:"kerberos_realm"`
	KerberosKeytab types.String `tfsdk:"kerberos_keytab"`
	KerberosConfig types.String `tfsdk:"kerberos_config"`
	KerberosCCache types.String `tfsdk:"kerberos_ccache"`
	KerberosSPN    types.String `tfsdk:"kerberos_spn"`

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

func (p *ActiveDirectoryProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ad"
	resp.Version = p.version
}

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
					"Can be set via the `AD_USERNAME` environment variable.",
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
				MarkdownDescription: "Path to Kerberos configuration file. Defaults to system default. " +
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
					"Can be set via the `AD_MAX_CONNECTIONS` environment variable.",
				Optional: true,
			},
			"max_idle_time": schema.Int64Attribute{
				MarkdownDescription: "Maximum idle time for connections in seconds. Defaults to `300` (5 minutes). " +
					"Can be set via the `AD_MAX_IDLE_TIME` environment variable.",
				Optional: true,
			},
			"connect_timeout": schema.Int64Attribute{
				MarkdownDescription: "Connection timeout in seconds. Defaults to `30`. " +
					"Can be set via the `AD_CONNECT_TIMEOUT` environment variable.",
				Optional: true,
			},

			// Retry settings
			"max_retries": schema.Int64Attribute{
				MarkdownDescription: "Maximum number of retry attempts for failed operations. Defaults to `3`. " +
					"Can be set via the `AD_MAX_RETRIES` environment variable.",
				Optional: true,
			},
			"initial_backoff": schema.Int64Attribute{
				MarkdownDescription: "Initial backoff delay in milliseconds for retry attempts. Defaults to `500`. " +
					"Can be set via the `AD_INITIAL_BACKOFF` environment variable.",
				Optional: true,
			},
			"max_backoff": schema.Int64Attribute{
				MarkdownDescription: "Maximum backoff delay in seconds for retry attempts. Defaults to `30`. " +
					"Can be set via the `AD_MAX_BACKOFF` environment variable.",
				Optional: true,
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
		"version": p.version,
	})

	// Build configuration from provider config and environment variables
	config := p.buildLDAPConfig(&data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create LDAP client with logging context
	start := time.Now()
	client, err := ldapclient.NewClientWithContext(ctx, config)
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
	ctx = tflog.SetField(ctx, "provider_version", p.version)

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
	username := p.getStringValue(data.Username, "AD_USERNAME")
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
				"For username/password: provide 'username' and 'password' attributes or set AD_USERNAME and AD_PASSWORD environment variables. "+
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
	if maxConnections := p.getInt64Value(data.MaxConnections, "AD_MAX_CONNECTIONS", 10); maxConnections > 0 {
		config.MaxConnections = int(maxConnections)
	}

	if maxIdleTime := p.getInt64Value(data.MaxIdleTime, "AD_MAX_IDLE_TIME", 300); maxIdleTime > 0 {
		config.MaxIdleTime = time.Duration(maxIdleTime) * time.Second
	}

	if connectTimeout := p.getInt64Value(data.ConnectTimeout, "AD_CONNECT_TIMEOUT", 30); connectTimeout > 0 {
		config.Timeout = time.Duration(connectTimeout) * time.Second
	}

	// Retry settings
	if maxRetries := p.getInt64Value(data.MaxRetries, "AD_MAX_RETRIES", 3); maxRetries >= 0 {
		config.MaxRetries = int(maxRetries)
	}

	if initialBackoff := p.getInt64Value(data.InitialBackoff, "AD_INITIAL_BACKOFF", 500); initialBackoff > 0 {
		config.InitialBackoff = time.Duration(initialBackoff) * time.Millisecond
	}

	if maxBackoff := p.getInt64Value(data.MaxBackoff, "AD_MAX_BACKOFF", 30); maxBackoff > 0 {
		config.MaxBackoff = time.Duration(maxBackoff) * time.Second
	}

	return config
}

// Helper functions for configuration value resolution

func (p *ActiveDirectoryProvider) getStringValue(configValue types.String, envVar string) string {
	if !configValue.IsNull() && configValue.ValueString() != "" {
		return configValue.ValueString()
	}
	return os.Getenv(envVar)
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

func (p *ActiveDirectoryProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewGroupResource,
		NewGroupMembershipResource,
		NewOUResource,
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
		NewUserDataSource,
		NewUsersDataSource,
		NewWhoAmIDataSource,
	}
}

func (p *ActiveDirectoryProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{
		// No provider functions defined yet
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &ActiveDirectoryProvider{
			version:      version,
			cacheManager: nil, // Will be initialized during Configure()
		}
	}
}
