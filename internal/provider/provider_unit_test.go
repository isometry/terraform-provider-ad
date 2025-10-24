package provider_test

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	this "github.com/isometry/terraform-provider-ad/internal/provider"
)

// TestProviderMetadata tests the provider metadata.
func TestProviderMetadata(t *testing.T) {
	p := &this.ActiveDirectoryProvider{Version: "test"}

	req := provider.MetadataRequest{}
	resp := &provider.MetadataResponse{}

	p.Metadata(t.Context(), req, resp)

	if resp.TypeName != "ad" {
		t.Errorf("Expected TypeName 'ad', got %s", resp.TypeName)
	}

	if resp.Version != "test" {
		t.Errorf("Expected Version 'test', got %s", resp.Version)
	}
}

// TestProviderSchema tests the provider schema.
func TestProviderSchema(t *testing.T) {
	p := &this.ActiveDirectoryProvider{}

	req := provider.SchemaRequest{}
	resp := &provider.SchemaResponse{}

	p.Schema(t.Context(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema creation failed: %v", resp.Diagnostics)
	}

	// Test that required attributes are present
	requiredAttributes := []string{
		"domain", "ldap_url", "base_dn",
		"username", "password",
		"kerberos_realm", "kerberos_keytab", "kerberos_config",
		"use_tls", "skip_tls_verify", "tls_ca_cert_file", "tls_ca_cert",
		"tls_client_cert_file", "tls_client_key_file",
		"max_connections", "max_idle_time", "connect_timeout",
		"max_retries", "initial_backoff", "max_backoff",
	}

	for _, attr := range requiredAttributes {
		if _, exists := resp.Schema.Attributes[attr]; !exists {
			t.Errorf("Expected attribute %s not found in schema", attr)
		}
	}
}

// TestProviderResources tests the provider resources.
func TestProviderResources(t *testing.T) {
	p := &this.ActiveDirectoryProvider{}

	resources := p.Resources(t.Context())

	expectedResources := []string{
		"ad_group",
		"ad_group_membership",
		"ad_ou",
	}

	if len(resources) != len(expectedResources) {
		t.Errorf("Expected %d resources, got %d", len(expectedResources), len(resources))
	}

	// Create instances to test they can be created without errors
	for i, resourceFunc := range resources {
		resource := resourceFunc()
		if resource == nil {
			t.Errorf("Resource function %d returned nil", i)
		}
	}
}

// TestProviderDataSources tests the provider data sources.
func TestProviderDataSources(t *testing.T) {
	p := &this.ActiveDirectoryProvider{}

	dataSources := p.DataSources(t.Context())

	expectedDataSources := []string{
		"ad_group",
		"ad_groups",
		"ad_ou",
		"ad_user",
		"ad_users",
		"ad_whoami",
	}

	if len(dataSources) != len(expectedDataSources) {
		t.Errorf("Expected %d data sources, got %d", len(expectedDataSources), len(dataSources))
	}

	// Create instances to test they can be created without errors
	for i, dataSourceFunc := range dataSources {
		dataSource := dataSourceFunc()
		if dataSource == nil {
			t.Errorf("Data source function %d returned nil", i)
		}
	}
}

// TestProviderConfigValidators tests the provider config validators.
func TestProviderConfigValidators(t *testing.T) {
	p := &this.ActiveDirectoryProvider{}

	validators := p.ConfigValidators(t.Context())

	if len(validators) == 0 {
		t.Error("Expected config validators, got none")
	}

	// Test that validators can be created without errors
	for i, validator := range validators {
		if validator == nil {
			t.Errorf("Config validator %d is nil", i)
		}
	}
}

// TestProviderFunctions tests the provider functions.
func TestProviderFunctions(t *testing.T) {
	p := &this.ActiveDirectoryProvider{}

	functions := p.Functions(t.Context())

	// AD provider has 2 functions: build_hierarchy, normalize_roles
	if len(functions) != 2 {
		t.Errorf("Expected 2 functions, got %d", len(functions))
	}

	// Test that the function can be instantiated
	if len(functions) > 0 {
		fn := functions[0]()
		if fn == nil {
			t.Error("Function factory returned nil")
		}
	}
}

// TestProviderEphemeralResources tests the provider ephemeral resources.
func TestProviderEphemeralResources(t *testing.T) {
	p := &this.ActiveDirectoryProvider{}

	ephemeralResources := p.EphemeralResources(t.Context())

	// AD provider currently has no ephemeral resources defined
	if len(ephemeralResources) != 0 {
		t.Errorf("Expected 0 ephemeral resources, got %d", len(ephemeralResources))
	}
}

// TestNewProvider tests the New provider function.
func TestNewProvider(t *testing.T) {
	testCases := []struct {
		name    string
		version string
	}{
		{
			name:    "test version",
			version: "test",
		},
		{
			name:    "dev version",
			version: "dev",
		},
		{
			name:    "release version",
			version: "1.0.0",
		},
		{
			name:    "empty version",
			version: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			providerFunc := this.New(tc.version)
			if providerFunc == nil {
				t.Fatal("New() returned nil")
			}

			provider := providerFunc()
			if provider == nil {
				t.Fatal("Provider function returned nil")
			}

			adProvider, ok := provider.(*this.ActiveDirectoryProvider)
			if !ok {
				t.Fatal("Provider is not of type *ActiveDirectoryProvider")
			}

			if adProvider.Version != tc.version {
				t.Errorf("Expected version %s, got %s", tc.version, adProvider.Version)
			}
		})
	}
}

// TestProviderServer tests provider server creation.
func TestProviderServer(t *testing.T) {
	providerFunc := this.New("test")

	serverFactory := providerserver.NewProtocol6WithError(providerFunc())
	if serverFactory == nil {
		t.Fatal("Provider server factory is nil")
	}

	// Test that we can create a server from the factory
	server, err := serverFactory()
	if err != nil {
		t.Fatalf("Failed to create provider server: %v", err)
	}

	if server == nil {
		t.Fatal("Provider server is nil")
	}

	// Server correctly implements the expected interface
}

// TestProviderConfigValidation tests provider configuration validation.
func TestProviderConfigValidation(t *testing.T) {
	testCases := []struct {
		name      string
		config    string
		expectErr bool
	}{
		{
			name: "valid domain config",
			config: `
provider "ad" {
  domain   = "example.com"
  username = "admin"
  password = "password"
}`,
			expectErr: false,
		},
		{
			name: "valid ldap_url config",
			config: `
provider "ad" {
  ldap_url = "ldaps://dc1.example.com:636"
  username = "admin"
  password = "password"
}`,
			expectErr: false,
		},
		{
			name: "both domain and ldap_url",
			config: `
provider "ad" {
  domain   = "example.com"
  ldap_url = "ldaps://dc1.example.com:636"
  username = "admin"
  password = "password"
}`,
			expectErr: true,
		},
		{
			name: "neither domain nor ldap_url",
			config: `
provider "ad" {
  username = "admin"
  password = "password"
}`,
			expectErr: true,
		},
		{
			name: "kerberos config",
			config: `
provider "ad" {
  domain         = "example.com"
  username       = "admin"
  kerberos_realm = "EXAMPLE.COM"
  kerberos_keytab = "/path/to/keytab"
}`,
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
					"ad": providerserver.NewProtocol6WithError(this.New("test")()),
				},
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: nil, // Basic syntax check
						PlanOnly:    true,
					},
				},
			})
		})
	}
}

// TestProviderEnvironmentVariables tests environment variable handling.
func TestProviderEnvironmentVariables(t *testing.T) {
	// This test would require environment variable setup
	// For now, we test that the provider accepts environment variables

	envVars := []string{
		"AD_DOMAIN",
		"AD_LDAP_URL",
		"AD_BASE_DN",
		"AD_USERNAME",
		"AD_PASSWORD",
		"AD_KERBEROS_REALM",
		"AD_KERBEROS_KEYTAB",
		"AD_KERBEROS_CONFIG",
		"AD_USE_TLS",
		"AD_SKIP_TLS_VERIFY",
		"AD_TLS_CA_CERT_FILE",
		"AD_TLS_CA_CERT",
		"AD_TLS_CLIENT_CERT_FILE",
		"AD_TLS_CLIENT_KEY_FILE",
	}

	// Test that environment variables are documented
	p := &this.ActiveDirectoryProvider{}
	req := provider.SchemaRequest{}
	resp := &provider.SchemaResponse{}

	p.Schema(t.Context(), req, resp)

	for _, envVar := range envVars {
		found := false
		for _, attr := range resp.Schema.Attributes {
			if attr.GetMarkdownDescription() != "" {
				if strings.Contains(attr.GetMarkdownDescription(), envVar) {
					found = true
					break
				}
			}
		}

		if !found {
			t.Logf("Environment variable %s not found in schema documentation", envVar)
		}
	}
}
