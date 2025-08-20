package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
)

// testAccProtoV6ProviderFactories is used to instantiate a provider during acceptance testing.
// The factory function is called for each Terraform CLI command to create a provider
// server that the CLI can connect to and interact with.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"ad": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccProtoV6ProviderFactoriesWithEcho includes the echo provider alongside the AD provider.
// It allows for testing assertions on data returned by an ephemeral resource during Open.
// The echoprovider is used to arrange tests by echoing ephemeral data into the Terraform state.
// This lets the data be referenced in test assertions with state checks.
var testAccProtoV6ProviderFactoriesWithEcho = map[string]func() (tfprotov6.ProviderServer, error){
	"ad":   providerserver.NewProtocol6WithError(New("test")()),
	"echo": echoprovider.NewProviderServer(),
}

func testAccPreCheck(t *testing.T) {
	// You can add code here to run prior to any test case execution, for example assertions
	// about the appropriate environment variables being set are common to see in a pre-check
	// function.

	// For AD provider acceptance tests, we would check for:
	// - AD_DOMAIN or AD_LDAP_URL
	// - AD_USERNAME and AD_PASSWORD (or Kerberos settings)
	//
	// For now, we skip acceptance tests since they require a real AD server
	t.Skip("Skipping acceptance test - requires Active Directory server configuration")
}

// TestAccProvider_Domain tests domain-based configuration.
func TestAccProvider_Domain(t *testing.T) {
	// This test would verify domain-based SRV discovery configuration
	// It requires a real AD environment for full testing
	testAccPreCheck(t)
}

// TestAccProvider_LDAPURL tests direct LDAP URL configuration.
func TestAccProvider_LDAPURL(t *testing.T) {
	// This test would verify direct LDAP URL configuration
	// It requires a real AD environment for full testing
	testAccPreCheck(t)
}

// TestAccProvider_ConfigValidation tests configuration validation.
func TestAccProvider_ConfigValidation(t *testing.T) {
	// This test would verify the ConfigValidators work correctly
	// For now, unit tests of individual validators would be more appropriate
	testAccPreCheck(t)
}
