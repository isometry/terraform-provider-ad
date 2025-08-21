package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories is used to instantiate a provider during acceptance testing.
// The factory function is called for each Terraform CLI command to create a provider
// server that the CLI can connect to and interact with.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"ad": providerserver.NewProtocol6WithError(New("test")()),
}

func testAccPreCheck(t *testing.T) {
	testAccPreCheckWithConfig(t)
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
