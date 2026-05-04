package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestProviderConfigure_MaxConnectionsRejectsZero exercises the full plan-time
// path: schema parse → validator invocation → diagnostic propagation. A
// representative test for the `int64validator.Between(...)` constraints added
// to the six provider-config Int64 attributes; the wiring tests in
// provider_internal_test.go cover the other five attributes.
//
// Uses resource.UnitTest so the case runs without TF_ACC=1 and without a real
// Active Directory; the validator rejects the value before Configure attempts
// to bind, so no network is needed.
func TestProviderConfigure_MaxConnectionsRejectsZero(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "ad" {
  domain          = "example.com"
  max_connections = 0
}

data "ad_whoami" "test" {}
`,
				ExpectError: regexp.MustCompile(`max_connections.*(?s).*1.*100`),
			},
		},
	})
}

// TestProviderConfigure_MaxIdleTimeRejectsNegative verifies the duration
// validators also fire at plan time on the HCL path.
func TestProviderConfigure_MaxIdleTimeRejectsNegative(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "ad" {
  domain        = "example.com"
  max_idle_time = -1
}

data "ad_whoami" "test" {}
`,
				ExpectError: regexp.MustCompile(`max_idle_time`),
			},
		},
	})
}
