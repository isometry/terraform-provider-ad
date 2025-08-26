package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccUserDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccUserDataSourceConfig_byUPN("testuser@example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ad_user.test", "user_principal_name", "testuser@example.com"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_guid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "sam_account_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "display_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "when_created"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "when_changed"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "account_enabled"),
				),
			},
		},
	})
}

func TestAccUserDataSource_byDN(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserDataSourceConfig_byDN("CN=Test User,CN=Users,DC=example,DC=com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ad_user.test", "dn", "CN=Test User,CN=Users,DC=example,DC=com"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_guid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "user_principal_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "sam_account_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "display_name"),
				),
			},
		},
	})
}

func TestAccUserDataSource_byGUID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserDataSourceConfig_byGUID("550e8400-e29b-41d4-a716-446655440000"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ad_user.test", "object_guid", "550e8400-e29b-41d4-a716-446655440000"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "user_principal_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "sam_account_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "display_name"),
				),
			},
		},
	})
}

func TestAccUserDataSource_bySAM(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserDataSourceConfig_bySAM("testuser"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ad_user.test", "sam_account_name", "testuser"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_guid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "user_principal_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "display_name"),
				),
			},
		},
	})
}

func TestAccUserDataSource_bySID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserDataSourceConfig_bySID("S-1-5-21-123456789-123456789-123456789-1001"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ad_user.test", "object_sid", "S-1-5-21-123456789-123456789-123456789-1001"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_guid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "user_principal_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "sam_account_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "display_name"),
				),
			},
		},
	})
}

func TestAccUserDataSource_allAttributes(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserDataSourceConfig_byUPN("fulluser@example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Core identity
					resource.TestCheckResourceAttrSet("data.ad_user.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_guid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_sid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "dn"),
					resource.TestCheckResourceAttr("data.ad_user.test", "user_principal_name", "fulluser@example.com"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "sam_account_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "display_name"),

					// Contact information (may be empty for test users)
					resource.TestCheckResourceAttrSet("data.ad_user.test", "email_address"),

					// Organizational information (may be empty for test users)
					resource.TestCheckResourceAttrSet("data.ad_user.test", "title"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "department"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "company"),

					// Account status
					resource.TestCheckResourceAttrSet("data.ad_user.test", "account_enabled"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "password_never_expires"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "password_not_required"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "change_password_at_logon"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "cannot_change_password"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "smart_card_logon_required"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "trusted_for_delegation"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "account_locked_out"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "user_account_control"),

					// Group memberships
					resource.TestCheckResourceAttrSet("data.ad_user.test", "member_of"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "primary_group"),

					// Timestamps
					resource.TestCheckResourceAttrSet("data.ad_user.test", "when_created"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "when_changed"),
				),
			},
		},
	})
}

func TestAccUserDataSource_configValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test that exactly one lookup method is required
			{
				Config:      testAccUserDataSourceConfig_noLookupMethod(),
				ExpectError: regexp.MustCompile("Exactly one of these attributes must be configured"),
			},
			// Test that only one lookup method is allowed
			{
				Config:      testAccUserDataSourceConfig_multipleLookupMethods(),
				ExpectError: regexp.MustCompile("Exactly one of these attributes must be configured"),
			},
		},
	})
}

// Test configuration functions

func testAccUserDataSourceConfig_byUPN(upn string) string {
	return fmt.Sprintf(`
data "ad_user" "test" {
  user_principal_name = %[1]q
}
`, upn)
}

func testAccUserDataSourceConfig_byDN(dn string) string {
	return fmt.Sprintf(`
data "ad_user" "test" {
  dn = %[1]q
}
`, dn)
}

func testAccUserDataSourceConfig_byGUID(guid string) string {
	return fmt.Sprintf(`
data "ad_user" "test" {
  id = %[1]q
}
`, guid)
}

func testAccUserDataSourceConfig_bySAM(sam string) string {
	return fmt.Sprintf(`
data "ad_user" "test" {
  sam_account_name = %[1]q
}
`, sam)
}

func testAccUserDataSourceConfig_bySID(sid string) string {
	return fmt.Sprintf(`
data "ad_user" "test" {
  sid = %[1]q
}
`, sid)
}

func testAccUserDataSourceConfig_noLookupMethod() string {
	return `
data "ad_user" "test" {
}
`
}

func testAccUserDataSourceConfig_multipleLookupMethods() string {
	return `
data "ad_user" "test" {
  user_principal_name = "test@example.com"
  sam_account_name    = "test"
}
`
}
