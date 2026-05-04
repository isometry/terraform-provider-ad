package provider_test

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
			// Read testing by UPN
			{
				Config: testAccUserDataSourceConfig_createAndLookupByUPN(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.ad_user.test", "id", "ad_user.test", "id"),
					resource.TestCheckResourceAttrPair("data.ad_user.test", "dn", "ad_user.test", "dn"),
					resource.TestCheckResourceAttrPair("data.ad_user.test", "upn", "ad_user.test", "principal_name"),
					resource.TestCheckResourceAttrPair("data.ad_user.test", "sam_account_name", "ad_user.test", "sam_account_name"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_guid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "when_created"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "when_changed"),
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
				Config: testAccUserDataSourceConfig_createAndLookupByDN(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.ad_user.test", "id", "ad_user.test", "id"),
					resource.TestCheckResourceAttrPair("data.ad_user.test", "dn", "ad_user.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_guid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "upn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "sam_account_name"),
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
				Config: testAccUserDataSourceConfig_createAndLookupByGUID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.ad_user.test", "id", "ad_user.test", "id"),
					resource.TestCheckResourceAttrPair("data.ad_user.test", "object_guid", "ad_user.test", "id"),
					resource.TestCheckResourceAttrPair("data.ad_user.test", "dn", "ad_user.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "upn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "sam_account_name"),
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
				Config: testAccUserDataSourceConfig_createAndLookupBySAM(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.ad_user.test", "id", "ad_user.test", "id"),
					resource.TestCheckResourceAttrPair("data.ad_user.test", "sam_account_name", "ad_user.test", "sam_account_name"),
					resource.TestCheckResourceAttrPair("data.ad_user.test", "dn", "ad_user.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_guid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "upn"),
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
				Config: testAccUserDataSourceConfig_createAndLookupBySID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.ad_user.test", "id", "ad_user.test", "id"),
					resource.TestCheckResourceAttrPair("data.ad_user.test", "object_sid", "ad_user.test", "sid"),
					resource.TestCheckResourceAttrPair("data.ad_user.test", "dn", "ad_user.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_guid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "upn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "sam_account_name"),
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
				Config: testAccUserDataSourceConfig_createAndLookupByUPN(),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Core identity (always set by AD for a newly created user)
					resource.TestCheckResourceAttrSet("data.ad_user.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_guid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "object_sid"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "upn"),
					resource.TestCheckResourceAttrSet("data.ad_user.test", "sam_account_name"),

					// Group memberships (computed list/string attributes).
					resource.TestCheckResourceAttrSet("data.ad_user.test", "member_of.#"),
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

// testAccUserResourceForDataSource creates an ad_user that the data source tests can look up.
func testAccUserResourceForDataSource() string {
	return `
resource "ad_user" "test" {
  name             = "TestUserDS"
  principal_name   = "testuserds@${data.ad_rootdse.test.domain_name}"
  sam_account_name = "testuserds"
  container        = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  password         = "TestP4ssw0rd!Ds"
  enabled          = true
}
`
}

func testAccUserDataSourceConfig_createAndLookupByUPN() string {
	return fmt.Sprintf(`
%s

%s

%s

data "ad_user" "test" {
  upn = ad_user.test.principal_name
}
`, testProviderConfig(), testRootDSEDataSource(), testAccUserResourceForDataSource())
}

func testAccUserDataSourceConfig_createAndLookupByDN() string {
	return fmt.Sprintf(`
%s

%s

%s

data "ad_user" "test" {
  dn = ad_user.test.dn
}
`, testProviderConfig(), testRootDSEDataSource(), testAccUserResourceForDataSource())
}

func testAccUserDataSourceConfig_createAndLookupByGUID() string {
	return fmt.Sprintf(`
%s

%s

%s

data "ad_user" "test" {
  id = ad_user.test.id
}
`, testProviderConfig(), testRootDSEDataSource(), testAccUserResourceForDataSource())
}

func testAccUserDataSourceConfig_createAndLookupBySAM() string {
	return fmt.Sprintf(`
%s

%s

%s

data "ad_user" "test" {
  sam_account_name = ad_user.test.sam_account_name
}
`, testProviderConfig(), testRootDSEDataSource(), testAccUserResourceForDataSource())
}

func testAccUserDataSourceConfig_createAndLookupBySID() string {
	return fmt.Sprintf(`
%s

%s

%s

data "ad_user" "test" {
  sid = ad_user.test.sid
}
`, testProviderConfig(), testRootDSEDataSource(), testAccUserResourceForDataSource())
}

func testAccUserDataSourceConfig_noLookupMethod() string {
	return fmt.Sprintf(`
%s

data "ad_user" "test" {
}
`, testProviderConfig())
}

func testAccUserDataSourceConfig_multipleLookupMethods() string {
	return fmt.Sprintf(`
%s

data "ad_user" "test" {
  upn              = "test@example.com"
  sam_account_name = "test"
}
`, testProviderConfig())
}
