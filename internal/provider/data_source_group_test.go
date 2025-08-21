package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccGroupDataSource_ByID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing by objectGUID
			{
				Config: testAccGroupDataSourceConfig_ByID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_group.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "display_name"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "distinguished_name"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "scope"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "category"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "group_type"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "member_count"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "members"),
					// Test specific expected values
					resource.TestCheckResourceAttr("data.ad_group.test", "display_name", "TestGroup"),
					resource.TestCheckResourceAttr("data.ad_group.test", "description", "Test group for data source"),
					resource.TestCheckResourceAttr("data.ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("data.ad_group.test", "category", "Security"),
				),
			},
		},
	})
}

func TestAccGroupDataSource_ByDN(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing by Distinguished Name
			{
				Config: testAccGroupDataSourceConfig_ByDN(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_group.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "display_name"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "distinguished_name"),
					resource.TestCheckResourceAttr("data.ad_group.test", "display_name", "TestGroup"),
					resource.TestCheckResourceAttr("data.ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("data.ad_group.test", "category", "Security"),
				),
			},
		},
	})
}

func TestAccGroupDataSource_ByName(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing by name and container
			{
				Config: testAccGroupDataSourceConfig_ByName(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_group.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "display_name"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "distinguished_name"),
					resource.TestCheckResourceAttr("data.ad_group.test", "display_name", "TestGroup"),
					resource.TestCheckResourceAttr("data.ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("data.ad_group.test", "category", "Security"),
				),
			},
		},
	})
}

func TestAccGroupDataSource_BySAMAccountName(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing by SAM account name
			{
				Config: testAccGroupDataSourceConfig_BySAMAccountName(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_group.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "display_name"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "distinguished_name"),
					resource.TestCheckResourceAttr("data.ad_group.test", "display_name", "TestGroup"),
					resource.TestCheckResourceAttr("data.ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("data.ad_group.test", "category", "Security"),
				),
			},
		},
	})
}

func TestAccGroupDataSource_WithMembers(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create a group with members, then read it
			{
				Config: testAccGroupDataSourceConfig_WithMembers(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_group.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "display_name"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "members"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "member_count"),
					// Check that we have at least one member
					resource.TestCheckResourceAttrWith("data.ad_group.test", "member_count", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected member_count to be greater than 0, got %s", value)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccGroupDataSource_ValidationErrors(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test that multiple lookup methods cause validation error
			{
				Config:      testAccGroupDataSourceConfig_MultipleLookupMethods(),
				ExpectError: regexp.MustCompile(`Exactly one of these attributes must be configured`),
			},
			// Test that no lookup method causes validation error
			{
				Config:      testAccGroupDataSourceConfig_NoLookupMethod(),
				ExpectError: regexp.MustCompile(`Exactly one of these attributes must be configured`),
			},
			// Test that name without container causes validation error
			{
				Config:      testAccGroupDataSourceConfig_NameWithoutContainer(),
				ExpectError: regexp.MustCompile(`These attributes must be configured together`),
			},
			// Test that container without name causes validation error
			{
				Config:      testAccGroupDataSourceConfig_ContainerWithoutName(),
				ExpectError: regexp.MustCompile(`These attributes must be configured together`),
			},
		},
	})
}

func TestAccGroupDataSource_NotFound(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test non-existent group by GUID
			{
				Config:      testAccGroupDataSourceConfig_NotFoundByID(),
				ExpectError: regexp.MustCompile(`Group Not Found|not found`),
			},
			// Test non-existent group by DN
			{
				Config:      testAccGroupDataSourceConfig_NotFoundByDN(),
				ExpectError: regexp.MustCompile(`Group Not Found|not found`),
			},
			// Test non-existent group by SAM account name
			{
				Config:      testAccGroupDataSourceConfig_NotFoundBySAM(),
				ExpectError: regexp.MustCompile(`Group Not Found|not found`),
			},
		},
	})
}

// Test configuration functions

func testAccGroupDataSourceConfig_ByID() string {
	return fmt.Sprintf(`
%s

resource "ad_group" "test" {
  name               = "TestGroup"
  sam_account_name   = "TestGroup"
  container          = "CN=Users,${data.ad_domain.test.distinguished_name}"
  scope              = "Global"
  category           = "Security"
  description        = "Test group for data source"
}

data "ad_group" "test" {
  id = ad_group.test.id
}
`, testAccProviderConfig())
}

func testAccGroupDataSourceConfig_ByDN() string {
	return fmt.Sprintf(`
%s

resource "ad_group" "test" {
  name               = "TestGroup"
  sam_account_name   = "TestGroup"
  container          = "CN=Users,${data.ad_domain.test.distinguished_name}"
  scope              = "Global"
  category           = "Security"
  description        = "Test group for data source"
}

data "ad_group" "test" {
  dn = ad_group.test.distinguished_name
}
`, testAccProviderConfig())
}

func testAccGroupDataSourceConfig_ByName() string {
	return fmt.Sprintf(`
%s

resource "ad_group" "test" {
  name               = "TestGroup"
  sam_account_name   = "TestGroup"
  container          = "CN=Users,${data.ad_domain.test.distinguished_name}"
  scope              = "Global"
  category           = "Security"
  description        = "Test group for data source"
}

data "ad_group" "test" {
  name      = ad_group.test.name
  container = ad_group.test.container
}
`, testAccProviderConfig())
}

func testAccGroupDataSourceConfig_BySAMAccountName() string {
	return fmt.Sprintf(`
%s

resource "ad_group" "test" {
  name               = "TestGroup"
  sam_account_name   = "TestGroup"
  container          = "CN=Users,${data.ad_domain.test.distinguished_name}"
  scope              = "Global"
  category           = "Security"
  description        = "Test group for data source"
}

data "ad_group" "test" {
  sam_account_name = ad_group.test.sam_account_name
}
`, testAccProviderConfig())
}

func testAccGroupDataSourceConfig_WithMembers() string {
	return fmt.Sprintf(`
%s

# Create a test group
resource "ad_group" "test" {
  name               = "TestGroupWithMembers"
  sam_account_name   = "TestGroupWithMembers"
  container          = "CN=Users,${data.ad_domain.test.distinguished_name}"
  scope              = "Global"
  category           = "Security"
  description        = "Test group with members for data source"
}

# Create another group to use as a member
resource "ad_group" "member" {
  name               = "TestMemberGroup"
  sam_account_name   = "TestMemberGroup"
  container          = "CN=Users,${data.ad_domain.test.distinguished_name}"
  scope              = "Global"
  category           = "Security"
  description        = "Test member group"
}

# Add the member group to the test group
resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members  = [ad_group.member.distinguished_name]
}

# Read the group with members
data "ad_group" "test" {
  id = ad_group.test.id
  depends_on = [ad_group_membership.test]
}
`, testAccProviderConfig())
}

// Validation error test configurations

func testAccGroupDataSourceConfig_MultipleLookupMethods() string {
	return fmt.Sprintf(`
%s

data "ad_group" "test" {
  id = "550e8400-e29b-41d4-a716-446655440000"
  dn = "CN=TestGroup,CN=Users,DC=example,DC=com"
}
`, testAccProviderConfig())
}

func testAccGroupDataSourceConfig_NoLookupMethod() string {
	return fmt.Sprintf(`
%s

data "ad_group" "test" {
  # No lookup method specified
}
`, testAccProviderConfig())
}

func testAccGroupDataSourceConfig_NameWithoutContainer() string {
	return fmt.Sprintf(`
%s

data "ad_group" "test" {
  name = "TestGroup"
  # container not specified
}
`, testAccProviderConfig())
}

func testAccGroupDataSourceConfig_ContainerWithoutName() string {
	return fmt.Sprintf(`
%s

data "ad_group" "test" {
  container = "CN=Users,DC=example,DC=com"
  # name not specified
}
`, testAccProviderConfig())
}

// Not found test configurations

func testAccGroupDataSourceConfig_NotFoundByID() string {
	return fmt.Sprintf(`
%s

data "ad_group" "test" {
  id = "550e8400-e29b-41d4-a716-446655440000"  # Non-existent GUID
}
`, testAccProviderConfig())
}

func testAccGroupDataSourceConfig_NotFoundByDN() string {
	return fmt.Sprintf(`
%s

data "ad_group" "test" {
  dn = "CN=NonExistentGroup,CN=Users,${data.ad_domain.test.distinguished_name}"
}
`, testAccProviderConfig())
}

func testAccGroupDataSourceConfig_NotFoundBySAM() string {
	return fmt.Sprintf(`
%s

data "ad_group" "test" {
  sam_account_name = "NonExistentGroup"
}
`, testAccProviderConfig())
}

// Helper function to get provider configuration for tests.
func testAccProviderConfig() string {
	return `
provider "ad" {
  domain   = "example.com"
  username = "Administrator"
  password = "Password123!"
}

# Get domain information for building DNs
data "ad_domain" "test" {}
`
}
