package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccUsersDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing - basic search without filters
			{
				Config: testAccUsersDataSourceConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
					// Verify we got at least one user
					resource.TestCheckResourceAttrWith("data.ad_users.test", "user_count", func(value string) error {
						if value == "0" {
							return fmt.Errorf("Expected at least one user, got 0")
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccUsersDataSource_withContainer(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUsersDataSourceConfig_withContainer("CN=Users,DC=example,DC=com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ad_users.test", "container", "CN=Users,DC=example,DC=com"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
		},
	})
}

func TestAccUsersDataSource_withScope(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUsersDataSourceConfig_withScope("onelevel"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ad_users.test", "scope", "onelevel"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
		},
	})
}

func TestAccUsersDataSource_nameFilters(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test name prefix filter
			{
				Config: testAccUsersDataSourceConfig_namePrefix("Admin"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
			// Test name suffix filter
			{
				Config: testAccUsersDataSourceConfig_nameSuffix("User"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
			// Test name contains filter
			{
				Config: testAccUsersDataSourceConfig_nameContains("test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
		},
	})
}

func TestAccUsersDataSource_organizationalFilters(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test department filter
			{
				Config: testAccUsersDataSourceConfig_department("IT"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
			// Test title filter
			{
				Config: testAccUsersDataSourceConfig_title("Manager"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
		},
	})
}

func TestAccUsersDataSource_statusFilters(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test enabled accounts filter
			{
				Config: testAccUsersDataSourceConfig_enabled(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
			// Test disabled accounts filter
			{
				Config: testAccUsersDataSourceConfig_enabled(false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
		},
	})
}

func TestAccUsersDataSource_emailFilters(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test users with email filter
			{
				Config: testAccUsersDataSourceConfig_hasEmail(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
			// Test users without email filter
			{
				Config: testAccUsersDataSourceConfig_hasEmail(false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
			// Test email domain filter
			{
				Config: testAccUsersDataSourceConfig_emailDomain("example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
				),
			},
		},
	})
}

func TestAccUsersDataSource_combinedFilters(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUsersDataSourceConfig_combinedFilters(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
					resource.TestCheckResourceAttr("data.ad_users.test", "container", "CN=Users,DC=example,DC=com"),
					resource.TestCheckResourceAttr("data.ad_users.test", "scope", "subtree"),
				),
			},
		},
	})
}

func TestAccUsersDataSource_userAttributes(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUsersDataSourceConfig_enabled(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users"),
					// Check that each user in the list has the required attributes
					resource.TestCheckTypeSetElemNestedAttrs("data.ad_users.test", "users.*", map[string]string{
						"id":               "", // Will be set to something
						"dn":               "", // Will be set to something
						"upn":              "", // Will be set to something
						"sam_account_name": "", // Will be set to something
						"display_name":     "", // Will be set to something
						"account_enabled":  "", // Will be set to something
						"when_created":     "", // Will be set to something
					}),
				),
			},
		},
	})
}

// Test configuration functions

func testAccUsersDataSourceConfig_basic() string {
	return `
data "ad_users" "test" {
}
`
}

func testAccUsersDataSourceConfig_withContainer(container string) string {
	return fmt.Sprintf(`
data "ad_users" "test" {
  container = %[1]q
}
`, container)
}

func testAccUsersDataSourceConfig_withScope(scope string) string {
	return fmt.Sprintf(`
data "ad_users" "test" {
  scope = %[1]q
}
`, scope)
}

func testAccUsersDataSourceConfig_namePrefix(prefix string) string {
	return fmt.Sprintf(`
data "ad_users" "test" {
  filter {
    name_prefix = %[1]q
  }
}
`, prefix)
}

func testAccUsersDataSourceConfig_nameSuffix(suffix string) string {
	return fmt.Sprintf(`
data "ad_users" "test" {
  filter {
    name_suffix = %[1]q
  }
}
`, suffix)
}

func testAccUsersDataSourceConfig_nameContains(contains string) string {
	return fmt.Sprintf(`
data "ad_users" "test" {
  filter {
    name_contains = %[1]q
  }
}
`, contains)
}

func testAccUsersDataSourceConfig_department(department string) string {
	return fmt.Sprintf(`
data "ad_users" "test" {
  filter {
    department = %[1]q
  }
}
`, department)
}

func testAccUsersDataSourceConfig_title(title string) string {
	return fmt.Sprintf(`
data "ad_users" "test" {
  filter {
    title = %[1]q
  }
}
`, title)
}

func testAccUsersDataSourceConfig_enabled(enabled bool) string {
	return fmt.Sprintf(`
data "ad_users" "test" {
  filter {
    enabled = %[1]t
  }
}
`, enabled)
}

func testAccUsersDataSourceConfig_hasEmail(hasEmail bool) string {
	return fmt.Sprintf(`
data "ad_users" "test" {
  filter {
    has_email = %[1]t
  }
}
`, hasEmail)
}

func testAccUsersDataSourceConfig_emailDomain(domain string) string {
	return fmt.Sprintf(`
data "ad_users" "test" {
  filter {
    email_domain = %[1]q
  }
}
`, domain)
}

func testAccUsersDataSourceConfig_combinedFilters() string {
	return `
data "ad_users" "test" {
  container = "CN=Users,DC=example,DC=com"
  scope     = "subtree"

  filter {
    name_contains = "test"
    enabled       = true
    has_email     = true
    department    = "IT"
  }
}
`
}
