package provider_test

// TODO: the ad_users data source does not currently expose a
// `membership_filter` (or `member_of`) attribute analogous to
// ad_groups.membership_filter (see internal/provider/data_source_groups.go).
// Adding one would be a genuinely valuable feature — e.g. "list all users
// who are direct or nested members of group X" — and the analogous test
// would then live here. This is a schema gap, not a test gap, so Tier 2
// intentionally leaves it unimplemented; it is surfaced as a schema-level
// follow-up rather than an additional acceptance test.

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
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
				Config: testAccUsersDataSourceConfig_withContainerFromRootDSE(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "container"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					// Every returned user's DN must be a descendant of the
					// configured container (subtree search semantics).
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.ad_users.test"]
						if !ok {
							return fmt.Errorf("data.ad_users.test not found")
						}
						container := rs.Primary.Attributes["container"]
						if container == "" {
							return fmt.Errorf("container not set in state")
						}
						return testCheckListAttrAllInSubtree("data.ad_users.test", "users", container)(s)
					},
				),
			},
		},
	})
}

func TestAccUsersDataSource_withScope(t *testing.T) {
	// Exercises the top-level `scope` attribute wired through to the LDAP
	// search. Targeting `CN=Users,<default_naming_context>` with
	// `scope = "onelevel"` restricts the search to the users living directly
	// under the default Users container (Administrator, Guest, krbtgt, etc.),
	// which should always be non-empty against a real AD.
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
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					// Expect at least one user directly under CN=Users (e.g. Administrator).
					resource.TestCheckResourceAttrWith("data.ad_users.test", "user_count", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one user directly under CN=Users, got 0")
						}
						return nil
					}),
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
			// Test name prefix filter: every returned user's name (CN) must
			// start with "Admin" (case-insensitive).
			{
				Config: testAccUsersDataSourceConfig_namePrefix("Admin"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					testCheckListAttrAllHavePrefix("data.ad_users.test", "users", "name", "Admin"),
				),
			},
			// Test name suffix filter: every returned user's name must end
			// with "User" (case-insensitive).
			{
				Config: testAccUsersDataSourceConfig_nameSuffix("User"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					testCheckListAttrAllHaveSuffix("data.ad_users.test", "users", "name", "User"),
				),
			},
			// Test name contains filter: every returned user's name must
			// contain "test" (case-insensitive).
			{
				Config: testAccUsersDataSourceConfig_nameContains("test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					testCheckListAttrAllContain("data.ad_users.test", "users", "name", "test"),
				),
			},
		},
	})
}

func TestAccUsersDataSource_organizationalFilters(t *testing.T) {
	// NOTE: Despite the schema docstring wording ("Case-insensitive partial
	// match"), the LDAP filter is built with `(department=<value>)` and
	// `(title=<value>)` — that is an exact match (case-insensitive under AD
	// attribute matching rules). Assertions below reflect the actual
	// behaviour: equality, not substring.
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test department filter: every returned user must have
			// department == "IT" (case-insensitive).
			{
				Config: testAccUsersDataSourceConfig_department("IT"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					testCheckListAttrAllEqual("data.ad_users.test", "users", "department", "IT"),
				),
			},
			// Test title filter: every returned user must have
			// title == "Manager" (case-insensitive).
			{
				Config: testAccUsersDataSourceConfig_title("Manager"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					testCheckListAttrAllEqual("data.ad_users.test", "users", "title", "Manager"),
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
			// Test enabled accounts filter: every returned user must have
			// account_enabled == true.
			{
				Config: testAccUsersDataSourceConfig_enabled(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					testCheckListAttrAllEqualBool("data.ad_users.test", "users", "account_enabled", true),
				),
			},
			// Test disabled accounts filter: every returned user must have
			// account_enabled == false.
			{
				Config: testAccUsersDataSourceConfig_enabled(false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					testCheckListAttrAllEqualBool("data.ad_users.test", "users", "account_enabled", false),
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
			// Test users with email: every returned user must have a
			// non-empty email_address.
			{
				Config: testAccUsersDataSourceConfig_hasEmail(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					testCheckListAttrAllNonEmpty("data.ad_users.test", "users", "email_address"),
				),
			},
			// Test users without email: every returned user must have an
			// empty email_address.
			{
				Config: testAccUsersDataSourceConfig_hasEmail(false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					testCheckListAttrAllEmpty("data.ad_users.test", "users", "email_address"),
				),
			},
			// Test email domain filter: every returned user must have an
			// email_address ending in "@example.com" (case-insensitive).
			{
				Config: testAccUsersDataSourceConfig_emailDomain("example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					testCheckListAttrAllEmailDomain("data.ad_users.test", "users", "email_address", "example.com"),
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
			// Combined filters: container CN=Users subtree, enabled=true.
			// Every returned user must satisfy BOTH predicates.
			{
				Config: testAccUsersDataSourceConfig_combinedFilters(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_users.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "user_count"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "container"),
					resource.TestCheckResourceAttr("data.ad_users.test", "scope", "subtree"),
					testCheckListAttrAllEqualBool("data.ad_users.test", "users", "account_enabled", true),
					// Every DN must lie within the configured container.
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.ad_users.test"]
						if !ok {
							return fmt.Errorf("data.ad_users.test not found")
						}
						container := rs.Primary.Attributes["container"]
						if container == "" {
							return fmt.Errorf("container not set in state")
						}
						return testCheckListAttrAllInSubtree("data.ad_users.test", "users", container)(s)
					},
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
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.#"),
					// Verify that the first returned user has the expected schema attributes populated.
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.0.id"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.0.dn"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.0.sam_account_name"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.0.account_enabled"),
					resource.TestCheckResourceAttrSet("data.ad_users.test", "users.0.when_created"),
				),
			},
		},
	})
}

// Test configuration functions

func testAccUsersDataSourceConfig_basic() string {
	return fmt.Sprintf(`
%s

data "ad_users" "test" {
}
`, testProviderConfig())
}

func testAccUsersDataSourceConfig_withContainerFromRootDSE() string {
	return fmt.Sprintf(`
%s

%s

data "ad_users" "test" {
  container = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource())
}

func testAccUsersDataSourceConfig_withScope(scope string) string {
	return fmt.Sprintf(`
%s

%s

data "ad_users" "test" {
  container = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  scope     = %[3]q
}
`, testProviderConfig(), testRootDSEDataSource(), scope)
}

func testAccUsersDataSourceConfig_namePrefix(prefix string) string {
	return fmt.Sprintf(`
%s

data "ad_users" "test" {
  filter {
    name_prefix = %[2]q
  }
}
`, testProviderConfig(), prefix)
}

func testAccUsersDataSourceConfig_nameSuffix(suffix string) string {
	return fmt.Sprintf(`
%s

data "ad_users" "test" {
  filter {
    name_suffix = %[2]q
  }
}
`, testProviderConfig(), suffix)
}

func testAccUsersDataSourceConfig_nameContains(contains string) string {
	return fmt.Sprintf(`
%s

data "ad_users" "test" {
  filter {
    name_contains = %[2]q
  }
}
`, testProviderConfig(), contains)
}

func testAccUsersDataSourceConfig_department(department string) string {
	return fmt.Sprintf(`
%s

data "ad_users" "test" {
  filter {
    department = %[2]q
  }
}
`, testProviderConfig(), department)
}

func testAccUsersDataSourceConfig_title(title string) string {
	return fmt.Sprintf(`
%s

data "ad_users" "test" {
  filter {
    title = %[2]q
  }
}
`, testProviderConfig(), title)
}

func testAccUsersDataSourceConfig_enabled(enabled bool) string {
	return fmt.Sprintf(`
%s

data "ad_users" "test" {
  filter {
    enabled = %[2]t
  }
}
`, testProviderConfig(), enabled)
}

func testAccUsersDataSourceConfig_hasEmail(hasEmail bool) string {
	return fmt.Sprintf(`
%s

data "ad_users" "test" {
  filter {
    has_email = %[2]t
  }
}
`, testProviderConfig(), hasEmail)
}

func testAccUsersDataSourceConfig_emailDomain(domain string) string {
	return fmt.Sprintf(`
%s

data "ad_users" "test" {
  filter {
    email_domain = %[2]q
  }
}
`, testProviderConfig(), domain)
}

func testAccUsersDataSourceConfig_combinedFilters() string {
	return fmt.Sprintf(`
%s

%s

data "ad_users" "test" {
  container = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  scope     = "subtree"

  filter {
    enabled = true
  }
}
`, testProviderConfig(), testRootDSEDataSource())
}
