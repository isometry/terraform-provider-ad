package provider_test

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// testCheckGroupsMemberCountAll asserts that every group in the data source's
// "groups" list has a member_count matching the predicate.
func testCheckGroupsMemberCountAll(resourceName string, predicate func(count int64) error) resource.TestCheckFunc {
	return testCheckListAttrEachWith(resourceName, "groups", "member_count", func(value string) error {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse member_count=%q: %w", value, err)
		}
		return predicate(n)
	})
}

func TestAccGroupsDataSource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupsDataSourceConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
				),
			},
		},
	})
}

func TestAccGroupsDataSource_withContainer(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupsDataSourceConfig_withContainer(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "container"),
					// Every returned group's DN must be a descendant of (or
					// equal to) the configured container. The container
					// interpolates the default naming context from ad_rootdse
					// at apply time, so we resolve it from the state.
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.ad_groups.test"]
						if !ok {
							return fmt.Errorf("data.ad_groups.test not found")
						}
						container := rs.Primary.Attributes["container"]
						if container == "" {
							return fmt.Errorf("container not set in state")
						}
						return testCheckListAttrAllInSubtree("data.ad_groups.test", "groups", container)(s)
					},
				),
			},
		},
	})
}

func TestAccGroupsDataSource_withScopeFilter(t *testing.T) {
	// Exercises the top-level `scope = "subtree"` attribute: the search is
	// executed against the default naming context and should return at least
	// one group (every real AD has built-in groups).
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupsDataSourceConfig_withScopeFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					resource.TestCheckResourceAttr("data.ad_groups.test", "scope", "subtree"),
				),
			},
		},
	})
}

// TestAccGroupsDataSource_scopeModes verifies that the top-level `scope`
// attribute is wired through to the LDAP search by building a small fixture
// (one parent OU with two child OUs, each holding one group) and running the
// data source against all three scope modes:
//
//   - base:     container == parent OU DN → 0 groups (OU entry is not a group)
//   - onelevel: container == parent OU DN → 0 groups (immediate children are OUs, not groups)
//   - subtree:  container == parent OU DN → 2 groups (both groups live in descendant OUs)
func TestAccGroupsDataSource_scopeModes(t *testing.T) {
	parentOU := GenerateTestName(TestOUPrefix + "parent-")
	childA := GenerateTestName(TestOUPrefix + "child-a-")
	childB := GenerateTestName(TestOUPrefix + "child-b-")
	groupA := GenerateTestName(TestGroupPrefix + "alpha-")
	groupB := GenerateTestName(TestGroupPrefix + "beta-")
	samA := GenerateTestSAMName("ga")
	samB := GenerateTestSAMName("gb")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupsDataSourceConfig_scopeMode(parentOU, childA, childB, groupA, groupB, samA, samB, "base"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ad_groups.test", "scope", "base"),
					resource.TestCheckResourceAttr("data.ad_groups.test", "group_count", "0"),
					resource.TestCheckResourceAttr("data.ad_groups.test", "groups.#", "0"),
				),
			},
			{
				Config: testAccGroupsDataSourceConfig_scopeMode(parentOU, childA, childB, groupA, groupB, samA, samB, "onelevel"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ad_groups.test", "scope", "onelevel"),
					resource.TestCheckResourceAttr("data.ad_groups.test", "group_count", "0"),
					resource.TestCheckResourceAttr("data.ad_groups.test", "groups.#", "0"),
				),
			},
			{
				Config: testAccGroupsDataSourceConfig_scopeMode(parentOU, childA, childB, groupA, groupB, samA, samB, "subtree"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ad_groups.test", "scope", "subtree"),
					resource.TestCheckResourceAttr("data.ad_groups.test", "group_count", "2"),
					resource.TestCheckResourceAttr("data.ad_groups.test", "groups.#", "2"),
				),
			},
		},
	})
}

func TestAccGroupsDataSource_withNameFilters(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test name prefix filter: every returned group's name must start
			// with "Domain" (case-insensitive).
			{
				Config: testAccGroupsDataSourceConfig_withNamePrefix(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckListAttrAllHavePrefix("data.ad_groups.test", "groups", "name", "Domain"),
				),
			},
			// Test name suffix filter: every returned group's name must end
			// with "Admins" (case-insensitive).
			{
				Config: testAccGroupsDataSourceConfig_withNameSuffix(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckListAttrAllHaveSuffix("data.ad_groups.test", "groups", "name", "Admins"),
				),
			},
			// Test name contains filter: every returned group's name must
			// contain "Admin" (case-insensitive).
			{
				Config: testAccGroupsDataSourceConfig_withNameContains(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckListAttrAllContain("data.ad_groups.test", "groups", "name", "Admin"),
				),
			},
		},
	})
}

func TestAccGroupsDataSource_withCategoryFilter(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test security category filter: every returned group must have
			// category == "security".
			{
				Config: testAccGroupsDataSourceConfig_withSecurityCategory(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckListAttrAllEqual("data.ad_groups.test", "groups", "category", "security"),
				),
			},
			// Test distribution category filter: every returned group must
			// have category == "distribution".
			{
				Config: testAccGroupsDataSourceConfig_withDistributionCategory(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckListAttrAllEqual("data.ad_groups.test", "groups", "category", "distribution"),
				),
			},
		},
	})
}

func TestAccGroupsDataSource_withScopeFilters(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test global scope filter: every returned group must have
			// scope == "global".
			{
				Config: testAccGroupsDataSourceConfig_withGlobalScope(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckListAttrAllEqual("data.ad_groups.test", "groups", "scope", "global"),
				),
			},
			// Test universal scope filter: every returned group must have
			// scope == "universal".
			{
				Config: testAccGroupsDataSourceConfig_withUniversalScope(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckListAttrAllEqual("data.ad_groups.test", "groups", "scope", "universal"),
				),
			},
			// Test domain local scope filter: every returned group must have
			// scope == "domainlocal".
			{
				Config: testAccGroupsDataSourceConfig_withDomainLocalScope(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckListAttrAllEqual("data.ad_groups.test", "groups", "scope", "domainlocal"),
				),
			},
		},
	})
}

func TestAccGroupsDataSource_withMembershipFilter(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test groups with members: every returned group must have
			// member_count > 0.
			{
				Config: testAccGroupsDataSourceConfig_withMembers(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckGroupsMemberCountAll("data.ad_groups.test", func(n int64) error {
						if n <= 0 {
							return fmt.Errorf("expected member_count > 0")
						}
						return nil
					}),
				),
			},
			// Test empty groups: every returned group must have
			// member_count == 0.
			{
				Config: testAccGroupsDataSourceConfig_withoutMembers(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckGroupsMemberCountAll("data.ad_groups.test", func(n int64) error {
						if n != 0 {
							return fmt.Errorf("expected member_count == 0")
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccGroupsDataSource_combinedFilters(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Combined filters: container CN=Users subtree, name_contains
			// "Admin", category "security", scope "global", has_members true.
			// Every returned group must satisfy ALL five predicates.
			{
				Config: testAccGroupsDataSourceConfig_combinedFilters(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					testCheckListAttrAllContain("data.ad_groups.test", "groups", "name", "Admin"),
					testCheckListAttrAllEqual("data.ad_groups.test", "groups", "category", "security"),
					testCheckListAttrAllEqual("data.ad_groups.test", "groups", "scope", "global"),
					testCheckGroupsMemberCountAll("data.ad_groups.test", func(n int64) error {
						if n <= 0 {
							return fmt.Errorf("expected member_count > 0")
						}
						return nil
					}),
					// Every DN must lie within the configured container.
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.ad_groups.test"]
						if !ok {
							return fmt.Errorf("data.ad_groups.test not found")
						}
						container := rs.Primary.Attributes["container"]
						if container == "" {
							return fmt.Errorf("container not set in state")
						}
						return testCheckListAttrAllInSubtree("data.ad_groups.test", "groups", container)(s)
					},
				),
			},
		},
	})
}

func TestAccGroupsDataSource_groupAttributes(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupsDataSourceConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					// Verify that the first returned group has the expected schema attributes populated.
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.0.id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.0.name"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.0.dn"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.0.sam_account_name"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.0.scope"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.0.category"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.0.sid"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.0.member_count"),
				),
			},
		},
	})
}

func TestAccGroupsDataSource_invalidScope(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccGroupsDataSourceConfig_invalidScope(),
				ExpectError: regexp.MustCompile("Invalid Attribute Value Match"),
			},
		},
	})
}

func TestAccGroupsDataSource_invalidFilterScope(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccGroupsDataSourceConfig_invalidFilterScope(),
				ExpectError: regexp.MustCompile("Invalid Attribute Value Match"),
			},
		},
	})
}

func TestAccGroupsDataSource_invalidCategory(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccGroupsDataSourceConfig_invalidCategory(),
				ExpectError: regexp.MustCompile("Invalid Attribute Value Match"),
			},
		},
	})
}

// Configuration functions

func testAccGroupsDataSourceConfig_basic() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_withContainer() string {
	return fmt.Sprintf(`
%s

%s

data "ad_groups" "test" {
  container = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource())
}

func testAccGroupsDataSourceConfig_withScopeFilter() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  scope = "subtree"
}
`, testProviderConfig())
}

// testAccGroupsDataSourceConfig_scopeMode builds a fixture with a parent OU,
// two child OUs, and one group in each child OU; the data source queries the
// parent OU with the supplied scope. The `depends_on` on the groups ensures
// that the data source observes both groups when running a subtree search.
func testAccGroupsDataSourceConfig_scopeMode(parentOU, childA, childB, groupA, groupB, samA, samB, scope string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_ou" "parent" {
  name = %[3]q
  path = data.ad_rootdse.test.default_naming_context
}

resource "ad_ou" "child_a" {
  name = %[4]q
  path = ad_ou.parent.dn
}

resource "ad_ou" "child_b" {
  name = %[5]q
  path = ad_ou.parent.dn
}

resource "ad_group" "alpha" {
  name             = %[6]q
  sam_account_name = %[8]q
  container        = ad_ou.child_a.dn
}

resource "ad_group" "beta" {
  name             = %[7]q
  sam_account_name = %[9]q
  container        = ad_ou.child_b.dn
}

data "ad_groups" "test" {
  container = ad_ou.parent.dn
  scope     = %[10]q

  depends_on = [ad_group.alpha, ad_group.beta]
}
`,
		testProviderConfig(),
		testRootDSEDataSource(),
		parentOU,
		childA,
		childB,
		groupA,
		groupB,
		samA,
		samB,
		scope,
	)
}

func testAccGroupsDataSourceConfig_withNamePrefix() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    name_prefix = "Domain"
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_withNameSuffix() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    name_suffix = "Admins"
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_withNameContains() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    name_contains = "Admin"
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_withSecurityCategory() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    category = "security"
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_withDistributionCategory() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    category = "distribution"
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_withGlobalScope() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    scope = "global"
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_withUniversalScope() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    scope = "universal"
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_withDomainLocalScope() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    scope = "domainlocal"
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_withMembers() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    has_members = true
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_withoutMembers() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    has_members = false
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_combinedFilters() string {
	return fmt.Sprintf(`
%s

%s

data "ad_groups" "test" {
  container = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  scope     = "subtree"

  filter {
    name_contains = "Admin"
    category      = "security"
    scope         = "global"
    has_members   = true
  }
}
`, testProviderConfig(), testRootDSEDataSource())
}

// Invalid configuration tests

func testAccGroupsDataSourceConfig_invalidScope() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  scope = "invalid"
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_invalidFilterScope() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    scope = "invalid"
  }
}
`, testProviderConfig())
}

func testAccGroupsDataSourceConfig_invalidCategory() string {
	return fmt.Sprintf(`
%s

data "ad_groups" "test" {
  filter {
    category = "invalid"
  }
}
`, testProviderConfig())
}
