package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

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
					resource.TestCheckResourceAttr("data.ad_groups.test", "groups.#", "0"), // Should match the count
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
				),
			},
		},
	})
}

func TestAccGroupsDataSource_withScopeFilter(t *testing.T) {
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
			// Test name prefix filter
			{
				Config: testAccGroupsDataSourceConfig_withNamePrefix(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
				),
			},
			// Test name suffix filter
			{
				Config: testAccGroupsDataSourceConfig_withNameSuffix(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
				),
			},
			// Test name contains filter
			{
				Config: testAccGroupsDataSourceConfig_withNameContains(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
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
			// Test security category filter
			{
				Config: testAccGroupsDataSourceConfig_withSecurityCategory(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
					// Verify that returned groups are security groups
					resource.TestMatchResourceAttr("data.ad_groups.test", "groups.0.category", regexp.MustCompile("(?i)security")),
				),
			},
			// Test distribution category filter
			{
				Config: testAccGroupsDataSourceConfig_withDistributionCategory(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
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
			// Test global scope filter
			{
				Config: testAccGroupsDataSourceConfig_withGlobalScope(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
				),
			},
			// Test universal scope filter
			{
				Config: testAccGroupsDataSourceConfig_withUniversalScope(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
				),
			},
			// Test domain local scope filter
			{
				Config: testAccGroupsDataSourceConfig_withDomainLocalScope(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
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
			// Test groups with members
			{
				Config: testAccGroupsDataSourceConfig_withMembers(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
				),
			},
			// Test empty groups
			{
				Config: testAccGroupsDataSourceConfig_withoutMembers(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
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
			{
				Config: testAccGroupsDataSourceConfig_combinedFilters(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "group_count"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_groups.test", "groups.#"),
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
					// Check that group attributes exist when groups are found
					resource.TestCheckTypeSetElemNestedAttrs("data.ad_groups.test", "groups.*", map[string]string{
						"id":               "",
						"name":             "",
						"display_name":     "",
						"description":      "",
						"dn":               "",
						"sam_account_name": "",
						"scope":            "",
						"category":         "",
						"sid":              "",
						"member_count":     "",
					}),
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
	return `
data "ad_groups" "test" {
}
`
}

func testAccGroupsDataSourceConfig_withContainer() string {
	return `
data "ad_groups" "test" {
  container = "CN=Users,DC=example,DC=com"
}
`
}

func testAccGroupsDataSourceConfig_withScopeFilter() string {
	return `
data "ad_groups" "test" {
  scope = "subtree"
}
`
}

func testAccGroupsDataSourceConfig_withNamePrefix() string {
	return `
data "ad_groups" "test" {
  filter {
    name_prefix = "Domain"
  }
}
`
}

func testAccGroupsDataSourceConfig_withNameSuffix() string {
	return `
data "ad_groups" "test" {
  filter {
    name_suffix = "Admins"
  }
}
`
}

func testAccGroupsDataSourceConfig_withNameContains() string {
	return `
data "ad_groups" "test" {
  filter {
    name_contains = "Admin"
  }
}
`
}

func testAccGroupsDataSourceConfig_withSecurityCategory() string {
	return `
data "ad_groups" "test" {
  filter {
    category = "security"
  }
}
`
}

func testAccGroupsDataSourceConfig_withDistributionCategory() string {
	return `
data "ad_groups" "test" {
  filter {
    category = "distribution"
  }
}
`
}

func testAccGroupsDataSourceConfig_withGlobalScope() string {
	return `
data "ad_groups" "test" {
  filter {
    scope = "global"
  }
}
`
}

func testAccGroupsDataSourceConfig_withUniversalScope() string {
	return `
data "ad_groups" "test" {
  filter {
    scope = "universal"
  }
}
`
}

func testAccGroupsDataSourceConfig_withDomainLocalScope() string {
	return `
data "ad_groups" "test" {
  filter {
    scope = "domainlocal"
  }
}
`
}

func testAccGroupsDataSourceConfig_withMembers() string {
	return `
data "ad_groups" "test" {
  filter {
    has_members = true
  }
}
`
}

func testAccGroupsDataSourceConfig_withoutMembers() string {
	return `
data "ad_groups" "test" {
  filter {
    has_members = false
  }
}
`
}

func testAccGroupsDataSourceConfig_combinedFilters() string {
	return `
data "ad_groups" "test" {
  container = "CN=Users,DC=example,DC=com"
  scope     = "subtree"

  filter {
    name_contains = "Admin"
    category      = "security"
    scope         = "global"
    has_members   = true
  }
}
`
}

// Invalid configuration tests

func testAccGroupsDataSourceConfig_invalidScope() string {
	return `
data "ad_groups" "test" {
  scope = "invalid"
}
`
}

func testAccGroupsDataSourceConfig_invalidFilterScope() string {
	return `
data "ad_groups" "test" {
  filter {
    scope = "invalid"
  }
}
`
}

func testAccGroupsDataSourceConfig_invalidCategory() string {
	return `
data "ad_groups" "test" {
  filter {
    category = "invalid"
  }
}
`
}
