package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccOUDataSource_id(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create an OU first, then read it via data source by ID
			{
				Config: testAccOUDataSourceConfig_id(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "TestOUDataSource"),
					resource.TestCheckResourceAttr("ad_ou.test", "description", "Test OU for data source"),
					resource.TestCheckResourceAttr("ad_ou.test", "protected", "false"),
					resource.TestCheckResourceAttrSet("ad_ou.test", "id"),
					resource.TestCheckResourceAttrSet("ad_ou.test", "guid"),
					resource.TestCheckResourceAttrSet("ad_ou.test", "dn"),

					// Data source checks
					resource.TestCheckResourceAttrPair("data.ad_ou.test", "id", "ad_ou.test", "id"),
					resource.TestCheckResourceAttr("data.ad_ou.test", "description", "Test OU for data source"),
					resource.TestCheckResourceAttr("data.ad_ou.test", "protected", "false"),
					resource.TestCheckResourceAttrPair("data.ad_ou.test", "guid", "ad_ou.test", "guid"),
					resource.TestCheckResourceAttrSet("data.ad_ou.test", "child_count"),
					resource.TestCheckResourceAttrSet("data.ad_ou.test", "children"),
				),
			},
		},
	})
}

func TestAccOUDataSource_dn(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create an OU first, then read it via data source by DN
			{
				Config: testAccOUDataSourceConfig_dn(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "TestOUDataSourceDN"),
					resource.TestCheckResourceAttr("ad_ou.test", "description", "Test OU for DN data source"),

					// Data source checks
					resource.TestCheckResourceAttrPair("data.ad_ou.test", "id", "ad_ou.test", "id"),
					resource.TestCheckResourceAttr("data.ad_ou.test", "description", "Test OU for DN data source"),
					resource.TestCheckResourceAttr("data.ad_ou.test", "protected", "false"),
					resource.TestCheckResourceAttrPair("data.ad_ou.test", "guid", "ad_ou.test", "guid"),
					resource.TestCheckResourceAttrSet("data.ad_ou.test", "child_count"),
					resource.TestCheckResourceAttrSet("data.ad_ou.test", "children"),
				),
			},
		},
	})
}

func TestAccOUDataSource_nameAndPath(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create an OU first, then read it via data source by name and path
			{
				Config: testAccOUDataSourceConfig_nameAndPath(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "TestOUDataSourceName"),
					resource.TestCheckResourceAttr("ad_ou.test", "description", "Test OU for name/path data source"),

					// Data source checks
					resource.TestCheckResourceAttrPair("data.ad_ou.test", "id", "ad_ou.test", "id"),
					resource.TestCheckResourceAttr("data.ad_ou.test", "description", "Test OU for name/path data source"),
					resource.TestCheckResourceAttr("data.ad_ou.test", "protected", "false"),
					resource.TestCheckResourceAttrPair("data.ad_ou.test", "guid", "ad_ou.test", "guid"),
					resource.TestCheckResourceAttrSet("data.ad_ou.test", "child_count"),
					resource.TestCheckResourceAttrSet("data.ad_ou.test", "children"),
				),
			},
		},
	})
}

func TestAccOUDataSource_withChildren(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create parent and child OUs, then test child enumeration
			{
				Config: testAccOUDataSourceConfig_withChildren(),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Parent OU checks
					resource.TestCheckResourceAttr("ad_ou.parent", "name", "TestOUParent"),
					resource.TestCheckResourceAttr("ad_ou.child1", "name", "TestOUChild1"),
					resource.TestCheckResourceAttr("ad_ou.child2", "name", "TestOUChild2"),

					// Data source checks - should find both children
					resource.TestCheckResourceAttrPair("data.ad_ou.parent", "id", "ad_ou.parent", "id"),
					resource.TestCheckResourceAttr("data.ad_ou.parent", "child_count", "2"),
					testAccCheckOUDataSourceHasChildren("data.ad_ou.parent", []string{
						"ad_ou.child1", "ad_ou.child2",
					}),
				),
			},
		},
	})
}

func TestAccOUDataSource_notFound(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccOUDataSourceConfig_notFound(),
				ExpectError: regexp.MustCompile("OU Not Found|not found"),
			},
		},
	})
}

func TestAccOUDataSource_invalidGUID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccOUDataSourceConfig_invalidGUID(),
				ExpectError: regexp.MustCompile("Invalid GUID Format"),
			},
		},
	})
}

func TestAccOUDataSource_configValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test that multiple lookup methods are rejected
			{
				Config:      testAccOUDataSourceConfig_multipleKeys(),
				ExpectError: regexp.MustCompile("Invalid Attribute Combination|ExactlyOneOf"),
			},
			// Test that name without path is rejected
			{
				Config:      testAccOUDataSourceConfig_nameWithoutPath(),
				ExpectError: regexp.MustCompile("Invalid Attribute Combination|RequiredTogether"),
			},
			// Test that path without name is rejected
			{
				Config:      testAccOUDataSourceConfig_pathWithoutName(),
				ExpectError: regexp.MustCompile("Invalid Attribute Combination|RequiredTogether"),
			},
		},
	})
}

// testAccCheckOUDataSourceHasChildren is a custom test helper to verify child OUs.
func testAccCheckOUDataSourceHasChildren(dataSourceName string, expectedChildResources []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[dataSourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", dataSourceName)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set for %s", dataSourceName)
		}

		// Get the children attribute
		childrenAttr, ok := rs.Primary.Attributes["children.#"]
		if !ok {
			return fmt.Errorf("children attribute not found for %s", dataSourceName)
		}

		expectedCount := len(expectedChildResources)
		if childrenAttr != fmt.Sprintf("%d", expectedCount) {
			return fmt.Errorf("Expected %d children, got %s", expectedCount, childrenAttr)
		}

		// Collect child DNs from expected resources
		expectedDNs := make(map[string]bool)
		for _, resourceName := range expectedChildResources {
			childRS, ok := s.RootModule().Resources[resourceName]
			if !ok {
				return fmt.Errorf("Expected child resource not found: %s", resourceName)
			}
			expectedDNs[childRS.Primary.Attributes["dn"]] = true
		}

		// Check that all expected children are present
		for i := 0; i < expectedCount; i++ {
			childDN, ok := rs.Primary.Attributes[fmt.Sprintf("children.%d", i)]
			if !ok {
				return fmt.Errorf("Child DN at index %d not found", i)
			}
			if !expectedDNs[childDN] {
				return fmt.Errorf("Unexpected child DN found: %s", childDN)
			}
		}

		return nil
	}
}

// Test configuration functions

func testAccOUDataSourceConfig_id() string {
	return `
resource "ad_ou" "test" {
  name        = "TestOUDataSource"
  path        = "DC=example,DC=com"
  description = "Test OU for data source"
  protected   = false
}

data "ad_ou" "test" {
  id = ad_ou.test.id
}
`
}

func testAccOUDataSourceConfig_dn() string {
	return `
resource "ad_ou" "test" {
  name        = "TestOUDataSourceDN"
  path        = "DC=example,DC=com"
  description = "Test OU for DN data source"
  protected   = false
}

data "ad_ou" "test" {
  dn = ad_ou.test.dn
}
`
}

func testAccOUDataSourceConfig_nameAndPath() string {
	return `
resource "ad_ou" "test" {
  name        = "TestOUDataSourceName"
  path        = "DC=example,DC=com"
  description = "Test OU for name/path data source"
  protected   = false
}

data "ad_ou" "test" {
  name = "TestOUDataSourceName"
  path = "DC=example,DC=com"
}
`
}

func testAccOUDataSourceConfig_withChildren() string {
	return `
resource "ad_ou" "parent" {
  name        = "TestOUParent"
  path        = "DC=example,DC=com"
  description = "Parent OU with children"
  protected   = false
}

resource "ad_ou" "child1" {
  name        = "TestOUChild1"
  path        = ad_ou.parent.dn
  description = "First child OU"
  protected   = false
}

resource "ad_ou" "child2" {
  name        = "TestOUChild2"
  path        = ad_ou.parent.dn
  description = "Second child OU"
  protected   = false
}

data "ad_ou" "parent" {
  id = ad_ou.parent.id
}
`
}

func testAccOUDataSourceConfig_notFound() string {
	return `
data "ad_ou" "test" {
  id = "00000000-0000-0000-0000-000000000000"
}
`
}

func testAccOUDataSourceConfig_invalidGUID() string {
	return `
data "ad_ou" "test" {
  id = "invalid-guid-format"
}
`
}

func testAccOUDataSourceConfig_multipleKeys() string {
	return `
data "ad_ou" "test" {
  id = "550e8400-e29b-41d4-a716-446655440000"
  dn = "OU=Test,DC=example,DC=com"
}
`
}

func testAccOUDataSourceConfig_nameWithoutPath() string {
	return `
data "ad_ou" "test" {
  name = "TestOU"
}
`
}

func testAccOUDataSourceConfig_pathWithoutName() string {
	return `
data "ad_ou" "test" {
  path = "DC=example,DC=com"
}
`
}
