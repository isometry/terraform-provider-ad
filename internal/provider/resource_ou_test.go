package provider_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccOUResource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccOUResourceConfig_basic("tf-test-ou-basic"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-basic"),
					resource.TestCheckResourceAttr("ad_ou.test", "protected", "false"),
					resource.TestCheckResourceAttrSet("ad_ou.test", "id"),
					resource.TestCheckResourceAttrSet("ad_ou.test", "dn"),
					resource.TestCheckResourceAttrSet("ad_ou.test", "guid"),
					resource.TestCheckResourceAttrSet("ad_ou.test", "path"),
					// Verify GUID and ID are the same
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ad_ou.test"]
						if !ok {
							return fmt.Errorf("resource not found: ad_ou.test")
						}

						id := rs.Primary.Attributes["id"]
						guid := rs.Primary.Attributes["guid"]

						if id != guid {
							return fmt.Errorf("expected id and guid to be the same, got id=%s, guid=%s", id, guid)
						}

						return nil
					},
				),
			},
			// ImportState testing
			{
				ResourceName:      "ad_ou.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccOUResource_withDescription(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with description
			{
				Config: testAccOUResourceConfig_withDescription("tf-test-ou-desc", "Test OU with description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-desc"),
					resource.TestCheckResourceAttr("ad_ou.test", "description", "Test OU with description"),
					resource.TestCheckResourceAttr("ad_ou.test", "protected", "false"),
				),
			},
		},
	})
}

func TestAccOUResource_protected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create protected OU
			{
				Config: testAccOUResourceConfig_protected("tf-test-ou-protected", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-protected"),
					resource.TestCheckResourceAttr("ad_ou.test", "protected", "true"),
				),
			},
			// Update protection status
			{
				Config: testAccOUResourceConfig_protected("tf-test-ou-protected", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-protected"),
					resource.TestCheckResourceAttr("ad_ou.test", "protected", "false"),
				),
			},
		},
	})
}

func TestAccOUResource_updateDescription(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with initial description
			{
				Config: testAccOUResourceConfig_withDescription("tf-test-ou-update", "Initial description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "description", "Initial description"),
				),
			},
			// Update description
			{
				Config: testAccOUResourceConfig_withDescription("tf-test-ou-update", "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "description", "Updated description"),
				),
			},
			// Remove description
			{
				Config: testAccOUResourceConfig_basic("tf-test-ou-update"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "description", ""),
				),
			},
		},
	})
}

func TestAccOUResource_nestedOU(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create parent and child OUs
			{
				Config: testAccOUResourceConfig_nested("tf-test-parent-ou", "tf-test-child-ou"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check parent OU
					resource.TestCheckResourceAttr("ad_ou.parent", "name", "tf-test-parent-ou"),
					resource.TestCheckResourceAttrSet("ad_ou.parent", "id"),
					resource.TestCheckResourceAttrSet("ad_ou.parent", "dn"),
					// Check child OU
					resource.TestCheckResourceAttr("ad_ou.child", "name", "tf-test-child-ou"),
					resource.TestCheckResourceAttrSet("ad_ou.child", "id"),
					resource.TestCheckResourceAttrSet("ad_ou.child", "dn"),
					// Verify child path references parent DN
					resource.TestCheckResourceAttrPair("ad_ou.child", "path", "ad_ou.parent", "dn"),
				),
			},
		},
	})
}

func TestAccOUResource_multipleOUs(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create multiple OUs
			{
				Config: testAccOUResourceConfig_multiple("tf-test-ou-1", "tf-test-ou-2", "tf-test-ou-3"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check first OU
					resource.TestCheckResourceAttr("ad_ou.test1", "name", "tf-test-ou-1"),
					resource.TestCheckResourceAttrSet("ad_ou.test1", "id"),
					// Check second OU
					resource.TestCheckResourceAttr("ad_ou.test2", "name", "tf-test-ou-2"),
					resource.TestCheckResourceAttrSet("ad_ou.test2", "id"),
					// Check third OU
					resource.TestCheckResourceAttr("ad_ou.test3", "name", "tf-test-ou-3"),
					resource.TestCheckResourceAttrSet("ad_ou.test3", "id"),
					// Verify all have different IDs
					func(s *terraform.State) error {
						ou1 := s.RootModule().Resources["ad_ou.test1"]
						ou2 := s.RootModule().Resources["ad_ou.test2"]
						ou3 := s.RootModule().Resources["ad_ou.test3"]

						id1 := ou1.Primary.Attributes["id"]
						id2 := ou2.Primary.Attributes["id"]
						id3 := ou3.Primary.Attributes["id"]

						if id1 == id2 || id1 == id3 || id2 == id3 {
							return fmt.Errorf("expected all OUs to have different IDs, got id1=%s, id2=%s, id3=%s", id1, id2, id3)
						}

						return nil
					},
				),
			},
		},
	})
}

func TestAccOUResource_importByGUID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create OU
			{
				Config: testAccOUResourceConfig_basic("tf-test-ou-import-guid"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-import-guid"),
					resource.TestCheckResourceAttrSet("ad_ou.test", "id"),
				),
			},
			// Import by GUID (ID)
			{
				ResourceName:      "ad_ou.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccOUResource_importByDN(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create OU
			{
				Config: testAccOUResourceConfig_basic("tf-test-ou-import-dn"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-import-dn"),
					resource.TestCheckResourceAttrSet("ad_ou.test", "dn"),
				),
			},
			// Import by DN (requires custom import check)
			{
				ResourceName: "ad_ou.test",
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources["ad_ou.test"]
					if !ok {
						return "", fmt.Errorf("resource not found: ad_ou.test")
					}

					return rs.Primary.Attributes["dn"], nil
				},
				ImportStateVerify: true,
			},
		},
	})
}

// Test configuration functions

func testAccOUResourceConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "ad_ou" "test" {
  name = %[1]q
  path = "dc=example,dc=com"
}
`, name)
}

func testAccOUResourceConfig_withDescription(name, description string) string {
	return fmt.Sprintf(`
resource "ad_ou" "test" {
  name        = %[1]q
  path        = "dc=example,dc=com"
  description = %[2]q
}
`, name, description)
}

func testAccOUResourceConfig_protected(name string, protected bool) string {
	return fmt.Sprintf(`
resource "ad_ou" "test" {
  name      = %[1]q
  path      = "dc=example,dc=com"
  protected = %[2]t
}
`, name, protected)
}

func testAccOUResourceConfig_nested(parentName, childName string) string {
	return fmt.Sprintf(`
resource "ad_ou" "parent" {
  name = %[1]q
  path = "dc=example,dc=com"
}

resource "ad_ou" "child" {
  name = %[2]q
  path = ad_ou.parent.dn
}
`, parentName, childName)
}

func testAccOUResourceConfig_multiple(name1, name2, name3 string) string {
	return fmt.Sprintf(`
resource "ad_ou" "test1" {
  name = %[1]q
  path = "dc=example,dc=com"
}

resource "ad_ou" "test2" {
  name = %[2]q
  path = "dc=example,dc=com"
}

resource "ad_ou" "test3" {
  name = %[3]q
  path = "dc=example,dc=com"
}
`, name1, name2, name3)
}
