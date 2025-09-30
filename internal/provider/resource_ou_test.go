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

func TestAccOUResource_managedBy(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create OU with managed_by specified
			{
				Config: testAccOUResourceConfig_withManagedBy("tf-test-ou-managed"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-managed"),
					resource.TestCheckResourceAttrPair("ad_ou.test", "managed_by", "ad_group.manager", "dn"),
				),
			},
			// ImportState testing - verify managed_by is imported
			{
				ResourceName:      "ad_ou.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccOUResource_managedByNotSpecified(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create OU without managed_by (computed field should be empty)
			{
				Config: testAccOUResourceConfig_basic("tf-test-ou-no-manager"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-no-manager"),
					resource.TestCheckResourceAttr("ad_ou.test", "managed_by", ""),
				),
			},
		},
	})
}

func TestAccOUResource_managedByUpdate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create OU with initial managed_by
			{
				Config: testAccOUResourceConfig_withManagedBy("tf-test-ou-mgr-update"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-mgr-update"),
					resource.TestCheckResourceAttrPair("ad_ou.test", "managed_by", "ad_group.manager", "dn"),
				),
			},
			// Update managed_by to different manager
			{
				Config: testAccOUResourceConfig_withDifferentManagedBy("tf-test-ou-mgr-update"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-mgr-update"),
					resource.TestCheckResourceAttrPair("ad_ou.test", "managed_by", "ad_group.manager2", "dn"),
				),
			},
		},
	})
}

func TestAccOUResource_managedByClear(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create OU with managed_by set
			{
				Config: testAccOUResourceConfig_withManagedBy("tf-test-ou-mgr-clear"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-mgr-clear"),
					resource.TestCheckResourceAttrPair("ad_ou.test", "managed_by", "ad_group.manager", "dn"),
				),
			},
			// Remove managed_by from config (clear it)
			{
				Config: testAccOUResourceConfig_basic("tf-test-ou-mgr-clear"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-mgr-clear"),
					resource.TestCheckResourceAttr("ad_ou.test", "managed_by", ""),
				),
			},
		},
	})
}

func TestAccOUResource_managedByWithOtherChanges(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create OU with description and managed_by
			{
				Config: testAccOUResourceConfig_withManagedByAndDescription("tf-test-ou-mgr-combo", "Initial description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-mgr-combo"),
					resource.TestCheckResourceAttr("ad_ou.test", "description", "Initial description"),
					resource.TestCheckResourceAttrPair("ad_ou.test", "managed_by", "ad_group.manager", "dn"),
				),
			},
			// Update both description and managed_by simultaneously
			{
				Config: testAccOUResourceConfig_withDifferentManagedByAndDescription("tf-test-ou-mgr-combo", "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-mgr-combo"),
					resource.TestCheckResourceAttr("ad_ou.test", "description", "Updated description"),
					resource.TestCheckResourceAttrPair("ad_ou.test", "managed_by", "ad_group.manager2", "dn"),
				),
			},
		},
	})
}

func TestAccOUResource_managedByWithProtected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create protected OU with managed_by
			{
				Config: testAccOUResourceConfig_withManagedByAndProtected("tf-test-ou-mgr-prot", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-mgr-prot"),
					resource.TestCheckResourceAttr("ad_ou.test", "protected", "true"),
					resource.TestCheckResourceAttrPair("ad_ou.test", "managed_by", "ad_group.manager", "dn"),
				),
			},
			// Update protection status (managed_by unchanged)
			{
				Config: testAccOUResourceConfig_withManagedByAndProtected("tf-test-ou-mgr-prot", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-mgr-prot"),
					resource.TestCheckResourceAttr("ad_ou.test", "protected", "false"),
					resource.TestCheckResourceAttrPair("ad_ou.test", "managed_by", "ad_group.manager", "dn"),
				),
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

// Helper functions for managed_by test configurations.

func testAccOUResourceConfig_withManagedBy(name string) string {
	return fmt.Sprintf(`
%s

%s

# Create a manager group to use as managed_by
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[3]sManager"
  container        = "%[4]s,${data.ad_domain.test.dn}"
}

resource "ad_ou" "test" {
  name       = %[3]q
  path       = data.ad_domain.test.dn
  managed_by = ad_group.manager.dn
}
`, testProviderConfig(), testDomainDataSource(), name, DefaultTestContainer)
}

func testAccOUResourceConfig_withDifferentManagedBy(name string) string {
	return fmt.Sprintf(`
%s

%s

# Create first manager group (not used in this step)
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[3]sManager"
  container        = "%[4]s,${data.ad_domain.test.dn}"
}

# Create second manager group to use as managed_by
resource "ad_group" "manager2" {
  name             = "%[3]s-manager2"
  sam_account_name = "%[3]sManager2"
  container        = "%[4]s,${data.ad_domain.test.dn}"
}

resource "ad_ou" "test" {
  name       = %[3]q
  path       = data.ad_domain.test.dn
  managed_by = ad_group.manager2.dn
}
`, testProviderConfig(), testDomainDataSource(), name, DefaultTestContainer)
}

func testAccOUResourceConfig_withManagedByAndDescription(name, description string) string {
	return fmt.Sprintf(`
%s

%s

# Create a manager group to use as managed_by
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[3]sManager"
  container        = "%[5]s,${data.ad_domain.test.dn}"
}

resource "ad_ou" "test" {
  name        = %[3]q
  path        = data.ad_domain.test.dn
  description = %[4]q
  managed_by  = ad_group.manager.dn
}
`, testProviderConfig(), testDomainDataSource(), name, description, DefaultTestContainer)
}

func testAccOUResourceConfig_withDifferentManagedByAndDescription(name, description string) string {
	return fmt.Sprintf(`
%s

%s

# Create first manager group (not used in this step)
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[3]sManager"
  container        = "%[5]s,${data.ad_domain.test.dn}"
}

# Create second manager group to use as managed_by
resource "ad_group" "manager2" {
  name             = "%[3]s-manager2"
  sam_account_name = "%[3]sManager2"
  container        = "%[5]s,${data.ad_domain.test.dn}"
}

resource "ad_ou" "test" {
  name        = %[3]q
  path        = data.ad_domain.test.dn
  description = %[4]q
  managed_by  = ad_group.manager2.dn
}
`, testProviderConfig(), testDomainDataSource(), name, description, DefaultTestContainer)
}

func testAccOUResourceConfig_withManagedByAndProtected(name string, protected bool) string {
	return fmt.Sprintf(`
%s

%s

# Create a manager group to use as managed_by
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[3]sManager"
  container        = "%[5]s,${data.ad_domain.test.dn}"
}

resource "ad_ou" "test" {
  name       = %[3]q
  path       = data.ad_domain.test.dn
  protected  = %[4]t
  managed_by = ad_group.manager.dn
}
`, testProviderConfig(), testDomainDataSource(), name, protected, DefaultTestContainer)
}
