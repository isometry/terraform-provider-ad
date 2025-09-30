package provider_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccGroupResource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccGroupResourceConfig_basic("tf-test-group-basic", "TFTestGroupBasic"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-basic"),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", "TFTestGroupBasic"),
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
					resource.TestCheckResourceAttrSet("ad_group.test", "id"),
					resource.TestCheckResourceAttrSet("ad_group.test", "dn"),
					resource.TestCheckResourceAttrSet("ad_group.test", "sid"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "ad_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccGroupResource_withDescription(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with description
			{
				Config: testAccGroupResourceConfig_withDescription("tf-test-group-desc", "TFTestGroupDesc", "Test group with description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-desc"),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", "TFTestGroupDesc"),
					resource.TestCheckResourceAttr("ad_group.test", "description", "Test group with description"),
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
				),
			},
		},
	})
}

func TestAccGroupResource_globalSecurity(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-global-security", "TFTestGlobalSec", "Global", "Security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
					// Global Security group type is 0x80000002 = -2147483646
				),
			},
		},
	})
}

func TestAccGroupResource_globalDistribution(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-global-dist", "TFTestGlobalDist", "Global", "Distribution"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Distribution"),
					// Global Distribution group type is 0x00000002 = 2
				),
			},
		},
	})
}

func TestAccGroupResource_universalSecurity(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-universal-security", "TFTestUnivSec", "Universal", "Security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Universal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
					// Universal Security group type is 0x80000008 = -2147483640
				),
			},
		},
	})
}

func TestAccGroupResource_universalDistribution(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-universal-dist", "TFTestUnivDist", "Universal", "Distribution"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Universal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Distribution"),
					// Universal Distribution group type is 0x00000008 = 8
				),
			},
		},
	})
}

func TestAccGroupResource_domainLocalSecurity(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-domainlocal-security", "TFTestDLSec", "DomainLocal", "Security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "DomainLocal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
					// DomainLocal Security group type is 0x80000004 = -2147483644
				),
			},
		},
	})
}

func TestAccGroupResource_domainLocalDistribution(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-domainlocal-dist", "TFTestDLDist", "DomainLocal", "Distribution"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "DomainLocal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Distribution"),
					// DomainLocal Distribution group type is 0x00000004 = 4
				),
			},
		},
	})
}

func TestAccGroupResource_update(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create initial group
			{
				Config: testAccGroupResourceConfig_withDescription("tf-test-group-update", "TFTestGroupUpd", "Original description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-update"),
					resource.TestCheckResourceAttr("ad_group.test", "description", "Original description"),
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
				),
			},
			// Update name and description
			{
				Config: testAccGroupResourceConfig_withDescription("tf-test-group-updated", "TFTestGroupUpd", "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-updated"),
					resource.TestCheckResourceAttr("ad_group.test", "description", "Updated description"),
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
				),
			},
			// Remove description
			{
				Config: testAccGroupResourceConfig_basic("tf-test-group-updated", "TFTestGroupUpd"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-updated"),
					resource.TestCheckResourceAttr("ad_group.test", "description", ""),
				),
			},
		},
	})
}

func TestAccGroupResource_scopeChange(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create Global group
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-scope-change", "TFTestScopeChg", "Global", "Security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
				),
			},
			// Change to Universal
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-scope-change", "TFTestScopeChg", "Universal", "Security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Universal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
				),
			},
			// Change to DomainLocal
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-scope-change", "TFTestScopeChg", "DomainLocal", "Security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "DomainLocal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
				),
			},
		},
	})
}

func TestAccGroupResource_categoryChange(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create Security group
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-category-change", "TFTestCatChg", "Global", "Security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Security"),
				),
			},
			// Change to Distribution
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-category-change", "TFTestCatChg", "Global", "Distribution"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "Global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "Distribution"),
				),
			},
		},
	})
}

func TestAccGroupResource_importByGUID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group
			{
				Config: testAccGroupResourceConfig_basic("tf-test-import-guid", "TFTestImportGUID"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-import-guid"),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", "TFTestImportGUID"),
				),
			},
			// Import by GUID
			{
				ResourceName:      "ad_group.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccGroupImportStateIdFunc,
			},
		},
	})
}

func TestAccGroupResource_importByDN(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group
			{
				Config: testAccGroupResourceConfig_basic("tf-test-import-dn", "TFTestImportDN"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-import-dn"),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", "TFTestImportDN"),
				),
			},
			// Import by DN
			{
				ResourceName:      "ad_group.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccGroupImportStateIdFuncDN,
			},
		},
	})
}

func TestAccGroupResource_largeValues(t *testing.T) {
	// Test with maximum length values
	longName := "This-is-a-very-long-group-name-that-approaches-the-64-char-limit"
	longSAMName := "TFTestLongSAMName20" // 20 characters (max for SAM)
	longDescription := "This is a very long description that tests the maximum length allowed for group descriptions in Active Directory which should be able to handle up to 1024 characters of text without any issues and this should help us verify that our validation and handling of longer descriptions works correctly in all scenarios including edge cases where users might want to provide detailed information about the purpose and usage of their Active Directory groups and this text should be long enough to test that functionality thoroughly and completely within the bounds of what Active Directory supports for group description fields and ensuring that our Terraform provider handles these cases gracefully and without errors during creation, updates, and reads of the group resources in question and providing comprehensive coverage of this particular test scenario."

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupResourceConfig_withDescription(longName, longSAMName, longDescription),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", longName),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", longSAMName),
					resource.TestCheckResourceAttr("ad_group.test", "description", longDescription),
				),
			},
		},
	})
}

func TestAccGroupResource_disappears(t *testing.T) {
	ctx := t.Context()
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckGroupDestroy(ctx, s)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGroupResourceConfig_basic("tf-test-disappears", "TFTestDisappears"),
				Check: resource.ComposeTestCheckFunc(
					testCheckGroupExists(ctx, "ad_group.test"),
					testCheckGroupDisappears(ctx, "ad_group.test"),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Helper functions for test configurations.
func testAccGroupResourceConfig_basic(name, samName string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[3]s,${data.ad_domain.test.dn}"
}
`, testProviderConfig(), testDomainDataSource(), name, samName, DefaultTestContainer)
}

func testAccGroupResourceConfig_withDescription(name, samName, description string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[4]s,${data.ad_domain.test.dn}"
  description      = %[3]q
}
`, testProviderConfig(), testDomainDataSource(), name, samName, description, DefaultTestContainer)
}

func testAccGroupResourceConfig_scopeCategory(name, samName, scope, category string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[5]s,${data.ad_domain.test.dn}"
  scope            = %[3]q
  category         = %[4]q
}
`, testProviderConfig(), testDomainDataSource(), name, samName, scope, category, DefaultTestContainer)
}

// Helper functions for import testing.
func testAccGroupImportStateIdFunc(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources["ad_group.test"]
	if !ok {
		return "", fmt.Errorf("not found: %s", "ad_group.test")
	}

	return rs.Primary.Attributes["id"], nil
}

func testAccGroupImportStateIdFuncDN(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources["ad_group.test"]
	if !ok {
		return "", fmt.Errorf("not found: %s", "ad_group.test")
	}

	return rs.Primary.Attributes["dn"], nil
}

// Helper functions for existence and destroy testing are now called directly.

func TestAccGroupResource_containerMove(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group in default container
			{
				Config: testAccGroupResourceConfig_basic("tf-test-container-move", "TFTestContainerMove"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-container-move"),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", "TFTestContainerMove"),
					resource.TestCheckResourceAttrSet("ad_group.test", "id"),
					resource.TestCheckResourceAttrSet("ad_group.test", "dn"),
					// Verify GUID remains the same throughout
					testAccStoreGroupGUID("ad_group.test"),
				),
			},
			// Move to different container
			{
				Config: testAccGroupResourceConfig_withContainer("tf-test-container-move", "TFTestContainerMove", "CN=Users"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-container-move"),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", "TFTestContainerMove"),
					// Verify GUID is preserved after move
					testAccCheckGroupGUIDUnchanged(),
					// Verify DN has changed to reflect new container
					resource.TestCheckResourceAttrWith("ad_group.test", "dn", func(value string) error {
						if !strings.Contains(value, "CN=Users") {
							return fmt.Errorf("expected DN to contain CN=Users, got: %s", value)
						}
						return nil
					}),
				),
			},
			// Move back to original container
			{
				Config: testAccGroupResourceConfig_basic("tf-test-container-move", "TFTestContainerMove"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-container-move"),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", "TFTestContainerMove"),
					// Verify GUID is still preserved after second move
					testAccCheckGroupGUIDUnchanged(),
				),
			},
		},
	})
}

func TestAccGroupResource_containerMoveWithOtherChanges(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group with description
			{
				Config: testAccGroupResourceConfig_withDescription("tf-test-move-desc", "TFTestMoveDesc", "Original description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-move-desc"),
					resource.TestCheckResourceAttr("ad_group.test", "description", "Original description"),
					testAccStoreGroupGUID("ad_group.test"),
				),
			},
			// Move container and update description simultaneously
			{
				Config: testAccGroupResourceConfig_withContainerAndDescription("tf-test-move-desc", "TFTestMoveDesc", "CN=Users", "Updated description after move"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-move-desc"),
					resource.TestCheckResourceAttr("ad_group.test", "description", "Updated description after move"),
					// Verify GUID is preserved
					testAccCheckGroupGUIDUnchanged(),
					// Verify DN reflects new container
					resource.TestCheckResourceAttrWith("ad_group.test", "dn", func(value string) error {
						if !strings.Contains(value, "CN=Users") {
							return fmt.Errorf("expected DN to contain CN=Users, got: %s", value)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccGroupResource_containerMoveNoChange(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group
			{
				Config: testAccGroupResourceConfig_basic("tf-test-move-nochange", "TFTestMoveNoChange"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-move-nochange"),
					testAccStoreGroupGUID("ad_group.test"),
				),
			},
			// Apply same configuration (no actual move)
			{
				Config: testAccGroupResourceConfig_basic("tf-test-move-nochange", "TFTestMoveNoChange"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-move-nochange"),
					// Verify GUID remains unchanged (no recreation occurred)
					testAccCheckGroupGUIDUnchanged(),
				),
			},
		},
	})
}

// Additional test configuration helpers for container moves.
func testAccGroupResourceConfig_withContainer(name, samName, container string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[3]s,${data.ad_domain.test.dn}"
}
`, testProviderConfig(), testDomainDataSource(), name, samName, container)
}

func testAccGroupResourceConfig_withContainerAndDescription(name, samName, container, description string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[3]s,${data.ad_domain.test.dn}"
  description      = %[4]q
}
`, testProviderConfig(), testDomainDataSource(), name, samName, container, description)
}

// Test helper to store the initial GUID for comparison.
var storedGUID string

func testAccStoreGroupGUID(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}

		storedGUID = rs.Primary.Attributes["id"]
		if storedGUID == "" {
			return fmt.Errorf("group ID (GUID) is empty")
		}

		return nil
	}
}

func testAccCheckGroupGUIDUnchanged() resource.TestCheckFunc {
	const resourceName = "ad_group.test"
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}

		currentGUID := rs.Primary.Attributes["id"]
		if currentGUID != storedGUID {
			return fmt.Errorf("group GUID changed: expected %s, got %s", storedGUID, currentGUID)
		}

		return nil
	}
}

func TestAccGroupResource_managedBy(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group with managed_by specified
			{
				Config: testAccGroupResourceConfig_withManagedBy("tf-test-group-managed", "TFTestGroupManaged"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-managed"),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", "TFTestGroupManaged"),
					resource.TestCheckResourceAttrPair("ad_group.test", "managed_by", "ad_group.manager", "dn"),
				),
			},
			// ImportState testing - verify managed_by is imported
			{
				ResourceName:      "ad_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccGroupResource_managedByNotSpecified(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group without managed_by (computed field should be empty)
			{
				Config: testAccGroupResourceConfig_basic("tf-test-group-no-manager", "TFTestGroupNoMgr"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-no-manager"),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", "TFTestGroupNoMgr"),
					resource.TestCheckResourceAttr("ad_group.test", "managed_by", ""),
				),
			},
		},
	})
}

func TestAccGroupResource_managedByUpdate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group with initial managed_by
			{
				Config: testAccGroupResourceConfig_withManagedBy("tf-test-group-mgr-update", "TFTestGroupMgrUpd"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-mgr-update"),
					resource.TestCheckResourceAttrPair("ad_group.test", "managed_by", "ad_group.manager", "dn"),
				),
			},
			// Update managed_by to different manager
			{
				Config: testAccGroupResourceConfig_withDifferentManagedBy("tf-test-group-mgr-update", "TFTestGroupMgrUpd"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-mgr-update"),
					resource.TestCheckResourceAttrPair("ad_group.test", "managed_by", "ad_group.manager2", "dn"),
				),
			},
		},
	})
}

func TestAccGroupResource_managedByClear(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group with managed_by set
			{
				Config: testAccGroupResourceConfig_withManagedBy("tf-test-group-mgr-clear", "TFTestGroupMgrClr"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-mgr-clear"),
					resource.TestCheckResourceAttrPair("ad_group.test", "managed_by", "ad_group.manager", "dn"),
				),
			},
			// Remove managed_by from config (clear it)
			{
				Config: testAccGroupResourceConfig_basic("tf-test-group-mgr-clear", "TFTestGroupMgrClr"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-mgr-clear"),
					resource.TestCheckResourceAttr("ad_group.test", "managed_by", ""),
				),
			},
		},
	})
}

func TestAccGroupResource_managedByWithOtherChanges(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group with description and managed_by
			{
				Config: testAccGroupResourceConfig_withManagedByAndDescription("tf-test-group-mgr-combo", "TFTestGroupMgrCmb", "Initial description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-mgr-combo"),
					resource.TestCheckResourceAttr("ad_group.test", "description", "Initial description"),
					resource.TestCheckResourceAttrPair("ad_group.test", "managed_by", "ad_group.manager", "dn"),
				),
			},
			// Update both description and managed_by simultaneously
			{
				Config: testAccGroupResourceConfig_withDifferentManagedByAndDescription("tf-test-group-mgr-combo", "TFTestGroupMgrCmb", "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-mgr-combo"),
					resource.TestCheckResourceAttr("ad_group.test", "description", "Updated description"),
					resource.TestCheckResourceAttrPair("ad_group.test", "managed_by", "ad_group.manager2", "dn"),
				),
			},
		},
	})
}

// Helper functions for managed_by test configurations.

func testAccGroupResourceConfig_withManagedBy(name, samName string) string {
	return fmt.Sprintf(`
%s

%s

# Create a manager group to use as managed_by
resource "ad_group" "manager" {
  name             = "%[1]s-manager"
  sam_account_name = "%[2]sManager"
  container        = "%[3]s,${data.ad_domain.test.dn}"
}

resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[3]s,${data.ad_domain.test.dn}"
  managed_by       = ad_group.manager.dn
}
`, testProviderConfig(), testDomainDataSource(), name, samName, DefaultTestContainer)
}

func testAccGroupResourceConfig_withDifferentManagedBy(name, samName string) string {
	return fmt.Sprintf(`
%s

%s

# Create first manager group (not used in this step)
resource "ad_group" "manager" {
  name             = "%[1]s-manager"
  sam_account_name = "%[2]sManager"
  container        = "%[3]s,${data.ad_domain.test.dn}"
}

# Create second manager group to use as managed_by
resource "ad_group" "manager2" {
  name             = "%[1]s-manager2"
  sam_account_name = "%[2]sManager2"
  container        = "%[3]s,${data.ad_domain.test.dn}"
}

resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[3]s,${data.ad_domain.test.dn}"
  managed_by       = ad_group.manager2.dn
}
`, testProviderConfig(), testDomainDataSource(), name, samName, DefaultTestContainer)
}

func testAccGroupResourceConfig_withManagedByAndDescription(name, samName, description string) string {
	return fmt.Sprintf(`
%s

%s

# Create a manager group to use as managed_by
resource "ad_group" "manager" {
  name             = "%[1]s-manager"
  sam_account_name = "%[2]sManager"
  container        = "%[4]s,${data.ad_domain.test.dn}"
}

resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[4]s,${data.ad_domain.test.dn}"
  description      = %[3]q
  managed_by       = ad_group.manager.dn
}
`, testProviderConfig(), testDomainDataSource(), name, samName, description, DefaultTestContainer)
}

func testAccGroupResourceConfig_withDifferentManagedByAndDescription(name, samName, description string) string {
	return fmt.Sprintf(`
%s

%s

# Create first manager group (not used in this step)
resource "ad_group" "manager" {
  name             = "%[1]s-manager"
  sam_account_name = "%[2]sManager"
  container        = "%[4]s,${data.ad_domain.test.dn}"
}

# Create second manager group to use as managed_by
resource "ad_group" "manager2" {
  name             = "%[1]s-manager2"
  sam_account_name = "%[2]sManager2"
  container        = "%[4]s,${data.ad_domain.test.dn}"
}

resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[4]s,${data.ad_domain.test.dn}"
  description      = %[3]q
  managed_by       = ad_group.manager2.dn
}
`, testProviderConfig(), testDomainDataSource(), name, samName, description, DefaultTestContainer)
}

// Note: testAccPreCheck is defined in provider_test.go
