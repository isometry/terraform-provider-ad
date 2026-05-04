package provider_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
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
					resource.TestCheckResourceAttr("ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
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
			// Idempotency spot-check: replanning the same config must produce
			// an empty diff. Guards against computed-attribute drift.
			{
				Config:             testAccGroupResourceConfig_basic("tf-test-group-basic", "TFTestGroupBasic"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
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
					resource.TestCheckResourceAttr("ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
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
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-global-security", "TFTestGlobalSec", "global", "security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
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
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-global-dist", "TFTestGlobalDist", "global", "distribution"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "distribution"),
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
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-universal-security", "TFTestUnivSec", "universal", "security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "universal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
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
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-universal-dist", "TFTestUnivDist", "universal", "distribution"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "universal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "distribution"),
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
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-domainlocal-security", "TFTestDLSec", "domainlocal", "security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "domainlocal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
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
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-domainlocal-dist", "TFTestDLDist", "domainlocal", "distribution"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "domainlocal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "distribution"),
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
					resource.TestCheckResourceAttr("ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
				),
			},
			// Update name and description
			{
				Config: testAccGroupResourceConfig_withDescription("tf-test-group-updated", "TFTestGroupUpd", "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-updated"),
					resource.TestCheckResourceAttr("ad_group.test", "description", "Updated description"),
					resource.TestCheckResourceAttr("ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
				),
			},
			// Remove description — Read surfaces a cleared description as null
			// via helpers.StringOrNull, so assert absence rather than "".
			{
				Config: testAccGroupResourceConfig_basic("tf-test-group-updated", "TFTestGroupUpd"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-updated"),
					resource.TestCheckNoResourceAttr("ad_group.test", "description"),
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
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-scope-change", "TFTestScopeChg", "global", "security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
				),
			},
			// Change to Universal
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-scope-change", "TFTestScopeChg", "universal", "security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "universal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
				),
			},
			// Change to DomainLocal
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-scope-change", "TFTestScopeChg", "domainlocal", "security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "domainlocal"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
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
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-category-change", "TFTestCatChg", "global", "security"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
				),
			},
			// Change to Distribution
			{
				Config: testAccGroupResourceConfig_scopeCategory("tf-test-category-change", "TFTestCatChg", "global", "distribution"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "distribution"),
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
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName, DefaultTestContainer)
}

func testAccGroupResourceConfig_withDescription(name, samName, description string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_group" "test" {
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  description      = %[5]q
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName, description, DefaultTestContainer)
}

func testAccGroupResourceConfig_scopeCategory(name, samName, scope, category string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_group" "test" {
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[7]s,${data.ad_rootdse.test.default_naming_context}"
  scope            = %[5]q
  category         = %[6]q
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName, scope, category, DefaultTestContainer)
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
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName, container)
}

func testAccGroupResourceConfig_withContainerAndDescription(name, samName, container, description string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_group" "test" {
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
  description      = %[6]q
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName, container, description)
}

// Test helper to store the initial GUID for comparison.
var storedGUID string

//nolint:unparam // resourceName kept for call-site readability across tests
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
			// Create group without managed_by — Read surfaces an unset
			// managedBy as null via helpers.StringOrNull; assert absence.
			{
				Config: testAccGroupResourceConfig_basic("tf-test-group-no-manager", "TFTestGroupNoMgr"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-no-manager"),
					resource.TestCheckResourceAttr("ad_group.test", "sam_account_name", "TFTestGroupNoMgr"),
					resource.TestCheckNoResourceAttr("ad_group.test", "managed_by"),
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
			// Clear managed_by by omitting the attribute. The Optional-only
			// schema turns config-null into plan-null; the Update path's
			// helpers.StringChanged converts plan-null + non-null state into
			// an LDAP clear (&"").
			{
				Config: testAccGroupResourceConfig_basic("tf-test-group-mgr-update", "TFTestGroupMgrUpd"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", "tf-test-group-mgr-update"),
					resource.TestCheckNoResourceAttr("ad_group.test", "managed_by"),
				),
			},
			// Confirm idempotency: re-planning the managed_by-absent config
			// yields an empty diff.
			{
				Config:             testAccGroupResourceConfig_basic("tf-test-group-mgr-update", "TFTestGroupMgrUpd"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
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
  name             = "%[3]s-manager"
  sam_account_name = "%[4]sManager"
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_group" "test" {
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
  managed_by       = ad_group.manager.dn
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName, DefaultTestContainer)
}

func testAccGroupResourceConfig_withDifferentManagedBy(name, samName string) string {
	return fmt.Sprintf(`
%s

%s

# Create first manager group (not used in this step)
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[4]sManager"
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}

# Create second manager group to use as managed_by
resource "ad_group" "manager2" {
  name             = "%[3]s-manager2"
  sam_account_name = "%[4]sManager2"
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_group" "test" {
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
  managed_by       = ad_group.manager2.dn
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName, DefaultTestContainer)
}

func testAccGroupResourceConfig_withManagedByAndDescription(name, samName, description string) string {
	return fmt.Sprintf(`
%s

%s

# Create a manager group to use as managed_by
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[4]sManager"
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_group" "test" {
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  description      = %[5]q
  managed_by       = ad_group.manager.dn
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName, description, DefaultTestContainer)
}

func testAccGroupResourceConfig_withDifferentManagedByAndDescription(name, samName, description string) string {
	return fmt.Sprintf(`
%s

%s

# Create first manager group (not used in this step)
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[4]sManager"
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
}

# Create second manager group to use as managed_by
resource "ad_group" "manager2" {
  name             = "%[3]s-manager2"
  sam_account_name = "%[4]sManager2"
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_group" "test" {
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  description      = %[5]q
  managed_by       = ad_group.manager2.dn
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName, description, DefaultTestContainer)
}

// TestAccGroupResource_updateFlow drives a sequence of updates against a
// single ad_group resource and verifies that:
//
//   - the description can be added, changed, and removed;
//   - the managed_by DN can be set, swapped to a different principal, and
//     cleared;
//   - the group's scope can be changed (global -> universal is a legal AD
//     transition; direct global <-> domainlocal changes would be rejected
//     by AD, so the test avoids them);
//   - the objectGUID (resource ID) is preserved across every update — the
//     resource is updated in place, never replaced.
func TestAccGroupResource_updateFlow(t *testing.T) {
	name := GenerateTestName("tf-test-grp-updflow-")
	samName := GenerateTestSAMName("TFGUpdFlow")
	managerName := name + "-manager"
	managerSAM := samName + "Mgr"
	managerName2 := name + "-manager2"
	managerSAM2 := samName + "Mg2"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: baseline global/security group with no description and
			// no manager. Capture the initial GUID for later comparison.
			{
				Config: testAccGroupResourceConfig_updFlowBase(name, samName, managerName, managerSAM, managerName2, managerSAM2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", name),
					resource.TestCheckResourceAttr("ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("ad_group.test", "category", "security"),
					testAccStoreGroupGUID("ad_group.test"),
				),
			},
			// Step 2: add description and managed_by in one apply.
			{
				Config: testAccGroupResourceConfig_updFlowWithDescAndManager(
					name, samName, managerName, managerSAM, managerName2, managerSAM2,
					"initial description",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "description", "initial description"),
					resource.TestCheckResourceAttrPair("ad_group.test", "managed_by", "ad_group.manager", "dn"),
					testAccCheckGroupGUIDUnchanged(),
				),
			},
			// Step 3: change both description and managed_by in one apply.
			{
				Config: testAccGroupResourceConfig_updFlowWithDescAndManager2(
					name, samName, managerName, managerSAM, managerName2, managerSAM2,
					"updated description",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "description", "updated description"),
					resource.TestCheckResourceAttrPair("ad_group.test", "managed_by", "ad_group.manager2", "dn"),
					testAccCheckGroupGUIDUnchanged(),
				),
			},
			// Step 4: change scope global -> universal (legal AD transition)
			// while keeping description and managed_by.
			{
				Config: testAccGroupResourceConfig_updFlowScopeUniversal(
					name, samName, managerName, managerSAM, managerName2, managerSAM2,
					"updated description",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "universal"),
					resource.TestCheckResourceAttr("ad_group.test", "description", "updated description"),
					resource.TestCheckResourceAttrPair("ad_group.test", "managed_by", "ad_group.manager2", "dn"),
					testAccCheckGroupGUIDUnchanged(),
				),
			},
			// Step 5: drop description and managed_by back to baseline while
			// keeping the now-universal scope. Confirms clearing optional
			// attributes works and GUID is still preserved.
			{
				Config: testAccGroupResourceConfig_updFlowScopeUniversalBare(
					name, samName, managerName, managerSAM, managerName2, managerSAM2,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "scope", "universal"),
					testAccCheckGroupGUIDUnchanged(),
				),
			},
		},
	})
}

// Helper: common manager-group block used by every updFlow config. Emitting
// both manager groups in every step keeps the resource graph stable so that
// only ad_group.test's own fields change between steps.
func updFlowManagersBlock(managerName, managerSAM, managerName2, managerSAM2 string) string {
	return fmt.Sprintf(`
resource "ad_group" "manager" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_group" "manager2" {
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}
`, managerName, managerSAM, managerName2, managerSAM2, DefaultTestContainer)
}

func testAccGroupResourceConfig_updFlowBase(name, samName, mgrName, mgrSAM, mgrName2, mgrSAM2 string) string {
	return fmt.Sprintf(`
%s

%s

%s

resource "ad_group" "test" {
  name             = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource(),
		updFlowManagersBlock(mgrName, mgrSAM, mgrName2, mgrSAM2),
		name, samName, DefaultTestContainer)
}

func testAccGroupResourceConfig_updFlowWithDescAndManager(name, samName, mgrName, mgrSAM, mgrName2, mgrSAM2, description string) string {
	return fmt.Sprintf(`
%s

%s

%s

resource "ad_group" "test" {
  name             = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  description      = %[7]q
  managed_by       = ad_group.manager.dn
}
`, testProviderConfig(), testRootDSEDataSource(),
		updFlowManagersBlock(mgrName, mgrSAM, mgrName2, mgrSAM2),
		name, samName, DefaultTestContainer, description)
}

func testAccGroupResourceConfig_updFlowWithDescAndManager2(name, samName, mgrName, mgrSAM, mgrName2, mgrSAM2, description string) string {
	return fmt.Sprintf(`
%s

%s

%s

resource "ad_group" "test" {
  name             = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  description      = %[7]q
  managed_by       = ad_group.manager2.dn
}
`, testProviderConfig(), testRootDSEDataSource(),
		updFlowManagersBlock(mgrName, mgrSAM, mgrName2, mgrSAM2),
		name, samName, DefaultTestContainer, description)
}

func testAccGroupResourceConfig_updFlowScopeUniversal(name, samName, mgrName, mgrSAM, mgrName2, mgrSAM2, description string) string {
	return fmt.Sprintf(`
%s

%s

%s

resource "ad_group" "test" {
  name             = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  scope            = "universal"
  category         = "security"
  description      = %[7]q
  managed_by       = ad_group.manager2.dn
}
`, testProviderConfig(), testRootDSEDataSource(),
		updFlowManagersBlock(mgrName, mgrSAM, mgrName2, mgrSAM2),
		name, samName, DefaultTestContainer, description)
}

func testAccGroupResourceConfig_updFlowScopeUniversalBare(name, samName, mgrName, mgrSAM, mgrName2, mgrSAM2 string) string {
	return fmt.Sprintf(`
%s

%s

%s

resource "ad_group" "test" {
  name             = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  scope            = "universal"
  category         = "security"
}
`, testProviderConfig(), testRootDSEDataSource(),
		updFlowManagersBlock(mgrName, mgrSAM, mgrName2, mgrSAM2),
		name, samName, DefaultTestContainer)
}

// TestAccGroupResource_specialCharsInName exercises the DN-escaping path
// through ldap.EscapeDN for group RDNs (CN=). The group-name schema only
// rejects `"`, so characters that require RFC 4514 escaping in the RDN —
// comma, plus, semicolon, less-than, greater-than, backslash, equals,
// leading `#`, and leading/trailing spaces — are all valid inputs.
//
// Verifies:
//   - Create succeeds and the DN contains the properly-escaped RDN.
//   - Import-by-DN works (exercises unescape-on-read + re-escape-on-build).
//
// Covers TEST_PLAN.md #4: DN Escaping Fix (group side).
func TestAccGroupResource_specialCharsInName(t *testing.T) {
	cases := []struct {
		label string
		name  string
	}{
		{label: "comma", name: "tf-test-grp-comma," + groupUniqueSuffix()},
		{label: "plus", name: "tf-test-grp-plus+" + groupUniqueSuffix()},
		{label: "semicolon", name: "tf-test-grp-semi;" + groupUniqueSuffix()},
		{label: "leading_space", name: " tf-test-grp-ls-" + groupUniqueSuffix()},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			// SAM account names can't contain the special chars we're testing,
			// so derive a SAM that uses only [a-zA-Z0-9._-].
			samName := GenerateTestSAMName("g")
			expectedEscaped := escapeGroupNameForDN(tc.name)
			expectedDNPrefix := "CN=" + expectedEscaped + ","

			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				CheckDestroy: func(s *terraform.State) error {
					return testCheckGroupDestroy(t.Context(), s)
				},
				Steps: []resource.TestStep{
					// Create: DN contains the properly-escaped RDN.
					{
						Config: testAccGroupResourceConfig_basic(tc.name, samName),
						Check: resource.ComposeAggregateTestCheckFunc(
							testCheckGroupExists(t.Context(), "ad_group.test"),
							resource.TestCheckResourceAttr("ad_group.test", "name", tc.name),
							resource.TestCheckResourceAttrWith("ad_group.test", "dn", func(value string) error {
								if !strings.HasPrefix(value, expectedDNPrefix) {
									return fmt.Errorf("expected DN to start with %q, got: %s", expectedDNPrefix, value)
								}
								return nil
							}),
						),
					},
					// Import-by-DN: exercises unescape on read + re-escape on build.
					{
						ResourceName: "ad_group.test",
						ImportState:  true,
						ImportStateIdFunc: func(s *terraform.State) (string, error) {
							rs, ok := s.RootModule().Resources["ad_group.test"]
							if !ok {
								return "", fmt.Errorf("resource not found: ad_group.test")
							}
							return rs.Primary.Attributes["dn"], nil
						},
						ImportStateVerify: true,
					},
				},
			})
		})
	}
}

// TestAccGroupResource_dnPredictedAtPlan guards the ComputeDN plan modifier
// for ad_group (TEST_PLAN.md #2). Without this modifier, `dn` would be
// unknown during plan and the provider could report "inconsistent result
// after apply" when AD normalises the RDN case. With it, the predicted DN
// must be known at plan time and match the canonical form.
//
// The concrete domain suffix is unknown ahead of time (it depends on the
// test AD), so we assert the *shape* of the predicted DN via a regex rather
// than an exact string match.
func TestAccGroupResource_dnPredictedAtPlan(t *testing.T) {
	name1 := GenerateTestName(TestGroupPrefix + "plandn-")
	name2 := GenerateTestName(TestGroupPrefix + "plandn2-")
	samName := GenerateTestSAMName("g")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckGroupDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Step 1: create. The predicted `dn` must be known at plan time
			// and match CN=<name>,... (RDN type is upper-cased by the
			// ComputeDN modifier).
			{
				Config: testAccGroupResourceConfig_basic(name1, samName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(
							"ad_group.test",
							tfjsonpath.New("dn"),
							knownvalue.StringRegexp(regexp.MustCompile(
								`^CN=`+regexp.QuoteMeta(name1)+`,.+$`,
							)),
						),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", name1),
					resource.TestCheckResourceAttrSet("ad_group.test", "dn"),
				),
			},
			// Step 2: rename. The predicted DN must shift to reflect the new
			// RDN while remaining known at plan time.
			{
				Config: testAccGroupResourceConfig_basic(name2, samName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(
							"ad_group.test",
							tfjsonpath.New("dn"),
							knownvalue.StringRegexp(regexp.MustCompile(
								`^CN=`+regexp.QuoteMeta(name2)+`,.+$`,
							)),
						),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.test", "name", name2),
				),
			},
		},
	})
}

// escapeGroupNameForDN mirrors ldap.EscapeDN for the characters exercised by
// TestAccGroupResource_specialCharsInName (RFC 4514: `"`, `+`, `,`, `;`,
// `<`, `>`, `\`, plus leading `#` and leading/trailing space). Replicated
// here to keep the expected value obvious at the call site without pulling
// go-ldap into the test package just for this helper.
func escapeGroupNameForDN(s string) string {
	if s == "" {
		return ""
	}
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		if (i == 0 || i == len(runes)-1) && r == ' ' {
			b.WriteRune('\\')
			b.WriteRune(r)
			continue
		}
		if i == 0 && r == '#' {
			b.WriteRune('\\')
			b.WriteRune(r)
			continue
		}
		switch r {
		case '"', '+', ',', ';', '<', '>', '\\':
			b.WriteRune('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// groupUniqueSuffix returns a short suffix suitable for embedding in group
// test names. Uses GenerateTestName with an empty prefix so the call sites
// can focus on the interesting (special-character) part of the name.
func groupUniqueSuffix() string {
	return GenerateTestName("")
}

// Note: testAccPreCheck is defined in provider_test.go
