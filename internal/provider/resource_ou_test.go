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
			// Idempotency spot-check: replanning the same config must produce
			// an empty diff. Guards against computed-attribute drift.
			{
				Config:             testAccOUResourceConfig_basic("tf-test-ou-basic"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
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
			// Remove description — Read surfaces a cleared description as null
			// via helpers.StringOrNull, so assert absence rather than "".
			{
				Config: testAccOUResourceConfig_basic("tf-test-ou-update"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("ad_ou.test", "description"),
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
			// Create OU without managed_by — attribute is null in state when not set.
			{
				Config: testAccOUResourceConfig_basic("tf-test-ou-no-manager"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-no-manager"),
					resource.TestCheckNoResourceAttr("ad_ou.test", "managed_by"),
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
			// Clear managed_by by omitting the attribute. The Optional-only
			// schema turns config-null into plan-null; the Update path's
			// helpers.StringChanged converts plan-null + non-null state into
			// an LDAP clear (&"").
			{
				Config: testAccOUResourceConfig_basic("tf-test-ou-mgr-update"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", "tf-test-ou-mgr-update"),
					resource.TestCheckNoResourceAttr("ad_ou.test", "managed_by"),
				),
			},
			// Confirm idempotency: re-planning the managed_by-absent config
			// yields an empty diff.
			{
				Config:             testAccOUResourceConfig_basic("tf-test-ou-mgr-update"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
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
%s

%s

resource "ad_ou" "test" {
  name = %[3]q
  path = "${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource(), name)
}

func testAccOUResourceConfig_withDescription(name, description string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_ou" "test" {
  name        = %[3]q
  path        = "${data.ad_rootdse.test.default_naming_context}"
  description = %[4]q
}
`, testProviderConfig(), testRootDSEDataSource(), name, description)
}

func testAccOUResourceConfig_protected(name string, protected bool) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_ou" "test" {
  name      = %[3]q
  path      = "${data.ad_rootdse.test.default_naming_context}"
  protected = %[4]t
}
`, testProviderConfig(), testRootDSEDataSource(), name, protected)
}

func testAccOUResourceConfig_nested(parentName, childName string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_ou" "parent" {
  name = %[3]q
  path = "${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_ou" "child" {
  name = %[4]q
  path = ad_ou.parent.dn
}
`, testProviderConfig(), testRootDSEDataSource(), parentName, childName)
}

func testAccOUResourceConfig_multiple(name1, name2, name3 string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_ou" "test1" {
  name = %[3]q
  path = "${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_ou" "test2" {
  name = %[4]q
  path = "${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_ou" "test3" {
  name = %[5]q
  path = "${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource(), name1, name2, name3)
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
  container        = "%[4]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_ou" "test" {
  name       = %[3]q
  path       = data.ad_rootdse.test.default_naming_context
  managed_by = ad_group.manager.dn
}
`, testProviderConfig(), testRootDSEDataSource(), name, DefaultTestContainer)
}

func testAccOUResourceConfig_withDifferentManagedBy(name string) string {
	return fmt.Sprintf(`
%s

%s

# Create first manager group (not used in this step)
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[3]sManager"
  container        = "%[4]s,${data.ad_rootdse.test.default_naming_context}"
}

# Create second manager group to use as managed_by
resource "ad_group" "manager2" {
  name             = "%[3]s-manager2"
  sam_account_name = "%[3]sManager2"
  container        = "%[4]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_ou" "test" {
  name       = %[3]q
  path       = data.ad_rootdse.test.default_naming_context
  managed_by = ad_group.manager2.dn
}
`, testProviderConfig(), testRootDSEDataSource(), name, DefaultTestContainer)
}

func testAccOUResourceConfig_withManagedByAndDescription(name, description string) string {
	return fmt.Sprintf(`
%s

%s

# Create a manager group to use as managed_by
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[3]sManager"
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_ou" "test" {
  name        = %[3]q
  path        = data.ad_rootdse.test.default_naming_context
  description = %[4]q
  managed_by  = ad_group.manager.dn
}
`, testProviderConfig(), testRootDSEDataSource(), name, description, DefaultTestContainer)
}

func testAccOUResourceConfig_withDifferentManagedByAndDescription(name, description string) string {
	return fmt.Sprintf(`
%s

%s

# Create first manager group (not used in this step)
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[3]sManager"
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}

# Create second manager group to use as managed_by
resource "ad_group" "manager2" {
  name             = "%[3]s-manager2"
  sam_account_name = "%[3]sManager2"
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_ou" "test" {
  name        = %[3]q
  path        = data.ad_rootdse.test.default_naming_context
  description = %[4]q
  managed_by  = ad_group.manager2.dn
}
`, testProviderConfig(), testRootDSEDataSource(), name, description, DefaultTestContainer)
}

func testAccOUResourceConfig_withManagedByAndProtected(name string, protected bool) string {
	return fmt.Sprintf(`
%s

%s

# Create a manager group to use as managed_by
resource "ad_group" "manager" {
  name             = "%[3]s-manager"
  sam_account_name = "%[3]sManager"
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_ou" "test" {
  name       = %[3]q
  path       = data.ad_rootdse.test.default_naming_context
  protected  = %[4]t
  managed_by = ad_group.manager.dn
}
`, testProviderConfig(), testRootDSEDataSource(), name, protected, DefaultTestContainer)
}

// TestAccOUResource_protectedDeletion verifies that Terraform refuses to
// delete an OU marked protected=true and surfaces a clear error instead. Only
// after the user explicitly flips protected=false should deletion succeed.
//
// The test sequence:
//  1. Create OU with protected=true.
//  2. Invoke a Destroy step with ExpectError; the provider's Delete must
//     return a "protected from accidental deletion" diagnostic.
//  3. Re-apply with protected=false to unprotect the OU. This leaves the
//     resource in state so that the automatic end-of-test teardown can
//     destroy it cleanly.
func TestAccOUResource_protectedDeletion(t *testing.T) {
	name := GenerateTestName("tf-test-ou-protdel-")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create protected OU.
			{
				Config: testAccOUResourceConfig_protected(name, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", name),
					resource.TestCheckResourceAttr("ad_ou.test", "protected", "true"),
				),
			},
			// Step 2: a destroy-only step that attempts to remove the OU
			// while it's still protected. The provider must refuse with a
			// clear diagnostic.
			{
				Config:      testAccOUResourceConfig_protected(name, true),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`(?s)(protected from accidental deletion|Error Deleting Protected OU|cannot delete protected OU)`),
			},
			// Step 3: unprotect the OU so the framework's end-of-test
			// teardown can destroy it without leaking state.
			{
				Config: testAccOUResourceConfig_protected(name, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", name),
					resource.TestCheckResourceAttr("ad_ou.test", "protected", "false"),
				),
			},
		},
	})
}

// TestAccOUResource_rename verifies the in-place rename path that replaced the
// previous RequiresReplace semantics for `name`. Changing `name` must trigger
// an LDAP ModifyDN (rename) rather than a destroy/create cycle, so the
// objectGUID — captured in step 1 and compared in step 2 — must survive.
//
// Covers TEST_PLAN.md #1: OU rename via ModifyDN.
func TestAccOUResource_rename(t *testing.T) {
	name1 := GenerateTestName(TestOUPrefix + "rename-")
	name2 := GenerateTestName(TestOUPrefix + "rename2-")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckOUDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Step 1: create OU with original name, capture GUID.
			{
				Config: testAccOUResourceConfig_basic(name1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", name1),
					resource.TestCheckResourceAttrSet("ad_ou.test", "dn"),
					testAccStoreOUGUID("ad_ou.test"),
					// Sanity: initial DN contains the original name.
					resource.TestCheckResourceAttrWith("ad_ou.test", "dn", func(value string) error {
						if !strings.Contains(strings.ToUpper(value), "OU="+strings.ToUpper(name1)+",") {
							return fmt.Errorf("expected DN to contain OU=%s, got: %s", name1, value)
						}
						return nil
					}),
				),
			},
			// Step 2: rename to a new `name`, assert GUID preserved and DN
			// reflects the new RDN.
			{
				Config: testAccOUResourceConfig_basic(name2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", name2),
					testAccCheckOUGUIDUnchanged(),
					resource.TestCheckResourceAttrWith("ad_ou.test", "dn", func(value string) error {
						if !strings.Contains(strings.ToUpper(value), "OU="+strings.ToUpper(name2)+",") {
							return fmt.Errorf("expected DN to contain OU=%s, got: %s", name2, value)
						}
						return nil
					}),
				),
			},
			// Step 3: re-plan with same config — state should be stable.
			{
				Config:             testAccOUResourceConfig_basic(name2),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccOUResource_move verifies the in-place move path. Changing `path`
// must trigger an LDAP ModifyDN (move) rather than a destroy/create cycle, so
// the child OU's objectGUID must survive the move and the reported DN must
// sit under the new parent.
//
// Covers TEST_PLAN.md #1: OU move via ModifyDN.
func TestAccOUResource_move(t *testing.T) {
	parent1 := GenerateTestName(TestOUPrefix + "move-p1-")
	parent2 := GenerateTestName(TestOUPrefix + "move-p2-")
	child := GenerateTestName(TestOUPrefix + "move-c-")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckOUDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Step 1: create two parents + a child nested under parent1.
			{
				Config: testAccOUResourceConfig_moveScenario(parent1, parent2, child, "ad_ou.parent1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.parent1", "name", parent1),
					resource.TestCheckResourceAttr("ad_ou.parent2", "name", parent2),
					resource.TestCheckResourceAttr("ad_ou.child", "name", child),
					resource.TestCheckResourceAttrPair("ad_ou.child", "path", "ad_ou.parent1", "dn"),
					// Capture the child's GUID so step 2 can confirm the move
					// was in-place.
					testAccStoreOUGUID("ad_ou.child"),
				),
			},
			// Step 2: flip the child's path to parent2.dn. GUID must be
			// preserved; the child's DN must now sit under parent2.
			{
				Config: testAccOUResourceConfig_moveScenario(parent1, parent2, child, "ad_ou.parent2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.child", "name", child),
					resource.TestCheckResourceAttrPair("ad_ou.child", "path", "ad_ou.parent2", "dn"),
					testAccCheckNamedOUGUIDUnchanged("ad_ou.child"),
					resource.TestCheckResourceAttrWith("ad_ou.child", "dn", func(value string) error {
						if !strings.Contains(strings.ToUpper(value), "OU="+strings.ToUpper(parent2)+",") {
							return fmt.Errorf("expected child DN to contain OU=%s (parent2), got: %s", parent2, value)
						}
						return nil
					}),
				),
			},
		},
	})
}

// TestAccOUResource_renameAndMove exercises the combined rename+move code
// path: a single apply changes both `name` and `path`. The underlying LDAP
// ModifyDN supports both in one call; this test ensures the provider
// collapses the two changes into a single operation and the resulting state
// shows the new name under the new parent with the same objectGUID.
//
// Covers TEST_PLAN.md #1: rename + move simultaneously.
func TestAccOUResource_renameAndMove(t *testing.T) {
	parent1 := GenerateTestName(TestOUPrefix + "rnm-p1-")
	parent2 := GenerateTestName(TestOUPrefix + "rnm-p2-")
	childName1 := GenerateTestName(TestOUPrefix + "rnm-c1-")
	childName2 := GenerateTestName(TestOUPrefix + "rnm-c2-")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckOUDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Step 1: child named childName1 under parent1.
			{
				Config: testAccOUResourceConfig_moveScenario(parent1, parent2, childName1, "ad_ou.parent1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.child", "name", childName1),
					resource.TestCheckResourceAttrPair("ad_ou.child", "path", "ad_ou.parent1", "dn"),
					testAccStoreOUGUID("ad_ou.child"),
				),
			},
			// Step 2: change both name (-> childName2) and path (-> parent2.dn)
			// in a single apply.
			{
				Config: testAccOUResourceConfig_moveScenario(parent1, parent2, childName2, "ad_ou.parent2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.child", "name", childName2),
					resource.TestCheckResourceAttrPair("ad_ou.child", "path", "ad_ou.parent2", "dn"),
					testAccCheckNamedOUGUIDUnchanged("ad_ou.child"),
					resource.TestCheckResourceAttrWith("ad_ou.child", "dn", func(value string) error {
						upper := strings.ToUpper(value)
						if !strings.Contains(upper, "OU="+strings.ToUpper(childName2)+",") {
							return fmt.Errorf("expected child DN to start with OU=%s, got: %s", childName2, value)
						}
						if !strings.Contains(upper, "OU="+strings.ToUpper(parent2)+",") {
							return fmt.Errorf("expected child DN to contain parent OU=%s, got: %s", parent2, value)
						}
						return nil
					}),
				),
			},
		},
	})
}

// TestAccOUResource_moveWithChildren verifies that moving a parent OU does
// not require the provider to re-parent its descendants. AD's ModifyDN moves
// the whole subtree atomically on the server side; the provider should just
// update the moved OU's own DN and let a subsequent refresh observe that each
// descendant's DN now sits under the new parent.
//
// Covers TEST_PLAN.md #1: OU with children follows on move.
func TestAccOUResource_moveWithChildren(t *testing.T) {
	grandparent := GenerateTestName(TestOUPrefix + "mwc-gp-")
	parent := GenerateTestName(TestOUPrefix + "mwc-p-")
	child := GenerateTestName(TestOUPrefix + "mwc-c-")
	grp := GenerateTestName(TestGroupPrefix + "mwc-")
	grpSAM := GenerateTestSAMName("MWC")

	var parentGUID, childGUID, grpGUID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			if err := testCheckOUDestroy(t.Context(), s); err != nil {
				return err
			}
			return testCheckGroupDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Step 1: create grandparent -> parent -> (child OU, group).
			{
				Config: testAccOUResourceConfig_moveWithChildren(
					grandparent, parent, child, grp, grpSAM,
					"ad_ou.grandparent.dn", // parent is under grandparent
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("ad_ou.parent", "path", "ad_ou.grandparent", "dn"),
					resource.TestCheckResourceAttrPair("ad_ou.child", "path", "ad_ou.parent", "dn"),
					resource.TestCheckResourceAttrPair("ad_group.inside", "container", "ad_ou.parent", "dn"),
					testAccStoreNamedResourceGUID("ad_ou.parent", &parentGUID),
					testAccStoreNamedResourceGUID("ad_ou.child", &childGUID),
					testAccStoreNamedResourceGUID("ad_group.inside", &grpGUID),
				),
			},
			// Step 2: move the parent to the domain root. AD moves the whole
			// subtree atomically. Terraform refreshes each descendant and
			// should observe DNs updated to the new location with all GUIDs
			// preserved.
			{
				Config: testAccOUResourceConfig_moveWithChildren(
					grandparent, parent, child, grp, grpSAM,
					"data.ad_rootdse.test.default_naming_context", // parent moves to domain root
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					// parent now sits at the domain root; no longer under grandparent.
					resource.TestCheckResourceAttrWith("ad_ou.parent", "dn", func(value string) error {
						if strings.Contains(strings.ToUpper(value), "OU="+strings.ToUpper(grandparent)+",") {
							return fmt.Errorf("expected parent DN to no longer contain grandparent %s, got: %s", grandparent, value)
						}
						return nil
					}),
					// Child and group now sit under the (moved) parent; their
					// DNs reflect the new parent path even though neither was
					// modified directly.
					resource.TestCheckResourceAttrPair("ad_ou.child", "path", "ad_ou.parent", "dn"),
					resource.TestCheckResourceAttrPair("ad_group.inside", "container", "ad_ou.parent", "dn"),
					// All three GUIDs must be preserved.
					testAccCheckNamedResourceGUIDUnchanged("ad_ou.parent", &parentGUID),
					testAccCheckNamedResourceGUIDUnchanged("ad_ou.child", &childGUID),
					testAccCheckNamedResourceGUIDUnchanged("ad_group.inside", &grpGUID),
				),
			},
		},
	})
}

// Note: TestAccOUResource_renameWhileProtected was removed. In a default AD
// configuration, the "protect from accidental deletion" ACE on an OU also
// blocks ModifyDN (rename/move), not only Delete. A user who needs to rename
// or move such an OU must first unprotect it, then reprotect after the move —
// that's an AD-side workflow, not a provider-level concern. Rename/move
// coverage on unprotected OUs is exercised by TestAccOUResource_rename,
// _move, _renameAndMove, and _moveWithChildren.

// TestAccOUResource_specialCharsInName exercises the DN-escaping path from
// BuildOUDN via ldap.EscapeDN (the fix documented in TEST_PLAN.md #4). The
// OU-name schema is strict: it rejects `"`, `\`, `#`, `+`, `,`, `;`, `<`,
// `=`, `>`, CR, LF, and `/`. That leaves leading/trailing spaces as the only
// allowed characters that still trigger RFC4514 escaping in the RDN, which
// is sufficient to exercise the EscapeDN (vs. EscapeFilter) round-trip.
//
// Verifies:
//   - Create succeeds and DN reflects the expected \-escaped form.
//   - Import-by-DN works (exercises unescape-on-read and re-escape-on-build).
//
// Covers TEST_PLAN.md #4: DN Escaping Fix (OU side, constrained to what the
// schema regex permits).
func TestAccOUResource_specialCharsInName(t *testing.T) {
	// Names that the OU regex allows but that still require escaping in the
	// constructed RDN per RFC 4514: leading and trailing spaces must be
	// backslash-escaped.
	cases := []struct {
		label    string
		name     string
		escaped  string // expected escaped RDN value produced by ldap.EscapeDN
		contains string // substring the DN is expected to contain (upper-cased)
	}{
		{
			label:    "leading_space",
			name:     " tf-test-ou-lead-" + uniqueSuffix(),
			escaped:  "",
			contains: "",
		},
		{
			label:    "trailing_space",
			name:     "tf-test-ou-trail-" + uniqueSuffix() + " ",
			escaped:  "",
			contains: "",
		},
	}

	for i := range cases {
		// Populate expected escaped form and DN substring. EscapeDN escapes
		// leading/trailing spaces with a preceding backslash. The DN is also
		// upper-cased on the RDN prefix via NormalizeDNCase.
		cases[i].escaped = escapeDNForExpect(cases[i].name)
		cases[i].contains = "OU=" + strings.ToUpper(cases[i].escaped) + ","
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				CheckDestroy: func(s *terraform.State) error {
					return testCheckOUDestroy(t.Context(), s)
				},
				Steps: []resource.TestStep{
					// Create: DN must contain the properly-escaped RDN.
					{
						Config: testAccOUResourceConfig_basic(tc.name),
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttr("ad_ou.test", "name", tc.name),
							resource.TestCheckResourceAttrWith("ad_ou.test", "dn", func(value string) error {
								if !strings.Contains(strings.ToUpper(value), tc.contains) {
									return fmt.Errorf("expected DN to contain %q, got: %s", tc.contains, value)
								}
								return nil
							}),
						),
					},
					// Import-by-DN: exercises parse/unescape on read and
					// re-escape on subsequent writes.
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
		})
	}
}

// TestAccOUResource_dnPredictedAtPlan guards the ComputeDN plan modifier
// (TEST_PLAN.md #2). Without that modifier, `dn` is unknown during plan and
// the provider can produce "inconsistent result after apply" when AD
// normalises the RDN case. With it, the predicted DN must be known at plan
// time and match the canonical form (upper-cased RDN attribute types, escaped
// values) so that apply is a no-op transition.
//
// The test:
//   - Step 1 (create): asserts the predicted `dn` equals the expected
//     canonical form during plan.
//   - Step 2 (rename): changes `name` and asserts the re-planned `dn`
//     reflects the new RDN (again, known at plan time).
func TestAccOUResource_dnPredictedAtPlan(t *testing.T) {
	name1 := GenerateTestName(TestOUPrefix + "plandn-")
	name2 := GenerateTestName(TestOUPrefix + "plandn2-")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckOUDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Step 1: create. Assert the predicted DN at PreApply is the
			// expected canonical form. The DN is predicted from the computed
			// default_naming_context data source value + the planned name,
			// so we can't assert an exact value (we don't know the domain).
			// Instead, assert that `dn` is known (not unknown) during plan.
			{
				Config: testAccOUResourceConfig_basic(name1),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(
							"ad_ou.test",
							tfjsonpath.New("dn"),
							// Matches any non-empty string. The concrete
							// value depends on the test domain (unknown
							// ahead of time), so we assert shape not value.
							knownvalue.StringRegexp(regexp.MustCompile(
								`^OU=`+regexp.QuoteMeta(name1)+`,.+$`,
							)),
						),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", name1),
					resource.TestCheckResourceAttrSet("ad_ou.test", "dn"),
				),
			},
			// Step 2: rename. Assert the predicted DN shifts to reflect the
			// new RDN while remaining known at plan time.
			{
				Config: testAccOUResourceConfig_basic(name2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(
							"ad_ou.test",
							tfjsonpath.New("dn"),
							knownvalue.StringRegexp(regexp.MustCompile(
								`^OU=`+regexp.QuoteMeta(name2)+`,.+$`,
							)),
						),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_ou.test", "name", name2),
				),
			},
		},
	})
}

// escapeDNForExpect mirrors ldap.EscapeDN for the characters our test inputs
// actually use (leading/trailing spaces). Duplicated in the test to avoid
// pulling go-ldap into package provider_test just for this helper, and to
// keep the expected value calculation explicit at the call site.
func escapeDNForExpect(s string) string {
	if s == "" {
		return ""
	}
	// Only the leading/trailing space case is needed for the OU special-
	// chars test. Keep this deliberately narrow; other escaped characters
	// are not accepted by the OU name schema.
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		if (i == 0 || i == len(runes)-1) && r == ' ' {
			b.WriteRune('\\')
			b.WriteRune(r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// uniqueSuffix returns a short, collision-resistant suffix suitable for
// embedding in test resource names. Replicates the timestamp+uuid approach
// used by GenerateTestName without the prefix.
func uniqueSuffix() string {
	return GenerateTestName("")
}

// testAccOUResourceConfig_moveScenario emits two parent OUs and one child
// OU, where the child's `path` is controlled by `childPathRef`, a Terraform
// expression evaluating to one of the parent DNs (e.g. "ad_ou.parent1" or
// "ad_ou.parent2"). The childPathRef is inserted as "<ref>.dn".
func testAccOUResourceConfig_moveScenario(parent1, parent2, child, childPathRef string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_ou" "parent1" {
  name = %[3]q
  path = data.ad_rootdse.test.default_naming_context
}

resource "ad_ou" "parent2" {
  name = %[4]q
  path = data.ad_rootdse.test.default_naming_context
}

resource "ad_ou" "child" {
  name = %[5]q
  path = %[6]s.dn
}
`, testProviderConfig(), testRootDSEDataSource(), parent1, parent2, child, childPathRef)
}

// testAccOUResourceConfig_moveWithChildren creates a grandparent -> parent
// chain, a child OU inside `parent`, and a group inside `parent`. `parentPath`
// is a raw Terraform expression evaluating to a DN (either
// "ad_ou.grandparent.dn" or "data.ad_rootdse.test.default_naming_context"),
// controlling where `parent` lives.
func testAccOUResourceConfig_moveWithChildren(grandparent, parent, child, groupName, groupSAM, parentPath string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_ou" "grandparent" {
  name = %[3]q
  path = data.ad_rootdse.test.default_naming_context
}

resource "ad_ou" "parent" {
  name = %[4]q
  path = %[8]s
}

resource "ad_ou" "child" {
  name = %[5]q
  path = ad_ou.parent.dn
}

resource "ad_group" "inside" {
  name             = %[6]q
  sam_account_name = %[7]q
  container        = ad_ou.parent.dn
}
`, testProviderConfig(), testRootDSEDataSource(), grandparent, parent, child, groupName, groupSAM, parentPath)
}
