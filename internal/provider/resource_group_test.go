package provider

import (
	"fmt"
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
					resource.TestCheckResourceAttrSet("ad_group.test", "distinguished_name"),
					resource.TestCheckResourceAttrSet("ad_group.test", "sid"),
					resource.TestCheckResourceAttrSet("ad_group.test", "group_type"),
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
					resource.TestCheckResourceAttr("ad_group.test", "group_type", "-2147483646"),
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
					resource.TestCheckResourceAttr("ad_group.test", "group_type", "2"),
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
					resource.TestCheckResourceAttr("ad_group.test", "group_type", "-2147483640"),
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
					resource.TestCheckResourceAttr("ad_group.test", "group_type", "8"),
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
					resource.TestCheckResourceAttr("ad_group.test", "group_type", "-2147483644"),
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
					resource.TestCheckResourceAttr("ad_group.test", "group_type", "4"),
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
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupResourceConfig_basic("tf-test-disappears", "TFTestDisappears"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGroupExists("ad_group.test"),
					testAccCheckGroupDisappears("ad_group.test"),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Helper functions for test configurations
func testAccGroupResourceConfig_basic(name, samName string) string {
	return fmt.Sprintf(`
resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "cn=Users,dc=example,dc=com"
}
`, name, samName)
}

func testAccGroupResourceConfig_withDescription(name, samName, description string) string {
	return fmt.Sprintf(`
resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "cn=Users,dc=example,dc=com"
  description      = %[3]q
}
`, name, samName, description)
}

func testAccGroupResourceConfig_scopeCategory(name, samName, scope, category string) string {
	return fmt.Sprintf(`
resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "cn=Users,dc=example,dc=com"
  scope            = %[3]q
  category         = %[4]q
}
`, name, samName, scope, category)
}

// Helper functions for import testing
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

	return rs.Primary.Attributes["distinguished_name"], nil
}

// Helper functions for existence and destroy testing
func testAccCheckGroupExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Implement group existence check
		// This would use the LDAP client to verify the group exists
		return nil
	}
}

func testAccCheckGroupDestroy(s *terraform.State) error {
	// Implement group destroy check
	// This would use the LDAP client to verify all groups are deleted
	return nil
}

func testAccCheckGroupDisappears(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Implement group disappears check
		// This would manually delete the group outside Terraform
		return nil
	}
}

// Note: testAccPreCheck is defined in provider_test.go
