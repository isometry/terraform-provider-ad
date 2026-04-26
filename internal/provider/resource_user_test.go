package provider_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

func TestAccUserResource_basic(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "principal_name", upn),
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
					resource.TestCheckResourceAttrSet("ad_user.test", "id"),
					resource.TestCheckResourceAttrSet("ad_user.test", "dn"),
					resource.TestCheckResourceAttrSet("ad_user.test", "sid"),
					resource.TestCheckResourceAttrSet("ad_user.test", "sam_account_name"),
				),
			},
			// ImportState testing
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
			// Idempotency spot-check: replanning the same config must produce
			// an empty diff. Guards against computed-attribute drift.
			{
				Config:             testAccUserResourceConfig_basic(name, upn, samName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccUserResource_withSAMAccountName(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig_withSAMAccountName(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "principal_name", upn),
					resource.TestCheckResourceAttr("ad_user.test", "sam_account_name", samName),
				),
			},
		},
	})
}

func TestAccUserResource_withDescription(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)
	description := "Test user with description"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig_withDescription(name, upn, samName, description),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "principal_name", upn),
					resource.TestCheckResourceAttr("ad_user.test", "description", description),
				),
			},
		},
	})
}

func TestAccUserResource_withAllAttributes(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig_full(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "principal_name", upn),
					resource.TestCheckResourceAttr("ad_user.test", "sam_account_name", samName),
					resource.TestCheckResourceAttr("ad_user.test", "display_name", "Test Display Name"),
					resource.TestCheckResourceAttr("ad_user.test", "description", "Full test user"),
					resource.TestCheckResourceAttr("ad_user.test", "given_name", "Test"),
					resource.TestCheckResourceAttr("ad_user.test", "surname", "User"),
					resource.TestCheckResourceAttr("ad_user.test", "email_address", fmt.Sprintf("%s@example.com", samName)),
					resource.TestCheckResourceAttr("ad_user.test", "office_phone", "+1-555-0100"),
					resource.TestCheckResourceAttr("ad_user.test", "title", "Test Engineer"),
					resource.TestCheckResourceAttr("ad_user.test", "department", "Engineering"),
					resource.TestCheckResourceAttr("ad_user.test", "company", "Test Company"),
					resource.TestCheckResourceAttr("ad_user.test", "city", "Test City"),
					resource.TestCheckResourceAttr("ad_user.test", "state", "CA"),
					resource.TestCheckResourceAttr("ad_user.test", "postal_code", "90210"),
					resource.TestCheckResourceAttr("ad_user.test", "country", "US"),
				),
			},
			// ImportState testing
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
			// Idempotency spot-check: replanning the same config must produce
			// an empty diff. Guards against computed-attribute drift on the
			// broader set of optional string attributes.
			{
				Config:             testAccUserResourceConfig_full(name, upn, samName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccUserResource_update(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create initial user with description
			{
				Config: testAccUserResourceConfig_withDescription(name, upn, samName, "Original description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "description", "Original description"),
					testAccStoreUserGUID("ad_user.test"),
				),
			},
			// Update description
			{
				Config: testAccUserResourceConfig_withDescription(name, upn, samName, "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "description", "Updated description"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
			// Remove description (clear it)
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckNoResourceAttr("ad_user.test", "description"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
		},
	})
}

func TestAccUserResource_updateSecurityFlags(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user with default security flags (no password → disabled)
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
					resource.TestCheckResourceAttr("ad_user.test", "password_never_expires", "false"),
					testAccStoreUserGUID("ad_user.test"),
				),
			},
			// Explicitly disable account and enable password_never_expires
			{
				Config: testAccUserResourceConfig_withSecurityFlags(name, upn, samName, false, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
					resource.TestCheckResourceAttr("ad_user.test", "password_never_expires", "true"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
			// Request enabled but no password → still disabled
			{
				Config: testAccUserResourceConfig_withSecurityFlags(name, upn, samName, true, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
					resource.TestCheckResourceAttr("ad_user.test", "password_never_expires", "true"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
			// Reset to defaults (no password → still disabled)
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
					resource.TestCheckResourceAttr("ad_user.test", "password_never_expires", "false"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
		},
	})
}

func TestAccUserResource_containerMove(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user in default container
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttrSet("ad_user.test", "id"),
					resource.TestCheckResourceAttrSet("ad_user.test", "dn"),
					testAccStoreUserGUID("ad_user.test"),
				),
			},
			// Move to a specific container
			{
				Config: testAccUserResourceConfig_withContainer(name, upn, samName, "CN=Users"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					// Verify GUID is preserved after move
					testAccCheckUserGUIDUnchanged(),
					// Verify DN has changed to reflect new container
					resource.TestCheckResourceAttrWith("ad_user.test", "dn", func(value string) error {
						if !strings.Contains(strings.ToUpper(value), "CN=USERS") {
							return fmt.Errorf("expected DN to contain CN=Users, got: %s", value)
						}
						return nil
					}),
				),
			},
			// Move back to original container
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					testAccCheckUserGUIDUnchanged(),
				),
			},
		},
	})
}

func TestAccUserResource_disabledAccount(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create disabled user
			{
				Config: testAccUserResourceConfig_withSecurityFlags(name, upn, samName, false, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
				),
			},
			// ImportState testing - verify disabled state is preserved
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

func TestAccUserResource_serviceAccount(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("svc")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create service account (password never expires)
			{
				Config: testAccUserResourceConfig_serviceAccount(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
					resource.TestCheckResourceAttr("ad_user.test", "password_never_expires", "true"),
					resource.TestCheckResourceAttr("ad_user.test", "description", "Service Account"),
				),
			},
			// ImportState testing
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

func TestAccUserResource_importByGUID(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
				),
			},
			// Import by GUID
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
				ImportStateIdFunc:       testAccUserImportStateIdFunc,
			},
		},
	})
}

func TestAccUserResource_importByDN(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
				),
			},
			// Import by DN
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
				ImportStateIdFunc:       testAccUserImportStateIdFuncDN,
			},
		},
	})
}

func TestAccUserResource_importBySID(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
				),
			},
			// Import by SID
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
				ImportStateIdFunc:       testAccUserImportStateIdFuncSID,
			},
		},
	})
}

func TestAccUserResource_importByUPN(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
				),
			},
			// Import by UPN
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
				ImportStateIdFunc:       testAccUserImportStateIdFuncUPN,
			},
		},
	})
}

func TestAccUserResource_importBySAM(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user
			{
				Config: testAccUserResourceConfig_withSAMAccountName(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "sam_account_name", samName),
				),
			},
			// Import by SAM account name
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
				ImportStateIdFunc:       testAccUserImportStateIdFuncSAM,
			},
		},
	})
}

func TestAccUserResource_disappears(t *testing.T) {
	ctx := t.Context()
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(ctx, s)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeTestCheckFunc(
					testCheckUserExists(ctx, "ad_user.test"),
					testCheckUserDisappears(ctx, "ad_user.test"),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test configuration builders

func testAccUserResourceConfig_basic(name, upn, sam string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, DefaultTestContainer)
}

func testAccUserResourceConfig_withSAMAccountName(name, upn, sam string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, DefaultTestContainer)
}

func testAccUserResourceConfig_withContainer(name, upn, sam, container string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, container)
}

func testAccUserResourceConfig_withDescription(name, upn, sam, description string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[7]s,${data.ad_rootdse.test.default_naming_context}"
  description      = %[6]q
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, description, DefaultTestContainer)
}

func testAccUserResourceConfig_withSecurityFlags(name, upn, sam string, enabled, passwordNeverExpires bool) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name                   = %[3]q
  principal_name         = %[4]q
  sam_account_name       = %[5]q
  container              = "%[8]s,${data.ad_rootdse.test.default_naming_context}"
  enabled                = %[6]t
  password_never_expires = %[7]t
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, enabled, passwordNeverExpires, DefaultTestContainer)
}

func testAccUserResourceConfig_serviceAccount(name, upn, sam string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name                   = %[3]q
  principal_name         = %[4]q
  sam_account_name       = %[5]q
  container              = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  description            = "Service Account"
  password_never_expires = true
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, DefaultTestContainer)
}

func testAccUserResourceConfig_full(name, upn, sam string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"

  # Personal information
  display_name = "Test Display Name"
  description  = "Full test user"
  given_name   = "Test"
  surname      = "User"

  # Contact information
  email_address = "%[5]s@example.com"
  office_phone  = "+1-555-0100"

  # Organizational information
  title      = "Test Engineer"
  department = "Engineering"
  company    = "Test Company"

  # Address information
  city        = "Test City"
  state       = "CA"
  postal_code = "90210"
  country     = "US"
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, DefaultTestContainer)
}

// Helper functions for import testing

func testAccUserImportStateIdFunc(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources["ad_user.test"]
	if !ok {
		return "", fmt.Errorf("not found: %s", "ad_user.test")
	}

	return rs.Primary.Attributes["id"], nil
}

func testAccUserImportStateIdFuncDN(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources["ad_user.test"]
	if !ok {
		return "", fmt.Errorf("not found: %s", "ad_user.test")
	}

	return rs.Primary.Attributes["dn"], nil
}

func testAccUserImportStateIdFuncSID(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources["ad_user.test"]
	if !ok {
		return "", fmt.Errorf("not found: %s", "ad_user.test")
	}

	return rs.Primary.Attributes["sid"], nil
}

func testAccUserImportStateIdFuncUPN(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources["ad_user.test"]
	if !ok {
		return "", fmt.Errorf("not found: %s", "ad_user.test")
	}

	return rs.Primary.Attributes["principal_name"], nil
}

func testAccUserImportStateIdFuncSAM(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources["ad_user.test"]
	if !ok {
		return "", fmt.Errorf("not found: %s", "ad_user.test")
	}

	return rs.Primary.Attributes["sam_account_name"], nil
}

// User check functions.

//nolint:unparam // resourceName kept for consistency with other test check functions
func testCheckUserExists(ctx context.Context, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("resource ID not set")
		}

		config := GetTestConfig()
		ldapConfig := newTestLDAPConfig(config)

		client, err := ldapclient.NewClient(ctx, ldapConfig)
		if err != nil {
			return fmt.Errorf("failed to create LDAP client: %v", err)
		}
		defer client.Close()

		cacheManager := ldapclient.NewCacheManager()
		userManager := ldapclient.NewUserManager(ctx, client, config.BaseDN, cacheManager)

		// Try to read the user by GUID (stored in ID)
		_, err = userManager.GetUserByGUID(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("user %s does not exist: %v", rs.Primary.ID, err)
		}

		return nil
	}
}

func testCheckUserDestroy(ctx context.Context, s *terraform.State) error {
	config := GetTestConfig()
	ldapConfig := newTestLDAPConfig(config)

	client, err := ldapclient.NewClient(ctx, ldapConfig)
	if err != nil {
		return fmt.Errorf("failed to create LDAP client: %v", err)
	}
	defer client.Close()

	cacheManager := ldapclient.NewCacheManager()
	userManager := ldapclient.NewUserManager(ctx, client, config.BaseDN, cacheManager)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "ad_user" {
			continue
		}

		// Try to read the user - it should not exist
		_, err := userManager.GetUserByGUID(rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("user %s still exists", rs.Primary.ID)
		}

		// Verify it's a "not found" error, not some other error
		if !ldapclient.IsNotFoundError(err) {
			return fmt.Errorf("unexpected error checking user %s: %v", rs.Primary.ID, err)
		}
	}

	return nil
}

func testCheckUserDisappears(ctx context.Context, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		config := GetTestConfig()
		ldapConfig := newTestLDAPConfig(config)

		client, err := ldapclient.NewClient(ctx, ldapConfig)
		if err != nil {
			return fmt.Errorf("failed to create LDAP client: %v", err)
		}
		defer client.Close()

		cacheManager := ldapclient.NewCacheManager()
		userManager := ldapclient.NewUserManager(ctx, client, config.BaseDN, cacheManager)

		// Delete the user manually using its GUID
		err = userManager.DeleteUser(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("failed to manually delete user: %v", err)
		}

		return nil
	}
}

// GUID tracking for container move tests

var storedUserGUID string

func testAccStoreUserGUID(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}

		storedUserGUID = rs.Primary.Attributes["id"]
		if storedUserGUID == "" {
			return fmt.Errorf("user ID (GUID) is empty")
		}

		return nil
	}
}

func testAccCheckUserGUIDUnchanged() resource.TestCheckFunc {
	const resourceName = "ad_user.test"
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}

		currentGUID := rs.Primary.Attributes["id"]
		if currentGUID != storedUserGUID {
			return fmt.Errorf("user GUID changed: expected %s, got %s", storedUserGUID, currentGUID)
		}

		return nil
	}
}

// TestAccUserResource_passwordVersion tests that password_version defaults to 0
// (create-only password) and incrementing password_version triggers password reset.
func TestAccUserResource_passwordVersion(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user with password (version=0, create-only)
			{
				Config: testAccUserResourceConfig_withPasswordVersion(name, upn, samName, "InitialPass123!", 0),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "password_version", "0"),
				),
			},
			// Update version to 1 to trigger password reset
			{
				Config: testAccUserResourceConfig_withPasswordVersion(name, upn, samName, "UpdatedPass456!", 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "password_version", "1"),
				),
			},
			// Keep version at 1, change password value - no reset should occur
			// (password_version unchanged means password is not applied)
			{
				Config: testAccUserResourceConfig_withPasswordVersion(name, upn, samName, "DifferentPass789!", 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "password_version", "1"),
				),
			},
			// Increment to version 2 to force password change
			{
				Config: testAccUserResourceConfig_withPasswordVersion(name, upn, samName, "FinalPass999!", 2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "password_version", "2"),
				),
			},
			// ImportState - verify password is ignored
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

func testAccUserResourceConfig_withPasswordVersion(name, upn, sam, password string, version int) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[8]s,${data.ad_rootdse.test.default_naming_context}"
  password         = %[6]q
  password_version = %[7]d
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, password, version, DefaultTestContainer)
}

// TestAccUserResource_duplicateSAMAccountName confirms the provider surfaces
// a clear error when two ad_user resources in the same plan share a
// sAMAccountName. Active Directory requires sAMAccountName to be unique
// within a domain, so the second Create must fail.
func TestAccUserResource_duplicateSAMAccountName(t *testing.T) {
	name1 := GenerateTestName(TestUserPrefix)
	name2 := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("dupsam")
	upn1 := fmt.Sprintf("%s@%s", samName+"a", GetTestConfig().Domain)
	upn2 := fmt.Sprintf("%s@%s", samName+"b", GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig_duplicateSAM(name1, name2, upn1, upn2, samName),
				// AD returns LDAP result 68 (Entry already exists) when a
				// sAMAccountName collision occurs. The provider wraps it as
				// "Error Creating User ... Entry already exists".
				ExpectError: regexp.MustCompile(
					`(?s)(Error Creating User|Entry already exists|already exists|sAMAccountName|constraint)`,
				),
			},
		},
	})
}

func testAccUserResourceConfig_duplicateSAM(name1, name2, upn1, upn2, sam string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "first" {
  name             = %[3]q
  principal_name   = %[5]q
  sam_account_name = %[7]q
  container        = "%[8]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_user" "second" {
  name             = %[4]q
  principal_name   = %[6]q
  sam_account_name = %[7]q
  container        = "%[8]s,${data.ad_rootdse.test.default_naming_context}"
  depends_on       = [ad_user.first]
}
`, testProviderConfig(), testRootDSEDataSource(), name1, name2, upn1, upn2, sam, DefaultTestContainer)
}

// TestAccUserResource_invalidContainer confirms the provider surfaces a
// clear error when the container DN does not exist in the directory. The
// resource must fail to create — it must not silently place the user in a
// different location, nor succeed without an error.
func TestAccUserResource_invalidContainer(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig_invalidContainer(name, upn, samName),
				// AD returns LDAP result 32 (No such object) when the parent
				// container does not exist. Some AD configurations instead
				// return 53 (Unwilling to perform) or 64 (Naming violation).
				ExpectError: regexp.MustCompile(
					`(?s)(Error Creating User|does not exist|no such object|Naming violation|Unwilling to perform|Invalid DN syntax|not found)`,
				),
			},
		},
	})
}

func testAccUserResourceConfig_invalidContainer(name, upn, sam string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  # Deliberately reference an OU that does not exist in the directory.
  container        = "OU=ThisContainerDoesNotExist-%[5]s,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam)
}

// TestAccUserResource_manager exercises setting, updating, and clearing the
// manager attribute on a user. The manager attribute is Optional (no Computed),
// so clearing is expressed by omitting the attribute entirely (plan null →
// helpers.StringChanged emits an empty-string LDAP write that clears the
// attribute in AD).
func TestAccUserResource_manager(t *testing.T) {
	mgrAName := GenerateTestName(TestUserPrefix + "mgra-")
	mgrASAM := GenerateTestSAMName("mgra")
	mgrAUPN := fmt.Sprintf("%s@%s", mgrASAM, GetTestConfig().Domain)

	mgrBName := GenerateTestName(TestUserPrefix + "mgrb-")
	mgrBSAM := GenerateTestSAMName("mgrb")
	mgrBUPN := fmt.Sprintf("%s@%s", mgrBSAM, GetTestConfig().Domain)

	subName := GenerateTestName(TestUserPrefix + "sub-")
	subSAM := GenerateTestSAMName("sub")
	subUPN := fmt.Sprintf("%s@%s", subSAM, GetTestConfig().Domain)

	var subordinateGUID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Step 1: create subordinate with manager = manager_a.dn.
			{
				Config: testAccUserResourceConfig_managerA(
					mgrAName, mgrAUPN, mgrASAM,
					mgrBName, mgrBUPN, mgrBSAM,
					subName, subUPN, subSAM,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.subordinate"),
					testCheckUserExists(t.Context(), "ad_user.manager_a"),
					testCheckUserExists(t.Context(), "ad_user.manager_b"),
					resource.TestCheckResourceAttrPair(
						"ad_user.subordinate", "manager",
						"ad_user.manager_a", "dn",
					),
					testAccStoreNamedResourceGUID("ad_user.subordinate", &subordinateGUID),
				),
			},
			// Step 2: change subordinate.manager to manager_b.dn. GUID unchanged.
			{
				Config: testAccUserResourceConfig_managerB(
					mgrAName, mgrAUPN, mgrASAM,
					mgrBName, mgrBUPN, mgrBSAM,
					subName, subUPN, subSAM,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"ad_user.subordinate", "manager",
						"ad_user.manager_b", "dn",
					),
					testAccCheckNamedResourceGUIDUnchanged("ad_user.subordinate", &subordinateGUID),
				),
			},
			// Step 3: omit subordinate.manager to clear it.
			{
				Config: testAccUserResourceConfig_managerCleared(
					mgrAName, mgrAUPN, mgrASAM,
					mgrBName, mgrBUPN, mgrBSAM,
					subName, subUPN, subSAM,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("ad_user.subordinate", "manager"),
					testAccCheckNamedResourceGUIDUnchanged("ad_user.subordinate", &subordinateGUID),
				),
			},
			// Step 4: replan same config → no diff.
			{
				Config: testAccUserResourceConfig_managerCleared(
					mgrAName, mgrAUPN, mgrASAM,
					mgrBName, mgrBUPN, mgrBSAM,
					subName, subUPN, subSAM,
				),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// testAccUserResourceConfig_managerCommon emits provider + rootdse + two manager
// users so the individual manager-variant configs can concentrate on the
// subordinate.
func testAccUserResourceConfig_managerCommon(
	mgrAName, mgrAUPN, mgrASAM,
	mgrBName, mgrBUPN, mgrBSAM string,
) string {
	return fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_user" "manager_a" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[9]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_user" "manager_b" {
  name             = %[6]q
  principal_name   = %[7]q
  sam_account_name = %[8]q
  container        = "%[9]s,${data.ad_rootdse.test.default_naming_context}"
}
`,
		testProviderConfig(),
		testRootDSEDataSource(),
		mgrAName, mgrAUPN, mgrASAM,
		mgrBName, mgrBUPN, mgrBSAM,
		DefaultTestContainer,
	)
}

func testAccUserResourceConfig_managerA(
	mgrAName, mgrAUPN, mgrASAM,
	mgrBName, mgrBUPN, mgrBSAM,
	subName, subUPN, subSAM string,
) string {
	return fmt.Sprintf(`
%[1]s

resource "ad_user" "subordinate" {
  name             = %[2]q
  principal_name   = %[3]q
  sam_account_name = %[4]q
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
  manager          = ad_user.manager_a.dn
}
`,
		testAccUserResourceConfig_managerCommon(
			mgrAName, mgrAUPN, mgrASAM,
			mgrBName, mgrBUPN, mgrBSAM,
		),
		subName, subUPN, subSAM,
		DefaultTestContainer,
	)
}

func testAccUserResourceConfig_managerB(
	mgrAName, mgrAUPN, mgrASAM,
	mgrBName, mgrBUPN, mgrBSAM,
	subName, subUPN, subSAM string,
) string {
	return fmt.Sprintf(`
%[1]s

resource "ad_user" "subordinate" {
  name             = %[2]q
  principal_name   = %[3]q
  sam_account_name = %[4]q
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
  manager          = ad_user.manager_b.dn
}
`,
		testAccUserResourceConfig_managerCommon(
			mgrAName, mgrAUPN, mgrASAM,
			mgrBName, mgrBUPN, mgrBSAM,
		),
		subName, subUPN, subSAM,
		DefaultTestContainer,
	)
}

func testAccUserResourceConfig_managerCleared(
	mgrAName, mgrAUPN, mgrASAM,
	mgrBName, mgrBUPN, mgrBSAM,
	subName, subUPN, subSAM string,
) string {
	return fmt.Sprintf(`
%[1]s

resource "ad_user" "subordinate" {
  name             = %[2]q
  principal_name   = %[3]q
  sam_account_name = %[4]q
  container        = "%[5]s,${data.ad_rootdse.test.default_naming_context}"
  # manager intentionally omitted to exercise the clearing path.
}
`,
		testAccUserResourceConfig_managerCommon(
			mgrAName, mgrAUPN, mgrASAM,
			mgrBName, mgrBUPN, mgrBSAM,
		),
		subName, subUPN, subSAM,
		DefaultTestContainer,
	)
}

// TestAccUserResource_serviceAccountFlags exercises the trio of UAC-encoded
// boolean flags (enabled=false, password_never_expires=true,
// trusted_for_delegation=true) and confirms they survive an import round-trip.
// A password is supplied so the account can be enabled/disabled deterministically
// rather than being coerced disabled by EnabledRequiresPassword.
func TestAccUserResource_serviceAccountFlags(t *testing.T) {
	name := GenerateTestName(TestUserPrefix + "svcflag-")
	samName := GenerateTestSAMName("svcfl")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig_serviceAccountFlags(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
					resource.TestCheckResourceAttr("ad_user.test", "password_never_expires", "true"),
					resource.TestCheckResourceAttr("ad_user.test", "trusted_for_delegation", "true"),
				),
			},
			// Import round-trip: all three UAC-encoded flags must survive.
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

func testAccUserResourceConfig_serviceAccountFlags(name, upn, sam string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name                   = %[3]q
  principal_name         = %[4]q
  sam_account_name       = %[5]q
  container              = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  password               = "ComplexP@ssw0rd!#2024"
  enabled                = false
  password_never_expires = true
  trusted_for_delegation = true
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, DefaultTestContainer)
}

// TestAccUserResource_profileAttributes exercises the profile-related
// attributes (home_directory, home_drive, profile_path, logon_script) through
// create → partial update → clear. Clearing is expressed by omitting the
// attribute; helpers.StringChanged converts plan-null to an empty-string LDAP
// write that removes the attribute in AD.
func TestAccUserResource_profileAttributes(t *testing.T) {
	name := GenerateTestName(TestUserPrefix + "prof-")
	samName := GenerateTestSAMName("prof")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Step 1: create with all four profile attributes populated.
			{
				Config: testAccUserResourceConfig_profileAttributes(
					name, upn, samName,
					`\\server\share\%username%`,
					"H:",
					`\\server\profiles\%username%`,
					`logon.bat`,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "home_directory", `\\server\share\%username%`),
					resource.TestCheckResourceAttr("ad_user.test", "home_drive", "H:"),
					resource.TestCheckResourceAttr("ad_user.test", "profile_path", `\\server\profiles\%username%`),
					resource.TestCheckResourceAttr("ad_user.test", "logon_script", "logon.bat"),
					testAccStoreUserGUID("ad_user.test"),
				),
			},
			// Step 2: update only profile_path; the other three must not change.
			{
				Config: testAccUserResourceConfig_profileAttributes(
					name, upn, samName,
					`\\server\share\%username%`,
					"H:",
					`\\server\roaming\%username%`,
					`logon.bat`,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "home_directory", `\\server\share\%username%`),
					resource.TestCheckResourceAttr("ad_user.test", "home_drive", "H:"),
					resource.TestCheckResourceAttr("ad_user.test", "profile_path", `\\server\roaming\%username%`),
					resource.TestCheckResourceAttr("ad_user.test", "logon_script", "logon.bat"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
			// Step 3: omit home_directory to clear it; others remain set.
			{
				Config: testAccUserResourceConfig_profileAttributesNoHomeDir(
					name, upn, samName,
					"H:",
					`\\server\roaming\%username%`,
					`logon.bat`,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("ad_user.test", "home_directory"),
					resource.TestCheckResourceAttr("ad_user.test", "home_drive", "H:"),
					resource.TestCheckResourceAttr("ad_user.test", "profile_path", `\\server\roaming\%username%`),
					resource.TestCheckResourceAttr("ad_user.test", "logon_script", "logon.bat"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
		},
	})
}

func testAccUserResourceConfig_profileAttributes(
	name, upn, sam,
	homeDir, homeDrive, profilePath, logonScript string,
) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  home_directory   = %[7]q
  home_drive       = %[8]q
  profile_path     = %[9]q
  logon_script     = %[10]q
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, DefaultTestContainer,
		homeDir, homeDrive, profilePath, logonScript)
}

func testAccUserResourceConfig_profileAttributesNoHomeDir(
	name, upn, sam,
	homeDrive, profilePath, logonScript string,
) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  # home_directory intentionally omitted to exercise the clearing path.
  home_drive       = %[7]q
  profile_path     = %[8]q
  logon_script     = %[9]q
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, DefaultTestContainer,
		homeDrive, profilePath, logonScript)
}

// TestAccUserResource_organizationalUpdate exercises title / department /
// company / employee_id through create → update all four → clear all four.
// GUID is captured in step 1 and re-asserted in steps 2–3.
func TestAccUserResource_organizationalUpdate(t *testing.T) {
	name := GenerateTestName(TestUserPrefix + "org-")
	samName := GenerateTestSAMName("org")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Step 1: create with organizational attributes.
			{
				Config: testAccUserResourceConfig_organizational(
					name, upn, samName,
					"Engineer", "Engineering", "Acme Corp", "EMP-001",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "title", "Engineer"),
					resource.TestCheckResourceAttr("ad_user.test", "department", "Engineering"),
					resource.TestCheckResourceAttr("ad_user.test", "company", "Acme Corp"),
					resource.TestCheckResourceAttr("ad_user.test", "employee_id", "EMP-001"),
					testAccStoreUserGUID("ad_user.test"),
				),
			},
			// Step 2: update all four to new values. GUID unchanged.
			{
				Config: testAccUserResourceConfig_organizational(
					name, upn, samName,
					"Senior Engineer", "Platform", "Acme International", "EMP-042",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "title", "Senior Engineer"),
					resource.TestCheckResourceAttr("ad_user.test", "department", "Platform"),
					resource.TestCheckResourceAttr("ad_user.test", "company", "Acme International"),
					resource.TestCheckResourceAttr("ad_user.test", "employee_id", "EMP-042"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
			// Step 3: omit all four; StringOrNull maps AD's empty-string return
			// to types.StringNull, so TestCheckNoResourceAttr is the correct
			// assertion.
			{
				Config: testAccUserResourceConfig_basic(name, upn, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("ad_user.test", "title"),
					resource.TestCheckNoResourceAttr("ad_user.test", "department"),
					resource.TestCheckNoResourceAttr("ad_user.test", "company"),
					resource.TestCheckNoResourceAttr("ad_user.test", "employee_id"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
		},
	})
}

func testAccUserResourceConfig_organizational(
	name, upn, sam,
	title, department, company, employeeID string,
) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  title            = %[7]q
  department       = %[8]q
  company          = %[9]q
  employee_id      = %[10]q
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, DefaultTestContainer,
		title, department, company, employeeID)
}

// TestAccUserResource_enableWithPassword is the positive-path counterpart to
// TestAccUserResource_updateSecurityFlags: given a password, enabling the
// account on create must succeed. Verifies that enabled=true survives an
// import round-trip (with password ignored).
func TestAccUserResource_enableWithPassword(t *testing.T) {
	name := GenerateTestName(TestUserPrefix + "enable-")
	samName := GenerateTestSAMName("en")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Step 1: create enabled user with a valid strong password.
			{
				Config: testAccUserResourceConfig_enabledWithPassword(name, upn, samName, "ComplexP@ssw0rd!#2024"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "true"),
				),
			},
			// Step 2: import with password ignored.
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

func testAccUserResourceConfig_enabledWithPassword(name, upn, sam, password string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  sam_account_name = %[5]q
  container        = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  password         = %[7]q
  enabled          = true
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, DefaultTestContainer, password)
}

// TestAccUserResource_changePasswordAtLogon exercises the
// change_password_at_logon flag: setting it to true alongside an initial
// password must persist through state and survive an import round-trip. The
// companion password_last_set attribute is computed by AD (via
// PasswordLastSetUnknown plan modifier) so we only assert it is set — AD
// represents "must change at next logon" by setting pwdLastSet to 0, which the
// provider then renders as a timestamp; depending on AD's epoch handling this
// may or may not surface as a stable string, so we avoid asserting its value.
func TestAccUserResource_changePasswordAtLogon(t *testing.T) {
	name := GenerateTestName(TestUserPrefix + "chgpwd-")
	samName := GenerateTestSAMName("chg")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig_changePasswordAtLogon(name, upn, samName, "ComplexP@ssw0rd!#2024"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "change_password_at_logon", "true"),
				),
			},
			{
				ResourceName:            "ad_user.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

func testAccUserResourceConfig_changePasswordAtLogon(name, upn, sam, password string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name                     = %[3]q
  principal_name           = %[4]q
  sam_account_name         = %[5]q
  container                = "%[6]s,${data.ad_rootdse.test.default_naming_context}"
  password                 = %[7]q
  change_password_at_logon = true
}
`, testProviderConfig(), testRootDSEDataSource(), name, upn, sam, DefaultTestContainer, password)
}
