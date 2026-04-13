package provider_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

func TestAccUserResource_basic(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccUserResourceConfig_basic(name, upn),
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
		},
	})
}

func TestAccUserResource_withSAMAccountName(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@test.local", samName)

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
	upn := fmt.Sprintf("%s@test.local", samName)
	description := "Test user with description"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig_withDescription(name, upn, description),
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
	upn := fmt.Sprintf("%s@test.local", samName)

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
		},
	})
}

func TestAccUserResource_update(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create initial user with description
			{
				Config: testAccUserResourceConfig_withDescription(name, upn, "Original description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "description", "Original description"),
					testAccStoreUserGUID("ad_user.test"),
				),
			},
			// Update description
			{
				Config: testAccUserResourceConfig_withDescription(name, upn, "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "description", "Updated description"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
			// Remove description (clear it)
			{
				Config: testAccUserResourceConfig_basic(name, upn),
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
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user with default security flags (no password → disabled)
			{
				Config: testAccUserResourceConfig_basic(name, upn),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
					resource.TestCheckResourceAttr("ad_user.test", "password_never_expires", "false"),
					testAccStoreUserGUID("ad_user.test"),
				),
			},
			// Explicitly disable account and enable password_never_expires
			{
				Config: testAccUserResourceConfig_withSecurityFlags(name, upn, false, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
					resource.TestCheckResourceAttr("ad_user.test", "password_never_expires", "true"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
			// Request enabled but no password → still disabled
			{
				Config: testAccUserResourceConfig_withSecurityFlags(name, upn, true, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "enabled", "false"),
					resource.TestCheckResourceAttr("ad_user.test", "password_never_expires", "true"),
					testAccCheckUserGUIDUnchanged(),
				),
			},
			// Reset to defaults (no password → still disabled)
			{
				Config: testAccUserResourceConfig_basic(name, upn),
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
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user in default container
			{
				Config: testAccUserResourceConfig_basic(name, upn),
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
				Config: testAccUserResourceConfig_withContainer(name, upn, "CN=Users"),
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
				Config: testAccUserResourceConfig_basic(name, upn),
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
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create disabled user
			{
				Config: testAccUserResourceConfig_withSecurityFlags(name, upn, false, false),
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
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create service account (password never expires)
			{
				Config: testAccUserResourceConfig_serviceAccount(name, upn),
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
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user
			{
				Config: testAccUserResourceConfig_basic(name, upn),
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
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user
			{
				Config: testAccUserResourceConfig_basic(name, upn),
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
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user
			{
				Config: testAccUserResourceConfig_basic(name, upn),
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
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user
			{
				Config: testAccUserResourceConfig_basic(name, upn),
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
	upn := fmt.Sprintf("%s@test.local", samName)

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
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(ctx, s)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccUserResourceConfig_basic(name, upn),
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

func testAccUserResourceConfig_basic(name, upn string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name           = %[1]q
  principal_name = %[2]q
  container      = "%[3]s,${data.ad_domain.test.dn}"
}
`, testProviderConfig(), testDomainDataSource(), name, upn, DefaultTestContainer)
}

func testAccUserResourceConfig_withSAMAccountName(name, upn, sam string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[1]q
  principal_name   = %[2]q
  sam_account_name = %[3]q
  container        = "%[4]s,${data.ad_domain.test.dn}"
}
`, testProviderConfig(), testDomainDataSource(), name, upn, sam, DefaultTestContainer)
}

func testAccUserResourceConfig_withContainer(name, upn, container string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name           = %[1]q
  principal_name = %[2]q
  container      = "%[3]s,${data.ad_domain.test.dn}"
}
`, testProviderConfig(), testDomainDataSource(), name, upn, container)
}

func testAccUserResourceConfig_withDescription(name, upn, description string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name           = %[1]q
  principal_name = %[2]q
  container      = "%[4]s,${data.ad_domain.test.dn}"
  description    = %[3]q
}
`, testProviderConfig(), testDomainDataSource(), name, upn, description, DefaultTestContainer)
}

func testAccUserResourceConfig_withSecurityFlags(name, upn string, enabled, passwordNeverExpires bool) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name                   = %[3]q
  principal_name         = %[4]q
  container              = "%[7]s,${data.ad_domain.test.dn}"
  enabled                = %[5]t
  password_never_expires = %[6]t
}
`, testProviderConfig(), testDomainDataSource(), name, upn, enabled, passwordNeverExpires, DefaultTestContainer)
}

func testAccUserResourceConfig_serviceAccount(name, upn string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name                   = %[1]q
  principal_name         = %[2]q
  container              = "%[3]s,${data.ad_domain.test.dn}"
  description            = "Service Account"
  password_never_expires = true
}
`, testProviderConfig(), testDomainDataSource(), name, upn, DefaultTestContainer)
}

func testAccUserResourceConfig_full(name, upn, sam string) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[1]q
  principal_name   = %[2]q
  sam_account_name = %[3]q
  container        = "%[4]s,${data.ad_domain.test.dn}"

  # Personal information
  display_name = "Test Display Name"
  description  = "Full test user"
  given_name   = "Test"
  surname      = "User"

  # Contact information
  email_address = "%[3]s@example.com"
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
`, testProviderConfig(), testDomainDataSource(), name, upn, sam, DefaultTestContainer)
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
		ldapURLs := []string{}
		if config.LDAPURL != "" {
			ldapURLs = []string{config.LDAPURL}
		}
		ldapConfig := &ldapclient.ConnectionConfig{
			Domain:         config.Domain,
			LDAPURLs:       ldapURLs,
			Username:       config.Username,
			Password:       config.Password,
			KerberosKeytab: config.Keytab,
			KerberosRealm:  config.Realm,
		}

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
	ldapURLs := []string{}
	if config.LDAPURL != "" {
		ldapURLs = []string{config.LDAPURL}
	}
	ldapConfig := &ldapclient.ConnectionConfig{
		Domain:         config.Domain,
		LDAPURLs:       ldapURLs,
		Username:       config.Username,
		Password:       config.Password,
		KerberosKeytab: config.Keytab,
		KerberosRealm:  config.Realm,
	}

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
		ldapURLs := []string{}
		if config.LDAPURL != "" {
			ldapURLs = []string{config.LDAPURL}
		}
		ldapConfig := &ldapclient.ConnectionConfig{
			Domain:         config.Domain,
			LDAPURLs:       ldapURLs,
			Username:       config.Username,
			Password:       config.Password,
			KerberosKeytab: config.Keytab,
			KerberosRealm:  config.Realm,
		}

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
	upn := fmt.Sprintf("%s@test.local", samName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create user with password (version=0, create-only)
			{
				Config: testAccUserResourceConfig_withPasswordVersion(name, upn, "InitialPass123!", 0),
				Check: resource.ComposeAggregateTestCheckFunc(
					testCheckUserExists(t.Context(), "ad_user.test"),
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "password_version", "0"),
				),
			},
			// Update version to 1 to trigger password reset
			{
				Config: testAccUserResourceConfig_withPasswordVersion(name, upn, "UpdatedPass456!", 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "password_version", "1"),
				),
			},
			// Keep version at 1, change password value - no reset should occur
			// (password_version unchanged means password is not applied)
			{
				Config: testAccUserResourceConfig_withPasswordVersion(name, upn, "DifferentPass789!", 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "name", name),
					resource.TestCheckResourceAttr("ad_user.test", "password_version", "1"),
				),
			},
			// Increment to version 2 to force password change
			{
				Config: testAccUserResourceConfig_withPasswordVersion(name, upn, "FinalPass999!", 2),
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

func testAccUserResourceConfig_withPasswordVersion(name, upn, password string, version int) string {
	return fmt.Sprintf(`
%s

%s

resource "ad_user" "test" {
  name             = %[3]q
  principal_name   = %[4]q
  container        = "%[7]s,${data.ad_domain.test.dn}"
  password         = %[5]q
  password_version = %[6]d
}
`, testProviderConfig(), testDomainDataSource(), name, upn, password, version, DefaultTestContainer)
}
