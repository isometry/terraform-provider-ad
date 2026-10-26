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

// TestAccUserResource_passwordVersionBackToZero covers lowering password_version
// to 0 while a password remains configured: no password reset is performed, and
// the apply must still produce a fully known state (no unknown when_changed /
// password_last_set left over from the plan).
func TestAccUserResource_passwordVersionBackToZero(t *testing.T) {
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
				Config: testAccUserResourceConfig_withPasswordVersion(name, upn, samName, "InitialPass123!", 1),
				Check:  resource.TestCheckResourceAttr("ad_user.test", "password_version", "1"),
			},
			{
				Config:             testAccUserResourceConfig_withPasswordVersion(name, upn, samName, "InitialPass123!", 1),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: testAccUserResourceConfig_withPasswordVersion(name, upn, samName, "InitialPass123!", 0),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "password_version", "0"),
					resource.TestCheckResourceAttrSet("ad_user.test", "when_changed"),
					resource.TestCheckResourceAttrSet("ad_user.test", "password_last_set"),
				),
			},
		},
	})
}

// TestAccUserResource_volatileAttributesAfterOutOfBandChange adds the user to a
// group behind Terraform's back, then applies an unrelated change. On a real
// change ModifyPlan marks the server-owned computed attributes (member_of, ...)
// unknown, so the apply is consistent; a following plan must then be empty.
func TestAccUserResource_volatileAttributesAfterOutOfBandChange(t *testing.T) {
	name := GenerateTestName(TestUserPrefix)
	samName := GenerateTestSAMName("u")
	upn := fmt.Sprintf("%s@%s", samName, GetTestConfig().Domain)
	groupName := GenerateTestName(TestGroupPrefix)
	groupSAM := GenerateTestSAMName("g")

	var userDN, groupDN string

	config := func(description string) string {
		return fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_group" "test" {
  name             = %[3]q
  sam_account_name = %[4]q
  container        = "%[8]s,${data.ad_rootdse.test.default_naming_context}"
}

resource "ad_user" "test" {
  name             = %[5]q
  principal_name   = %[6]q
  sam_account_name = %[7]q
  container        = "%[8]s,${data.ad_rootdse.test.default_naming_context}"
  description      = %[9]q
}
`, testProviderConfig(), testRootDSEDataSource(), groupName, groupSAM, name, upn, samName, DefaultTestContainer, description)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckUserDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			{
				Config: config("before"),
				Check: resource.ComposeAggregateTestCheckFunc(
					captureStateAttr("ad_user.test", "dn", &userDN),
					captureStateAttr("ad_group.test", "dn", &groupDN),
				),
			},
			{
				PreConfig: func() {
					if err := addMemberOutOfBand(t.Context(), groupDN, userDN); err != nil {
						t.Fatalf("failed to add user to group out-of-band: %v", err)
					}
				},
				Config: config("after"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_user.test", "description", "after"),
					func(s *terraform.State) error {
						attrs := s.RootModule().Resources["ad_user.test"].Primary.Attributes
						for k, v := range attrs {
							if strings.HasPrefix(k, "member_of.") && k != "member_of.#" && strings.EqualFold(v, groupDN) {
								return nil
							}
						}
						return fmt.Errorf("member_of does not contain %q: %v", groupDN, attrs)
					},
				),
			},
			{
				Config:             config("after"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func addMemberOutOfBand(ctx context.Context, groupDN, memberDN string) error {
	client, err := ldapclient.NewClient(ctx, newTestLDAPConfig(GetTestConfig()))
	if err != nil {
		return fmt.Errorf("failed to create LDAP client: %w", err)
	}
	defer client.Close()

	return client.Modify(ctx, &ldapclient.ModifyRequest{
		DN:            groupDN,
		AddAttributes: map[string][]string{"member": {memberDN}},
	})
}
