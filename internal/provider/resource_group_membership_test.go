package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccGroupMembershipResource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccGroupMembershipResourceConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser1,OU=TestUsers,DC=test,DC=local"),
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser2,OU=TestUsers,DC=test,DC=local"),
					resource.TestCheckResourceAttrSet("ad_group_membership.test", "id"),
					resource.TestCheckResourceAttrSet("ad_group_membership.test", "group_id"),
					// Verify that ID equals group_id by checking they're both GUIDs
					resource.TestMatchResourceAttr("ad_group_membership.test", "id",
						regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)),
					resource.TestMatchResourceAttr("ad_group_membership.test", "group_id",
						regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)),
				),
			},
			// ImportState testing
			{
				ResourceName:      "ad_group_membership.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccGroupMembershipImportStateIdFunc,
			},
			// Update membership (add a member)
			{
				Config: testAccGroupMembershipResourceConfig_updated(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "3"),
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser1,OU=TestUsers,DC=test,DC=local"),
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser2,OU=TestUsers,DC=test,DC=local"),
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser3,OU=TestUsers,DC=test,DC=local"),
				),
			},
			// Update membership (remove a member)
			{
				Config: testAccGroupMembershipResourceConfig_reduced(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser1,OU=TestUsers,DC=test,DC=local"),
				),
			},
		},
	})
}

func TestAccGroupMembershipResource_antiDrift(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with DN format
			{
				Config: testAccGroupMembershipResourceConfig_antiDriftDN(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser1,OU=TestUsers,DC=test,DC=local"),
				),
			},
			// Update with UPN format (same user) - should be no-op
			{
				Config:   testAccGroupMembershipResourceConfig_antiDriftUPN(),
				PlanOnly: true,
				// This should not show any changes because the UPN should normalize to the same DN
				ExpectNonEmptyPlan: false,
			},
			// Apply with UPN format to verify it works
			{
				Config: testAccGroupMembershipResourceConfig_antiDriftUPN(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					// State should still contain the normalized DN
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser1,OU=TestUsers,DC=test,DC=local"),
				),
			},
			// Test with GUID format (same user) - should be no-op
			{
				Config:   testAccGroupMembershipResourceConfig_antiDriftGUID(),
				PlanOnly: true,
				// This should not show any changes because the GUID should normalize to the same DN
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccGroupMembershipResource_mixedIdentifiers(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with mixed identifier formats
			{
				Config: testAccGroupMembershipResourceConfig_mixedIdentifiers(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "3"),
					// All should be normalized to DNs in state
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser1,OU=TestUsers,DC=test,DC=local"),
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser2,OU=TestUsers,DC=test,DC=local"),
					resource.TestCheckTypeSetElemAttr("ad_group_membership.test", "members.*", "CN=testuser3,OU=TestUsers,DC=test,DC=local"),
				),
			},
		},
	})
}

func TestAccGroupMembershipResource_largeSet(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with many members (testing batch operations)
			{
				Config: testAccGroupMembershipResourceConfig_largeSet(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "10"),
				),
			},
		},
	})
}

func TestAccGroupMembershipResource_empty(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with members, then clear them
			{
				Config: testAccGroupMembershipResourceConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
				),
			},
			// Clear all members
			{
				Config: testAccGroupMembershipResourceConfig_empty(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "0"),
				),
			},
		},
	})
}

// testAccGroupMembershipImportStateIdFunc returns the group GUID for import testing
func testAccGroupMembershipImportStateIdFunc(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources["ad_group_membership.test"]
	if !ok {
		return "", fmt.Errorf("Not found: ad_group_membership.test")
	}

	return rs.Primary.Attributes["group_id"], nil
}

// Configuration functions for tests

func testAccGroupMembershipResourceConfig_basic() string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    "CN=testuser1,OU=TestUsers,DC=test,DC=local",
    "CN=testuser2,OU=TestUsers,DC=test,DC=local"
  ]
}
`, testAccGroupMembershipResourceConfig_prerequisite())
}

func testAccGroupMembershipResourceConfig_updated() string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    "CN=testuser1,OU=TestUsers,DC=test,DC=local",
    "CN=testuser2,OU=TestUsers,DC=test,DC=local",
    "CN=testuser3,OU=TestUsers,DC=test,DC=local"
  ]
}
`, testAccGroupMembershipResourceConfig_prerequisite())
}

func testAccGroupMembershipResourceConfig_reduced() string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    "CN=testuser1,OU=TestUsers,DC=test,DC=local"
  ]
}
`, testAccGroupMembershipResourceConfig_prerequisite())
}

func testAccGroupMembershipResourceConfig_antiDriftDN() string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    "CN=testuser1,OU=TestUsers,DC=test,DC=local"  # DN format
  ]
}
`, testAccGroupMembershipResourceConfig_prerequisite())
}

func testAccGroupMembershipResourceConfig_antiDriftUPN() string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    "testuser1@test.local"  # UPN format (same user as above)
  ]
}
`, testAccGroupMembershipResourceConfig_prerequisite())
}

func testAccGroupMembershipResourceConfig_antiDriftGUID() string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    "550e8400-e29b-41d4-a716-446655440001"  # GUID format (same user)
  ]
}
`, testAccGroupMembershipResourceConfig_prerequisite())
}

func testAccGroupMembershipResourceConfig_mixedIdentifiers() string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    "CN=testuser1,OU=TestUsers,DC=test,DC=local",  # DN format
    "testuser2@test.local",                        # UPN format
    "TEST\\testuser3"                              # SAM format
  ]
}
`, testAccGroupMembershipResourceConfig_prerequisite())
}

func testAccGroupMembershipResourceConfig_largeSet() string {
	membersList := make([]string, 10)
	for i := 0; i < 10; i++ {
		membersList[i] = fmt.Sprintf("\"CN=testuser%d,OU=TestUsers,DC=test,DC=local\"", i+1)
	}

	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    %s
  ]
}
`, testAccGroupMembershipResourceConfig_prerequisite(),
		strings.Join(membersList, ",\n    "))
}

func testAccGroupMembershipResourceConfig_empty() string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = []
}
`, testAccGroupMembershipResourceConfig_prerequisite())
}

// Prerequisite configuration that creates a test group
func testAccGroupMembershipResourceConfig_prerequisite() string {
	return `
data "ad_domain" "test" {}

resource "ad_group" "test" {
  name             = "tf-test-group-membership"
  sam_account_name = "TFTestGroupMembership"
  container        = "CN=Users,${data.ad_domain.test.base_dn}"
  scope            = "Global"
  category         = "Security"
  description      = "Test group for membership testing"
}
`
}

// Additional test configurations for error scenarios

func TestAccGroupMembershipResource_invalidGroupId(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccGroupMembershipResourceConfig_invalidGroupId(),
				ExpectError: regexp.MustCompile("not found"),
			},
		},
	})
}

func testAccGroupMembershipResourceConfig_invalidGroupId() string {
	return `
resource "ad_group_membership" "test" {
  group_id = "invalid-guid-that-does-not-exist"
  members = [
    "CN=testuser1,OU=TestUsers,DC=test,DC=local"
  ]
}
`
}

func TestAccGroupMembershipResource_invalidMember(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccGroupMembershipResourceConfig_invalidMember(),
				ExpectError: regexp.MustCompile("invalid member identifier"),
			},
		},
	})
}

func testAccGroupMembershipResourceConfig_invalidMember() string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    "invalid-member-identifier-format"
  ]
}
`, testAccGroupMembershipResourceConfig_prerequisite())
}
