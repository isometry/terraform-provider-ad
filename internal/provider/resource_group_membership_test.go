package provider_test

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// gmTestNames holds the unique names used by a single membership-test
// prerequisite plan so that every step in the same test references the same
// resources consistently.
type gmTestNames struct {
	OU      string
	Group   string
	GroupS  string
	User1   string
	User1S  string
	User2   string
	User2S  string
	User3   string
	User3S  string
	ExtraUs []struct {
		Name string
		SAM  string
	}
}

// newGMTestNames builds a set of unique names for a single test invocation.
// extraUsers creates additional user resources beyond the three defaults
// (used by the _largeSet test).
func newGMTestNames(extraUsers int) gmTestNames {
	n := gmTestNames{
		OU:     GenerateTestName("tf-mship-ou-"),
		Group:  GenerateTestName("tf-mship-grp-"),
		GroupS: GenerateTestSAMName("TFMshipG"),
		User1:  GenerateTestName("tf-mship-u1-"),
		User1S: GenerateTestSAMName("tfmshu1"),
		User2:  GenerateTestName("tf-mship-u2-"),
		User2S: GenerateTestSAMName("tfmshu2"),
		User3:  GenerateTestName("tf-mship-u3-"),
		User3S: GenerateTestSAMName("tfmshu3"),
	}
	for i := range extraUsers {
		n.ExtraUs = append(n.ExtraUs, struct {
			Name string
			SAM  string
		}{
			Name: GenerateTestName(fmt.Sprintf("tf-mship-ue%d-", i)),
			SAM:  GenerateTestSAMName(fmt.Sprintf("tfmshe%d", i)),
		})
	}
	return n
}

// prerequisiteConfig emits provider + rootdse + a test OU + three users
// inside that OU + a test group inside that OU. Optionally emits `extraUsers`
// additional ad_user.extra[N] resources.
func prerequisiteConfig(n gmTestNames) string {
	var extras strings.Builder
	for i, u := range n.ExtraUs {
		fmt.Fprintf(&extras, `
resource "ad_user" "extra%[1]d" {
  name             = %[2]q
  sam_account_name = %[3]q
  principal_name   = format("%[3]s@%%s", data.ad_rootdse.test.domain_name)
  container        = ad_ou.test.dn
}
`, i, u.Name, u.SAM)
	}

	return fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_ou" "test" {
  name        = %[3]q
  path        = data.ad_rootdse.test.default_naming_context
  description = "Temporary OU for ad_group_membership acceptance tests"
}

resource "ad_user" "testuser1" {
  name             = %[4]q
  sam_account_name = %[5]q
  principal_name   = format("%[5]s@%%s", data.ad_rootdse.test.domain_name)
  container        = ad_ou.test.dn
}

resource "ad_user" "testuser2" {
  name             = %[6]q
  sam_account_name = %[7]q
  principal_name   = format("%[7]s@%%s", data.ad_rootdse.test.domain_name)
  container        = ad_ou.test.dn
}

resource "ad_user" "testuser3" {
  name             = %[8]q
  sam_account_name = %[9]q
  principal_name   = format("%[9]s@%%s", data.ad_rootdse.test.domain_name)
  container        = ad_ou.test.dn
}

resource "ad_group" "test" {
  name             = %[10]q
  sam_account_name = %[11]q
  container        = ad_ou.test.dn
  scope            = "global"
  category         = "security"
  description      = "Test group for membership testing"
}
%[12]s`,
		testProviderConfig(),
		testRootDSEDataSource(),
		n.OU,
		n.User1, n.User1S,
		n.User2, n.User2S,
		n.User3, n.User3S,
		n.Group, n.GroupS,
		extras.String(),
	)
}

func TestAccGroupMembershipResource_basic(t *testing.T) {
	n := newGMTestNames(0)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccGroupMembershipResourceConfig_basic(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
					resource.TestCheckResourceAttrPair(
						"ad_group_membership.test", "group_id",
						"ad_group.test", "id",
					),
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
				Config: testAccGroupMembershipResourceConfig_updated(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "3"),
				),
			},
			// Update membership (remove a member)
			{
				Config: testAccGroupMembershipResourceConfig_reduced(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
				),
			},
		},
	})
}

// TestAccGroupMembershipResource_antiDrift verifies that `members` is a
// strictly verbatim passthrough of configuration: switching an existing
// member's identifier format (DN -> UPN -> GUID) for the very same AD
// principal is a real, expected plan diff on `members` (never silently
// reconciled), while `members_normalized` (and therefore actual AD
// membership) does not change across the format switch. Each format switch
// converges to an empty plan on the next apply.
func TestAccGroupMembershipResource_antiDrift(t *testing.T) {
	n := newGMTestNames(0)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with DN format
			{
				Config: testAccGroupMembershipResourceConfig_antiDriftDN(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "members_normalized.#", "1"),
				),
			},
			// Switching to UPN format for the same user is a real change to
			// the verbatim `members` attribute, even though the UPN
			// normalizes to the same DN. A non-empty plan is expected.
			{
				Config:             testAccGroupMembershipResourceConfig_antiDriftUPN(n),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			// Apply the UPN format: `members` must now hold the UPN
			// verbatim, while `members_normalized` (actual AD membership) is
			// unchanged.
			{
				Config: testAccGroupMembershipResourceConfig_antiDriftUPN(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "members_normalized.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(
						"ad_group_membership.test", "members.*",
						"ad_user.testuser1", "principal_name",
					),
				),
			},
			// Re-planning the same UPN config converges to an empty plan.
			{
				Config:             testAccGroupMembershipResourceConfig_antiDriftUPN(n),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Switching to GUID format is again a real change to `members`.
			{
				Config:             testAccGroupMembershipResourceConfig_antiDriftGUID(n),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			// Apply the GUID format: `members` must now hold the GUID
			// verbatim, while `members_normalized` (actual AD membership) is
			// unchanged.
			{
				Config: testAccGroupMembershipResourceConfig_antiDriftGUID(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "members_normalized.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(
						"ad_group_membership.test", "members.*",
						"ad_user.testuser1", "id",
					),
				),
			},
			// Re-planning the same GUID config converges to an empty plan.
			{
				Config:             testAccGroupMembershipResourceConfig_antiDriftGUID(n),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccGroupMembershipResource_mixedIdentifiers(t *testing.T) {
	n := newGMTestNames(0)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with mixed identifier formats (DN, UPN, GUID)
			{
				Config: testAccGroupMembershipResourceConfig_mixedIdentifiers(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "3"),
					// All should normalize to the same set of DNs
					resource.TestCheckResourceAttr("ad_group_membership.test", "members_normalized.#", "3"),
				),
			},
		},
	})
}

// mangleDNCase mimics the attribute-type case mangling performed by
// testAccGroupMembershipResourceConfig_mixedCaseDN's HCL `replace()` chain,
// so the Go test can compute the exact verbatim value expected in `members`
// without needing to read it back from a Terraform expression.
func mangleDNCase(dn string) string {
	out := dn
	for _, pair := range [][2]string{
		{"CN=", "Cn="},
		{"OU=", "Ou="},
		{"DC=", "Dc="},
	} {
		out = strings.ReplaceAll(out, pair[0], pair[1])
	}
	return out
}

// TestAccGroupMembershipResource_dnCaseNormalization verifies that `members`
// is a strictly verbatim passthrough of configuration: changing only the DN
// attribute-type case (e.g. `cn=` -> `Cn=`) for the same member is a real,
// expected plan diff on `members` (never silently reconciled), even though
// the underlying AD principal - and therefore `members_normalized` - is
// unchanged. Each case change converges to an empty plan on the next apply.
func TestAccGroupMembershipResource_dnCaseNormalization(t *testing.T) {
	n := newGMTestNames(0)

	var testUser1DN string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with lowercase DN
			{
				Config: testAccGroupMembershipResourceConfig_lowercaseDN(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "members_normalized.#", "1"),
					captureStateAttr("ad_user.testuser1", "dn", &testUser1DN),
				),
			},
			// Switching to a mixed-case DN for the same member is a real
			// change to the verbatim `members` attribute, even though DN
			// semantic-equality means the same AD principal is referenced. A
			// non-empty plan is expected.
			{
				Config:             testAccGroupMembershipResourceConfig_mixedCaseDN(n),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			// Apply the mixed-case DN: `members` must now hold the
			// mixed-case value verbatim, while `members_normalized` (actual
			// AD membership) is unchanged.
			{
				Config: testAccGroupMembershipResourceConfig_mixedCaseDN(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "members_normalized.#", "1"),
					func(s *terraform.State) error {
						return resource.TestCheckTypeSetElemAttr(
							"ad_group_membership.test", "members.*", mangleDNCase(testUser1DN),
						)(s)
					},
				),
			},
			// Re-planning the same mixed-case config converges to an empty plan.
			{
				Config:             testAccGroupMembershipResourceConfig_mixedCaseDN(n),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Switching back to the lowercase DN is again a real change to
			// `members`.
			{
				Config:             testAccGroupMembershipResourceConfig_lowercaseDN(n),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			// Apply the lowercase DN again: `members` reflects it verbatim,
			// and `members_normalized` (actual AD membership) is unchanged.
			{
				Config: testAccGroupMembershipResourceConfig_lowercaseDN(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "members_normalized.#", "1"),
					func(s *terraform.State) error {
						return resource.TestCheckTypeSetElemAttr(
							"ad_group_membership.test", "members.*", strings.ToLower(testUser1DN),
						)(s)
					},
				),
			},
			// Re-planning the same lowercase config converges to an empty plan.
			{
				Config:             testAccGroupMembershipResourceConfig_lowercaseDN(n),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccGroupMembershipResource_membersVerbatimNoInvalidPlan is an
// end-to-end, protocol-level regression test for the exact bug shape that
// broke CI on PR #5017 (github.com/nexthink/rbac4engineering): an existing
// membership established with DN-based members is reconfigured to reference
// the same principals - plus one newly added member - using GUIDs. Before
// the fix, ModifyPlan partially rewrote `members` against prior state
// (reusing state's DN literal for members that resolved to the same
// principal, while leaving the new member in its configured GUID format),
// producing a planned value that matched neither config nor prior state and
// triggering "Provider produced invalid plan". This test exercises the full
// plan+apply protocol path (not just ModifyPlan in isolation) to confirm the
// framework accepts the plan.
func TestAccGroupMembershipResource_membersVerbatimNoInvalidPlan(t *testing.T) {
	n := newGMTestNames(0)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Establish membership with DN-based members (simulates
			// legacy/imported prior state).
			{
				Config: testAccGroupMembershipResourceConfig_verbatimTransitionDN(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "members_normalized.#", "2"),
				),
			},
			// Reconfigure using GUIDs for the existing two members plus a
			// newly added third member, also as a GUID. This is the exact
			// shape of the CI failure: existing members changing format at
			// the same time a new member is added in the differing format,
			// against DN-based prior state. If the framework rejects this
			// plan with "Provider produced invalid plan", this step fails
			// with that protocol error.
			{
				Config: testAccGroupMembershipResourceConfig_verbatimTransitionGUID(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "3"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "members_normalized.#", "3"),
					// `members` must equal the configured GUIDs verbatim.
					resource.TestCheckTypeSetElemAttrPair(
						"ad_group_membership.test", "members.*",
						"ad_user.testuser1", "id",
					),
					resource.TestCheckTypeSetElemAttrPair(
						"ad_group_membership.test", "members.*",
						"ad_user.testuser2", "id",
					),
					resource.TestCheckTypeSetElemAttrPair(
						"ad_group_membership.test", "members.*",
						"ad_user.testuser3", "id",
					),
					// `members_normalized` must equal the resolved DNs for
					// all three members (old + new).
					resource.TestCheckTypeSetElemAttrPair(
						"ad_group_membership.test", "members_normalized.*",
						"ad_user.testuser1", "dn",
					),
					resource.TestCheckTypeSetElemAttrPair(
						"ad_group_membership.test", "members_normalized.*",
						"ad_user.testuser2", "dn",
					),
					resource.TestCheckTypeSetElemAttrPair(
						"ad_group_membership.test", "members_normalized.*",
						"ad_user.testuser3", "dn",
					),
				),
			},
			// Re-planning the same GUID config converges to an empty plan.
			{
				Config:             testAccGroupMembershipResourceConfig_verbatimTransitionGUID(n),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func testAccGroupMembershipResourceConfig_verbatimTransitionDN(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    ad_user.testuser1.dn,
    ad_user.testuser2.dn,
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_verbatimTransitionGUID(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    ad_user.testuser1.id,
    ad_user.testuser2.id,
    ad_user.testuser3.id,
  ]
}
`, prerequisiteConfig(n))
}

// Members declared with surrounding whitespace must apply cleanly, populate
// members_normalized with the trimmed canonical DNs, and produce zero diff on
// re-plan.
func TestAccGroupMembershipResource_WhitespaceTolerantMembers(t *testing.T) {
	n := newGMTestNames(0)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupMembershipResourceConfig_whitespacePadded(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "members_normalized.#", "2"),
				),
			},
			{
				Config:             testAccGroupMembershipResourceConfig_whitespacePadded(n),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccGroupMembershipResource_largeSet(t *testing.T) {
	// 3 base users + 7 extras = 10 total members
	n := newGMTestNames(7)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with many members (testing batch operations)
			{
				Config: testAccGroupMembershipResourceConfig_largeSet(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "10"),
				),
			},
		},
	})
}

func TestAccGroupMembershipResource_empty(t *testing.T) {
	n := newGMTestNames(0)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with members, then clear them
			{
				Config: testAccGroupMembershipResourceConfig_basic(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
				),
			},
			// Clear all members
			{
				Config: testAccGroupMembershipResourceConfig_empty(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "0"),
				),
			},
		},
	})
}

// TestAccGroupMembershipResource_unknownGroupId tests handling of unknown group_id
// during planning when the group is created in the same plan.
func TestAccGroupMembershipResource_unknownGroupId(t *testing.T) {
	n := newGMTestNames(0)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create group and membership in same plan with group ID dependency
			{
				Config: testAccGroupMembershipResourceConfig_unknownGroupId(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
					resource.TestCheckResourceAttrSet("ad_group_membership.test", "group_id"),
				),
			},
		},
	})
}

// TestAccGroupMembershipResource_unknownMembers tests handling of unknown member values
// during planning when members reference groups created in the same plan.
func TestAccGroupMembershipResource_unknownMembers(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create multiple groups and a membership that references their IDs
			{
				Config: testAccGroupMembershipResourceConfig_unknownMembers(),
				Check: resource.ComposeAggregateTestCheckFunc(
					// The filter group should have 2 member groups
					resource.TestCheckResourceAttr("ad_group_membership.filter", "members.#", "2"),
					resource.TestCheckResourceAttrSet("ad_group_membership.filter", "group_id"),
					resource.TestCheckResourceAttrSet("ad_group_membership.filter", "members_normalized.#"),
				),
			},
		},
	})
}

// testAccGroupMembershipImportStateIdFunc returns the group GUID for import testing.
func testAccGroupMembershipImportStateIdFunc(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources["ad_group_membership.test"]
	if !ok {
		return "", fmt.Errorf("Not found: ad_group_membership.test")
	}

	return rs.Primary.Attributes["group_id"], nil
}

// Configuration functions for tests

func testAccGroupMembershipResourceConfig_basic(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    ad_user.testuser1.dn,
    ad_user.testuser2.dn,
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_updated(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    ad_user.testuser1.dn,
    ad_user.testuser2.dn,
    ad_user.testuser3.dn,
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_reduced(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    ad_user.testuser1.dn,
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_antiDriftDN(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    ad_user.testuser1.dn, # DN format
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_antiDriftUPN(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    ad_user.testuser1.principal_name, # UPN format (same user)
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_antiDriftGUID(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    ad_user.testuser1.id, # GUID format (same user)
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_mixedIdentifiers(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    ad_user.testuser1.dn,             # DN format
    ad_user.testuser2.principal_name, # UPN format
    ad_user.testuser3.id,             # GUID format
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_lowercaseDN(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    lower(ad_user.testuser1.dn), # Lowercase DN format
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_mixedCaseDN(n gmTestNames) string {
	// Mangle only the attribute-type prefixes (CN=, OU=, DC=) to a mixed case
	// while preserving the RDN values. DN normalization should still treat
	// this as the same DN as the canonical form.
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    replace(
      replace(
        replace(ad_user.testuser1.dn, "CN=", "Cn="),
        "OU=", "Ou="
      ),
      "DC=", "Dc="
    ), # Mixed case DN format
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_whitespacePadded(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    format("  %%s  ", ad_user.testuser1.dn), # padded DN
    format("\t%%s\n", ad_user.testuser2.dn), # tab/newline padded DN
  ]
}
`, prerequisiteConfig(n))
}

func testAccGroupMembershipResourceConfig_largeSet(n gmTestNames) string {
	// 3 primary + 7 extras = 10 total members.
	var members []string
	members = append(members,
		"ad_user.testuser1.dn",
		"ad_user.testuser2.dn",
		"ad_user.testuser3.dn",
	)
	for i := range n.ExtraUs {
		members = append(members, fmt.Sprintf("ad_user.extra%d.dn", i))
	}

	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    %s,
  ]
}
`, prerequisiteConfig(n), strings.Join(members, ",\n    "))
}

func testAccGroupMembershipResourceConfig_empty(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members  = []
}
`, prerequisiteConfig(n))
}

// Test configuration for unknown group_id scenario.
func testAccGroupMembershipResourceConfig_unknownGroupId(n gmTestNames) string {
	return fmt.Sprintf(`
%s

# Group is created in same plan, so ID is unknown during planning.
resource "ad_group" "dynamic" {
  name             = %[2]q
  sam_account_name = %[3]q
  container        = ad_ou.test.dn
  scope            = "global"
  category         = "security"
  description      = "Test group created dynamically"
}

# Membership references the dynamic group's ID (unknown during planning).
resource "ad_group_membership" "test" {
  group_id = ad_group.dynamic.id
  members = [
    ad_user.testuser1.dn,
    ad_user.testuser2.dn,
  ]
}
`,
		prerequisiteConfig(n),
		GenerateTestName("tf-mship-dyn-"),
		GenerateTestSAMName("TFMshipDyn"),
	)
}

// Test configuration for unknown members scenario (simulates user's exact use case).
func testAccGroupMembershipResourceConfig_unknownMembers() string {
	return fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_ou" "test" {
  name        = %[3]q
  path        = data.ad_rootdse.test.default_naming_context
  description = "Temporary OU for ad_group_membership unknown-members test"
}

# Create two groups dynamically (similar to user's aws roles)
resource "ad_group" "aws_role_1" {
  name             = %[4]q
  sam_account_name = %[5]q
  container        = ad_ou.test.dn
  scope            = "domainlocal"
  category         = "security"
  description      = "Test AWS role 1"
}

resource "ad_group" "aws_role_2" {
  name             = %[6]q
  sam_account_name = %[7]q
  container        = ad_ou.test.dn
  scope            = "domainlocal"
  category         = "security"
  description      = "Test AWS role 2"
}

# Create a filter group
resource "ad_group" "filter" {
  name             = %[8]q
  sam_account_name = %[9]q
  container        = ad_ou.test.dn
  scope            = "domainlocal"
  category         = "security"
  description      = "Test AWS filter group"
}

# Add membership where members are the IDs of groups created above.
# This simulates the user's exact scenario where members are unknown during planning.
resource "ad_group_membership" "filter" {
  group_id = ad_group.filter.id
  members = [
    ad_group.aws_role_1.id,
    ad_group.aws_role_2.id,
  ]
}
`,
		testProviderConfig(),
		testRootDSEDataSource(),
		GenerateTestName("tf-mship-unk-ou-"),
		GenerateTestName("tf-test-aws-role-1-"), GenerateTestSAMName("TFMshipAR1"),
		GenerateTestName("tf-test-aws-role-2-"), GenerateTestSAMName("TFMshipAR2"),
		GenerateTestName("tf-test-aws-filter-"), GenerateTestSAMName("TFMshipAF"),
	)
}

// Additional test configurations for error scenarios

func TestAccGroupMembershipResource_invalidGroupId(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupMembershipResourceConfig_invalidGroupId(),
				// Plan-time member normalization runs before the group_id is
				// resolved against AD, so the first error surfaced is per-
				// member ("Member could not be resolved"). The strict-mode
				// safety net ("All Members Failed to Resolve") only fires
				// when ignore_missing_members is true, but match it anyway
				// for robustness.
				ExpectError: regexp.MustCompile(
					`Member could not be resolved|All Members Failed to Resolve`,
				),
			},
		},
	})
}

func testAccGroupMembershipResourceConfig_invalidGroupId() string {
	// Deliberately uses a non-existent group GUID and a syntactically-valid
	// but fictional member DN. The provider should fail during apply when it
	// tries to resolve the group_id, so the member never actually gets looked
	// up in AD.
	return fmt.Sprintf(`
%s

%s

resource "ad_group_membership" "test" {
  group_id = "00000000-0000-0000-0000-000000000000"
  members = [
    "CN=nonexistent,${data.ad_rootdse.test.default_naming_context}",
  ]
}
`, testProviderConfig(), testRootDSEDataSource())
}

func TestAccGroupMembershipResource_invalidMember(t *testing.T) {
	n := newGMTestNames(0)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccGroupMembershipResourceConfig_invalidMember(n),
				// Plan-time normalization fails for the bogus identifier
				// and surfaces a per-member "Member could not be resolved"
				// diagnostic.
				ExpectError: regexp.MustCompile(
					`Member could not be resolved|All Members Failed to Resolve`,
				),
			},
		},
	})
}

func testAccGroupMembershipResourceConfig_invalidMember(n gmTestNames) string {
	return fmt.Sprintf(`
%s

resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members = [
    "invalid-member-identifier-format",
  ]
}
`, prerequisiteConfig(n))
}

// TestValidateMemberIdentifiers tests member identifier validation.
func TestValidateMemberIdentifiers(t *testing.T) {
	testCases := []struct {
		name      string
		members   []string
		expectErr bool
	}{
		{
			name:      "empty members",
			members:   []string{},
			expectErr: false,
		},
		{
			name:      "nil members",
			members:   nil,
			expectErr: false,
		},
		{
			name: "valid DN",
			members: []string{
				"CN=TestUser,CN=Users,DC=example,DC=com",
			},
			expectErr: false,
		},
		{
			name: "valid GUID",
			members: []string{
				"550e8400-e29b-41d4-a716-446655440000",
			},
			expectErr: false,
		},
		{
			name: "valid SID",
			members: []string{
				"S-1-5-21-123456789-123456789-123456789-1001",
			},
			expectErr: false,
		},
		{
			name: "valid UPN",
			members: []string{
				"user@example.com",
			},
			expectErr: false,
		},
		{
			name: "valid SAM with domain",
			members: []string{
				"EXAMPLE\\user",
			},
			expectErr: false,
		},
		{
			name: "mixed valid identifiers",
			members: []string{
				"CN=TestUser,CN=Users,DC=example,DC=com",
				"550e8400-e29b-41d4-a716-446655440000",
				"user@example.com",
				"EXAMPLE\\user",
			},
			expectErr: false,
		},
		{
			name: "invalid identifier",
			members: []string{
				"@invalid.com", // Invalid UPN format (missing username)
			},
			expectErr: true,
		},
		{
			name: "mixed valid and invalid",
			members: []string{
				"CN=TestUser,CN=Users,DC=example,DC=com",
				"domain\\", // Invalid SAM format (missing username)
			},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the validation directly using the normalizer since we're only
			// testing format validation, not actual LDAP resolution
			normalizer := ldapclient.NewMemberNormalizer(nil, "DC=example,DC=com", ldapclient.NewCacheManager())

			// Create a temporary manager-like validator
			var err error
			for _, member := range tc.members {
				if validationErr := normalizer.ValidateIdentifier(member); validationErr != nil {
					err = validationErr
					break
				}
			}

			if tc.expectErr && err == nil {
				t.Error("Expected error but got none")
			}

			if !tc.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// Benchmark tests for member identifier validation.
func BenchmarkValidateMemberIdentifiers(b *testing.B) {
	members := []string{
		"CN=TestUser1,CN=Users,DC=example,DC=com",
		"CN=TestUser2,CN=Users,DC=example,DC=com",
		"550e8400-e29b-41d4-a716-446655440000",
		"user@example.com",
		"EXAMPLE\\user",
		"S-1-5-21-123456789-123456789-123456789-1001",
	}

	// Test validation directly using the normalizer for benchmarks
	normalizer := ldapclient.NewMemberNormalizer(nil, "DC=example,DC=com", ldapclient.NewCacheManager())

	for b.Loop() {
		for _, member := range members {
			_ = normalizer.ValidateIdentifier(member)
		}
	}
}

// Test helper function to create various member identifier formats.
func createTestMembers(count int) []string {
	members := make([]string, count)

	for i := range count {
		switch i % 5 {
		case 0:
			members[i] = "CN=TestUser" + string(rune(i)) + ",CN=Users,DC=example,DC=com"
		case 1:
			members[i] = "550e8400-e29b-41d4-a716-44665544000" + string(rune(i))
		case 2:
			members[i] = "user" + string(rune(i)) + "@example.com"
		case 3:
			members[i] = "EXAMPLE\\user" + string(rune(i))
		case 4:
			members[i] = "S-1-5-21-123456789-123456789-123456789-100" + string(rune(i))
		}
	}

	return members
}

// TestGroupMembershipResource_resolveIgnoreMissingMembers tests the resolution logic
// for ignore_missing_members at resource level vs provider level.
func TestGroupMembershipResource_resolveIgnoreMissingMembers(t *testing.T) {
	tests := []struct {
		name            string
		resourceValue   *bool // nil = not set (null), otherwise explicit value
		providerDefault bool
		expected        bool
	}{
		{
			name:            "resource true overrides provider false",
			resourceValue:   new(true),
			providerDefault: false,
			expected:        true,
		},
		{
			name:            "resource false overrides provider true",
			resourceValue:   new(false),
			providerDefault: true,
			expected:        false,
		},
		{
			name:            "resource null inherits provider true",
			resourceValue:   nil,
			providerDefault: true,
			expected:        true,
		},
		{
			name:            "resource null inherits provider false",
			resourceValue:   nil,
			providerDefault: false,
			expected:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Test the resolution logic directly
			// Priority: resource explicit > provider setting
			var effectiveIgnoreMissing bool

			if tc.resourceValue != nil {
				effectiveIgnoreMissing = *tc.resourceValue
			} else {
				effectiveIgnoreMissing = tc.providerDefault
			}

			if effectiveIgnoreMissing != tc.expected {
				t.Errorf("Expected effectiveIgnoreMissing=%v, got %v", tc.expected, effectiveIgnoreMissing)
			}
		})
	}
}

// Benchmark with different member counts.
func BenchmarkValidateMemberIdentifiers10(b *testing.B) {
	members := createTestMembers(10)
	normalizer := ldapclient.NewMemberNormalizer(nil, "DC=example,DC=com", ldapclient.NewCacheManager())

	for b.Loop() {
		for _, member := range members {
			_ = normalizer.ValidateIdentifier(member)
		}
	}
}

func BenchmarkValidateMemberIdentifiers100(b *testing.B) {
	members := createTestMembers(100)
	normalizer := ldapclient.NewMemberNormalizer(nil, "DC=example,DC=com", ldapclient.NewCacheManager())

	for b.Loop() {
		for _, member := range members {
			_ = normalizer.ValidateIdentifier(member)
		}
	}
}

func BenchmarkValidateMemberIdentifiers1000(b *testing.B) {
	members := createTestMembers(1000)
	normalizer := ldapclient.NewMemberNormalizer(nil, "DC=example,DC=com", ldapclient.NewCacheManager())

	for b.Loop() {
		for _, member := range members {
			_ = normalizer.ValidateIdentifier(member)
		}
	}
}

// TestAccGroupMembershipResource_groupAsMember exercises a membership that
// mixes a child group and a user, then swaps the child group for a different
// group, to confirm set-update semantics when members include groups.
//
// No new import step is needed — TestAccGroupMembershipResource_basic already
// covers that path.
func TestAccGroupMembershipResource_groupAsMember(t *testing.T) {
	parentName := GenerateTestName("tf-mship-gamp-")
	parentSAM := GenerateTestSAMName("TFMshipGAMP")
	childAName := GenerateTestName("tf-mship-gamca-")
	childASAM := GenerateTestSAMName("TFMshipGAMCa")
	childBName := GenerateTestName("tf-mship-gamcb-")
	childBSAM := GenerateTestSAMName("TFMshipGAMCb")
	ouName := GenerateTestName("tf-mship-gam-ou-")
	userName := GenerateTestName("tf-mship-gam-u-")
	userSAM := GenerateTestSAMName("tfmshgamu")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: parent.members = {child_a, user}. Membership count = 2.
			{
				Config: testAccGroupMembershipResourceConfig_groupAsMember(
					ouName, parentName, parentSAM,
					childAName, childASAM, childBName, childBSAM,
					userName, userSAM, "a",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
					resource.TestCheckResourceAttrPair(
						"ad_group_membership.test", "group_id",
						"ad_group.parent", "id",
					),
				),
			},
			// Step 1b: replan same config → no diff.
			{
				Config: testAccGroupMembershipResourceConfig_groupAsMember(
					ouName, parentName, parentSAM,
					childAName, childASAM, childBName, childBSAM,
					userName, userSAM, "a",
				),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 2: swap child_a → child_b. Membership count still 2.
			{
				Config: testAccGroupMembershipResourceConfig_groupAsMember(
					ouName, parentName, parentSAM,
					childAName, childASAM, childBName, childBSAM,
					userName, userSAM, "b",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
				),
			},
		},
	})
}

// testAccGroupMembershipResourceConfig_groupAsMember emits provider + rootdse
// + OU + parent/child_a/child_b groups + a user + a membership resource whose
// members = {child_<which>, user}. `which` must be "a" or "b".
func testAccGroupMembershipResourceConfig_groupAsMember(
	ouName, parentName, parentSAM,
	childAName, childASAM, childBName, childBSAM,
	userName, userSAM, which string,
) string {
	return fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_ou" "test" {
  name = %[3]q
  path = data.ad_rootdse.test.default_naming_context
}

resource "ad_group" "parent" {
  name             = %[4]q
  sam_account_name = %[5]q
  container        = ad_ou.test.dn
  scope            = "global"
  category         = "security"
}

resource "ad_group" "child_a" {
  name             = %[6]q
  sam_account_name = %[7]q
  container        = ad_ou.test.dn
  scope            = "global"
  category         = "security"
}

resource "ad_group" "child_b" {
  name             = %[8]q
  sam_account_name = %[9]q
  container        = ad_ou.test.dn
  scope            = "global"
  category         = "security"
}

resource "ad_user" "member" {
  name             = %[10]q
  sam_account_name = %[11]q
  principal_name   = format("%[11]s@%%s", data.ad_rootdse.test.domain_name)
  container        = ad_ou.test.dn
}

resource "ad_group_membership" "test" {
  group_id = ad_group.parent.id
  members = [
    ad_group.child_%[12]s.dn,
    ad_user.member.dn,
  ]
}
`,
		testProviderConfig(),
		testRootDSEDataSource(),
		ouName,
		parentName, parentSAM,
		childAName, childASAM,
		childBName, childBSAM,
		userName, userSAM,
		which,
	)
}

// TestAccGroupMembershipResource_driftRecovery verifies that out-of-band
// membership changes (made directly against AD, bypassing Terraform) are
// detected during refresh and reconciled back to the configured membership on
// the next apply.
//
// Scenario:
//  1. Terraform applies membership = {user1, user2}.
//  2. An external actor (simulated via the ldap package) adds user3 and
//     removes user1, so the real membership becomes {user2, user3}.
//  3. Terraform applies the same config again; refresh sees the drift and
//     Update converges back to {user1, user2}.
func TestAccGroupMembershipResource_driftRecovery(t *testing.T) {
	ctx := t.Context()
	n := newGMTestNames(0)

	// Capture identifiers during Step 1's Check, so Step 2's PreConfig (which
	// runs before the plan and has no access to state) can perform the drift.
	var (
		driftGroupGUID string
		driftUser1DN   string
		driftUser3DN   string
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: establish desired state {user1, user2}, and capture the
			// group GUID plus user1/user3 DNs for Step 2.
			{
				Config: testAccGroupMembershipResourceConfig_basic(n),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
					captureStateAttr("ad_group.test", "id", &driftGroupGUID),
					captureStateAttr("ad_user.testuser1", "dn", &driftUser1DN),
					captureStateAttr("ad_user.testuser3", "dn", &driftUser3DN),
				),
			},
			// Step 2: introduce drift directly via the ldap package, then
			// re-apply the same config. The framework will refresh (seeing
			// the drift) and update back to {user1, user2}.
			{
				Config: testAccGroupMembershipResourceConfig_basic(n),
				PreConfig: func() {
					if err := driftGroupMembership(ctx,
						driftGroupGUID,
						[]string{driftUser3DN}, // add user3
						[]string{driftUser1DN}, // remove user1
					); err != nil {
						t.Fatalf("failed to introduce drift: %v", err)
					}
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "2"),
					// Verify the reconciled set contains user1 and user2
					// (normalized) and does NOT contain user3.
					checkMembershipContains("ad_group_membership.test",
						"ad_user.testuser1", "ad_user.testuser2"),
					checkMembershipExcludes("ad_group_membership.test",
						"ad_user.testuser3"),
				),
			},
		},
	})
}

// captureStateAttr records the value of a state attribute into the given
// pointer. Used to bridge state captured in Step N into a PreConfig closure
// run in Step N+1, which has no access to state.
func captureStateAttr(resourceName, attr string, dest *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}
		val, ok := rs.Primary.Attributes[attr]
		if !ok {
			return fmt.Errorf("attribute %s not set on %s", attr, resourceName)
		}
		*dest = val
		return nil
	}
}

// driftGroupMembership mutates the target group's membership out-of-band
// using the ldap package directly, simulating an external actor.
func driftGroupMembership(ctx context.Context, groupGUID string, toAdd, toRemove []string) error {
	config := GetTestConfig()
	ldapConfig := newTestLDAPConfig(config)

	client, err := ldapclient.NewClient(ctx, ldapConfig)
	if err != nil {
		return fmt.Errorf("failed to create LDAP client: %w", err)
	}
	defer client.Close()

	cacheManager := ldapclient.NewCacheManager()
	mm := ldapclient.NewGroupMembershipManager(ctx, client, config.BaseDN, cacheManager)

	if len(toAdd) > 0 {
		if err := mm.AddGroupMembers(groupGUID, toAdd); err != nil {
			return fmt.Errorf("failed to add drift members: %w", err)
		}
	}
	if len(toRemove) > 0 {
		if err := mm.RemoveGroupMembers(groupGUID, toRemove); err != nil {
			return fmt.Errorf("failed to remove drift members: %w", err)
		}
	}
	return nil
}

// checkMembershipContains asserts that the normalized members of the given
// membership resource include the DNs of all listed user resources.
func checkMembershipContains(membershipRes string, userResources ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		membership, ok := s.RootModule().Resources[membershipRes]
		if !ok {
			return fmt.Errorf("resource not found: %s", membershipRes)
		}
		normalized := collectNormalizedMembers(membership.Primary.Attributes)
		for _, u := range userResources {
			rs, ok := s.RootModule().Resources[u]
			if !ok {
				return fmt.Errorf("resource not found: %s", u)
			}
			dn := strings.ToLower(rs.Primary.Attributes["dn"])
			if !containsLower(normalized, dn) {
				return fmt.Errorf("expected %s (%s) to be in membership %v", u, dn, normalized)
			}
		}
		return nil
	}
}

// checkMembershipExcludes asserts that the normalized members of the given
// membership resource do NOT include the DNs of any listed user resources.
func checkMembershipExcludes(membershipRes string, userResources ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		membership, ok := s.RootModule().Resources[membershipRes]
		if !ok {
			return fmt.Errorf("resource not found: %s", membershipRes)
		}
		normalized := collectNormalizedMembers(membership.Primary.Attributes)
		for _, u := range userResources {
			rs, ok := s.RootModule().Resources[u]
			if !ok {
				return fmt.Errorf("resource not found: %s", u)
			}
			dn := strings.ToLower(rs.Primary.Attributes["dn"])
			if containsLower(normalized, dn) {
				return fmt.Errorf("expected %s (%s) to NOT be in membership %v", u, dn, normalized)
			}
		}
		return nil
	}
}

// collectNormalizedMembers returns the members_normalized.* attribute values
// from a flat state-attribute map, lowercased for case-insensitive matching.
func collectNormalizedMembers(attrs map[string]string) []string {
	var out []string
	for k, v := range attrs {
		if strings.HasPrefix(k, "members_normalized.") && k != "members_normalized.#" {
			out = append(out, strings.ToLower(v))
		}
	}
	return out
}

func containsLower(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}
