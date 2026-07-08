package provider_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// TestAccGroupMembershipResource_memberGroupRenamedAcrossApplies covers the
// scenario the plan-time-GUID-capture design (see resource_group_membership.go's
// `member_details` attribute and resolveMemberDetailsForWrite) is built to
// handle safely: a member referenced by a rename-immune identifier (its
// GUID) gets renamed underneath the membership resource, changing its DN.
// Because `member_details` pairs that GUID with a DN, and AD writes prefer
// the GUID's rename-immune "<GUID=...>" alternative-DN form whenever the
// GUID is known, the membership resource's next refreshed plan must be
// completely empty — no membership re-diff or rewrite, and no attempt to
// rename the group back — regardless of whether the DN captured at some
// earlier plan time is now stale.
//
// This test exercises the out-of-band variant of the scenario: rename the
// member group directly via LDAP in PreConfig (simulating an external actor
// or a separate Terraform apply), then assert the refreshed plan is
// completely empty and a follow-up plan converges.
//
// The core correctness guarantee under test here — that the AD write always
// uses member_details' captured GUID, and that Create/Update perform zero
// LDAP calls to resolve member identity in the common case — is covered
// directly (and more cheaply) by the unit tests in
// resource_group_membership_apply_test.go
// (TestGroupMembershipResource_CreateUpdateTrustPlanTimeMemberDetails),
// which inject a "stale-looking" member_details DN directly and are not
// subject to any acceptance-test harness limitations.
func TestAccGroupMembershipResource_memberGroupRenamedAcrossApplies(t *testing.T) {
	ctx := t.Context()
	ou := GenerateTestName("tf-mship-ren-ou-")
	memberGroupName := GenerateTestName("tf-mship-ren-member-")
	memberGroupSAM := GenerateTestSAMName("TFMshRenM")
	containerGroupName := GenerateTestName("tf-mship-ren-container-")
	containerGroupSAM := GenerateTestSAMName("TFMshRenC")
	renamedMemberGroupName := GenerateTestName("tf-mship-ren-member2-")

	// Captured during Step 1's Check, so Step 2's PreConfig (which runs
	// before the plan and has no access to state) can perform the rename.
	var memberGroupGUID string

	config := func(memberName string) string {
		return fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_ou" "test" {
  name        = %[3]q
  path        = data.ad_rootdse.test.default_naming_context
  description = "Temporary OU for ad_group_membership rename acceptance test"
}

resource "ad_group" "member" {
  name             = %[4]q
  sam_account_name = %[5]q
  container        = ad_ou.test.dn
  scope            = "global"
  category         = "security"
  description      = "Member group, renamed out-of-band in this test"
}

resource "ad_group" "container" {
  name             = %[6]q
  sam_account_name = %[7]q
  container        = ad_ou.test.dn
  scope            = "global"
  category         = "security"
  description      = "Container group whose membership references ad_group.member by GUID"
}

resource "ad_group_membership" "test" {
  group_id = ad_group.container.id
  members = [
    ad_group.member.id, # rename-immune GUID reference
  ]
}
`,
			testProviderConfig(),
			testRootDSEDataSource(),
			ou,
			memberName, memberGroupSAM,
			containerGroupName, containerGroupSAM,
		)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create the member group, container group, and the
			// membership resource referencing the member group by GUID.
			// Capture the member group's GUID for Step 2's PreConfig.
			{
				Config: config(memberGroupName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "member_details.#", "1"),
					resource.TestCheckTypeSetElemAttrPair(
						"ad_group_membership.test", "members.*",
						"ad_group.member", "id",
					),
					captureStateAttr("ad_group.member", "id", &memberGroupGUID),
				),
			},
			// Step 2: rename the member group out-of-band via LDAP (its
			// GUID, and therefore the membership reference, is unaffected;
			// only its DN changes), then plan against a config that matches
			// the post-rename reality. The refreshed plan must contain ZERO
			// actions: refresh reconciles both ad_group.member (name already
			// matches) and the membership's member_details snapshot, and
			// the membership must not re-diff or attempt to rewrite anything
			// just because the referenced group's DN changed underneath it.
			{
				PreConfig: func() {
					if err := renameGroupOutOfBand(ctx, memberGroupGUID, renamedMemberGroupName); err != nil {
						t.Fatalf("failed to rename member group out-of-band: %v", err)
					}
				},
				Config: config(renamedMemberGroupName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ad_group.member", "name", renamedMemberGroupName),
					resource.TestCheckResourceAttr("ad_group_membership.test", "members.#", "1"),
					resource.TestCheckResourceAttr("ad_group_membership.test", "member_details.#", "1"),
				),
			},
			// Step 3: re-planning the same (post-rename) config must
			// converge to a clean, empty plan for the membership resource —
			// no drift, no attempted rewrite, despite the referenced
			// group's DN having changed underneath it.
			{
				Config:   config(renamedMemberGroupName),
				PlanOnly: true,
			},
		},
	})
}

// renameGroupOutOfBand renames a group directly via the ldap package,
// bypassing Terraform — simulating a rename performed by an external actor
// or a separate Terraform apply.
func renameGroupOutOfBand(ctx context.Context, groupGUID, newName string) error {
	config := GetTestConfig()
	ldapConfig := newTestLDAPConfig(config)

	client, err := ldapclient.NewClient(ctx, ldapConfig)
	if err != nil {
		return fmt.Errorf("failed to create LDAP client: %w", err)
	}
	defer client.Close()

	gm := ldapclient.NewGroupManager(ctx, client, config.BaseDN, ldapclient.NewCacheManager())
	if _, err := gm.UpdateGroup(groupGUID, &ldapclient.UpdateGroupRequest{Name: &newName}); err != nil {
		return fmt.Errorf("failed to rename group %s to %q: %w", groupGUID, newName, err)
	}
	return nil
}
