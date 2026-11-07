package provider_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// groupMemberTestNames holds the unique object names of one ad_group_member
// acceptance test.
type groupMemberTestNames struct {
	OU, Group, GroupS, Nested, NestedS string
	U1, U1S, U2, U2S, U3, U3S          string
}

func newGroupMemberTestNames() groupMemberTestNames {
	return groupMemberTestNames{
		OU:      GenerateTestName("tf-gmem-ou-"),
		Group:   GenerateTestName("tf-gmem-grp-"),
		GroupS:  GenerateTestSAMName("TFGmemG"),
		Nested:  GenerateTestName("tf-gmem-nested-"),
		NestedS: GenerateTestSAMName("TFGmemN"),
		U1:      GenerateTestName("tf-gmem-u1-"),
		U1S:     GenerateTestSAMName("tfgmu1"),
		U2:      GenerateTestName("tf-gmem-u2-"),
		U2S:     GenerateTestSAMName("tfgmu2"),
		U3:      GenerateTestName("tf-gmem-u3-"),
		U3S:     GenerateTestSAMName("tfgmu3"),
	}
}

// groupMemberFixture emits an OU holding three users, the group ad_group.test
// and the group ad_group.nested (named nestedName), followed by extra.
func groupMemberFixture(n groupMemberTestNames, nestedName, extra string) string {
	return fmt.Sprintf(`
%[1]s

%[2]s

data "ad_whoami" "test" {}

locals {
  netbios_domain = regex("^u:([^\\\\]+)\\\\", data.ad_whoami.test.id)[0]
}

resource "ad_ou" "test" {
  name        = %[3]q
  path        = data.ad_rootdse.test.default_naming_context
  description = "Temporary OU for ad_group_member acceptance tests"
}

resource "ad_user" "u1" {
  name             = %[4]q
  sam_account_name = %[5]q
  principal_name   = format("%[5]s@%%s", data.ad_rootdse.test.domain_name)
  container        = ad_ou.test.dn
}

resource "ad_user" "u2" {
  name             = %[6]q
  sam_account_name = %[7]q
  principal_name   = format("%[7]s@%%s", data.ad_rootdse.test.domain_name)
  container        = ad_ou.test.dn
}

resource "ad_user" "u3" {
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
}

resource "ad_group" "nested" {
  name             = %[12]q
  sam_account_name = %[13]q
  container        = ad_ou.test.dn
  scope            = "global"
  category         = "security"
}
%[14]s`,
		testProviderConfig(),
		testRootDSEDataSource(),
		n.OU,
		n.U1, n.U1S,
		n.U2, n.U2S,
		n.U3, n.U3S,
		n.Group, n.GroupS,
		nestedName, n.NestedS,
		extra,
	)
}

func groupMemberConfig(member string) string {
	return fmt.Sprintf(`
resource "ad_group_member" "test" {
  group_id = ad_group.test.id
  member   = %s
}
`, member)
}

// checkADGroupMembers asserts that the direct members of ad_group.test in AD
// are exactly the objects of memberRes (compared by objectGUID).
func checkADGroupMembers(ctx context.Context, memberRes ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		group, ok := s.RootModule().Resources["ad_group.test"]
		if !ok {
			return fmt.Errorf("resource not found: ad_group.test")
		}
		want := make([]string, 0, len(memberRes))
		for _, name := range memberRes {
			rs, ok := s.RootModule().Resources[name]
			if !ok {
				return fmt.Errorf("resource not found: %s", name)
			}
			want = append(want, strings.ToLower(rs.Primary.ID))
		}

		config := GetTestConfig()
		client, err := ldapclient.NewClient(ctx, newTestLDAPConfig(config))
		if err != nil {
			return fmt.Errorf("failed to create LDAP client: %w", err)
		}
		defer client.Close()

		mm := ldapclient.NewGroupMembershipManager(ctx, client, config.BaseDN, ldapclient.NewCacheManager())
		current, err := mm.GetCurrentMembers(group.Primary.ID)
		if err != nil {
			return fmt.Errorf("failed to read group members: %w", err)
		}
		got := make([]string, 0, len(current))
		for _, m := range current {
			got = append(got, strings.ToLower(m.GUID))
		}

		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			return fmt.Errorf("group members in AD: got %v, want %v (%v)", got, want, memberRes)
		}
		return nil
	}
}

// checkGroupMemberAttrs asserts the identity attributes of an ad_group_member
// that manages memberRes in ad_group.test.
func checkGroupMemberAttrs(name, memberRes string) resource.TestCheckFunc {
	return resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttrPair(name, "group_id", "ad_group.test", "id"),
		resource.TestCheckResourceAttrPair(name, "member_details.id", memberRes, "id"),
		resource.TestCheckResourceAttrPair(name, "member_details.dn", memberRes, "dn"),
		func(s *terraform.State) error {
			rs := s.RootModule().Resources[name]
			want := s.RootModule().Resources["ad_group.test"].Primary.ID + "/" + s.RootModule().Resources[memberRes].Primary.ID
			if got := rs.Primary.ID; got != want {
				return fmt.Errorf("%s: id = %q, want %q", name, got, want)
			}
			return nil
		},
	)
}

// TestAccGroupMember_basic adds one member to a group that already has an
// unmanaged member, leaves a member added out-of-band alone, imports the
// resource, and on destroy removes only its own member.
func TestAccGroupMember_basic(t *testing.T) {
	ctx := t.Context()
	n := newGroupMemberTestNames()
	base := groupMemberFixture(n, n.Nested, "")
	full := groupMemberFixture(n, n.Nested, groupMemberConfig("ad_user.u1.dn"))
	var groupGUID, u2DN, u3DN string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: base,
				Check: resource.ComposeAggregateTestCheckFunc(
					captureStateAttr("ad_group.test", "id", &groupGUID),
					captureStateAttr("ad_user.u2", "dn", &u2DN),
					captureStateAttr("ad_user.u3", "dn", &u3DN),
				),
			},
			{
				PreConfig: func() {
					if err := driftGroupMembership(ctx, groupGUID, []string{u2DN}, nil); err != nil {
						t.Fatalf("failed to add unmanaged member: %v", err)
					}
				},
				Config: full,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("ad_group_member.test", "member", "ad_user.u1", "dn"),
					checkGroupMemberAttrs("ad_group_member.test", "ad_user.u1"),
					checkADGroupMembers(ctx, "ad_user.u1", "ad_user.u2"),
				),
			},
			// A member added out-of-band is not a diff.
			{
				PreConfig: func() {
					if err := driftGroupMembership(ctx, groupGUID, []string{u3DN}, nil); err != nil {
						t.Fatalf("failed to add out-of-band member: %v", err)
					}
				},
				Config:   full,
				PlanOnly: true,
			},
			{
				ResourceName:            "ad_group_member.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"member"},
			},
			{
				Config: base,
				Check:  checkADGroupMembers(ctx, "ad_user.u2", "ad_user.u3"),
			},
		},
	})
}

// TestAccGroupMember_adoptExistingMember creates the resource for an object
// that is already a member, then removes it on destroy.
func TestAccGroupMember_adoptExistingMember(t *testing.T) {
	ctx := t.Context()
	n := newGroupMemberTestNames()
	base := groupMemberFixture(n, n.Nested, "")
	var groupGUID, u1DN string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: base,
				Check: resource.ComposeAggregateTestCheckFunc(
					captureStateAttr("ad_group.test", "id", &groupGUID),
					captureStateAttr("ad_user.u1", "dn", &u1DN),
				),
			},
			{
				PreConfig: func() {
					if err := driftGroupMembership(ctx, groupGUID, []string{u1DN}, nil); err != nil {
						t.Fatalf("failed to add member out-of-band: %v", err)
					}
				},
				Config: groupMemberFixture(n, n.Nested, groupMemberConfig("ad_user.u1.id")),
				Check: resource.ComposeAggregateTestCheckFunc(
					checkGroupMemberAttrs("ad_group_member.test", "ad_user.u1"),
					checkADGroupMembers(ctx, "ad_user.u1"),
				),
			},
			{
				Config: base,
				Check:  checkADGroupMembers(ctx),
			},
		},
	})
}

// TestAccGroupMember_removedOutOfBand re-adds a member removed outside of
// Terraform.
func TestAccGroupMember_removedOutOfBand(t *testing.T) {
	ctx := t.Context()
	n := newGroupMemberTestNames()
	full := groupMemberFixture(n, n.Nested, groupMemberConfig("ad_user.u1.principal_name"))
	var groupGUID, u1DN string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: full,
				Check: resource.ComposeAggregateTestCheckFunc(
					captureStateAttr("ad_group.test", "id", &groupGUID),
					captureStateAttr("ad_user.u1", "dn", &u1DN),
					checkADGroupMembers(ctx, "ad_user.u1"),
				),
			},
			{
				PreConfig: func() {
					if err := driftGroupMembership(ctx, groupGUID, nil, []string{u1DN}); err != nil {
						t.Fatalf("failed to remove member out-of-band: %v", err)
					}
				},
				Config: full,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ad_group_member.test", plancheck.ResourceActionCreate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					checkGroupMemberAttrs("ad_group_member.test", "ad_user.u1"),
					checkADGroupMembers(ctx, "ad_user.u1"),
				),
			},
			{
				Config:   full,
				PlanOnly: true,
			},
		},
	})
}

// TestAccGroupMember_nestedGroupRenamed adds a group as a member by GUID and
// renames it out-of-band: the plan stays empty and member_details.dn follows
// the rename.
func TestAccGroupMember_nestedGroupRenamed(t *testing.T) {
	ctx := t.Context()
	n := newGroupMemberTestNames()
	renamed := GenerateTestName("tf-gmem-renamed-")
	var nestedGUID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: groupMemberFixture(n, n.Nested, groupMemberConfig("ad_group.nested.id")),
				Check: resource.ComposeAggregateTestCheckFunc(
					captureStateAttr("ad_group.nested", "id", &nestedGUID),
					checkGroupMemberAttrs("ad_group_member.test", "ad_group.nested"),
					checkADGroupMembers(ctx, "ad_group.nested"),
				),
			},
			{
				PreConfig: func() {
					if err := renameGroupOutOfBand(ctx, nestedGUID, renamed); err != nil {
						t.Fatalf("failed to rename member group out-of-band: %v", err)
					}
				},
				Config: groupMemberFixture(n, renamed, groupMemberConfig("ad_group.nested.id")),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					checkGroupMemberAttrs("ad_group_member.test", "ad_group.nested"),
					resource.TestCheckResourceAttrWith("ad_group_member.test", "member_details.dn", func(dn string) error {
						if !strings.HasPrefix(dn, "CN="+renamed+",") {
							return fmt.Errorf("member_details.dn %q does not reflect the rename to %q", dn, renamed)
						}
						return nil
					}),
					checkADGroupMembers(ctx, "ad_group.nested"),
				),
			},
		},
	})
}

// TestAccGroupMember_groupDeletedOutOfBand drops the resource from state,
// without an error, when its group is deleted outside of Terraform.
func TestAccGroupMember_groupDeletedOutOfBand(t *testing.T) {
	ctx := t.Context()
	n := newGroupMemberTestNames()
	full := groupMemberFixture(n, n.Nested, groupMemberConfig("ad_user.u1.id"))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: full,
				Check: resource.ComposeAggregateTestCheckFunc(
					checkADGroupMembers(ctx, "ad_user.u1"),
					testCheckGroupDisappears(ctx, "ad_group.test"),
				),
				ExpectNonEmptyPlan: true,
			},
			{
				Config: full,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ad_group.test", plancheck.ResourceActionCreate),
						plancheck.ExpectResourceAction("ad_group_member.test", plancheck.ResourceActionCreate),
					},
				},
				Check: checkADGroupMembers(ctx, "ad_user.u1"),
			},
		},
	})
}

// TestAccGroupMember_multipleIdentifierFormats manages several members of one
// group, each given in a different identifier format, and removes one of them
// without affecting the others.
func TestAccGroupMember_multipleIdentifierFormats(t *testing.T) {
	ctx := t.Context()
	n := newGroupMemberTestNames()
	members := map[string]string{
		"upn":    "ad_user.u1.principal_name",
		"sam":    `"${local.netbios_domain}\\${ad_user.u2.sam_account_name}"`,
		"sid":    "ad_user.u3.sid",
		"nested": "ad_group.nested.dn",
	}
	config := func(names ...string) string {
		var b strings.Builder
		for _, name := range names {
			fmt.Fprintf(&b, `
resource "ad_group_member" %q {
  group_id = ad_group.test.id
  member   = %s
}
`, name, members[name])
		}
		return groupMemberFixture(n, n.Nested, b.String())
	}
	all := config("upn", "sam", "sid", "nested")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: all,
				Check: resource.ComposeAggregateTestCheckFunc(
					checkGroupMemberAttrs("ad_group_member.upn", "ad_user.u1"),
					checkGroupMemberAttrs("ad_group_member.sam", "ad_user.u2"),
					checkGroupMemberAttrs("ad_group_member.sid", "ad_user.u3"),
					checkGroupMemberAttrs("ad_group_member.nested", "ad_group.nested"),
					resource.TestCheckResourceAttrWith("ad_group_member.sam", "member", func(v string) error {
						if !strings.HasSuffix(v, `\`+n.U2S) || strings.HasPrefix(v, `\`) {
							return fmt.Errorf("member %q is not in DOMAIN\\name form", v)
						}
						return nil
					}),
					checkADGroupMembers(ctx, "ad_user.u1", "ad_user.u2", "ad_user.u3", "ad_group.nested"),
				),
			},
			{
				Config:   all,
				PlanOnly: true,
			},
			{
				Config: config("upn", "sam", "nested"),
				Check:  checkADGroupMembers(ctx, "ad_user.u1", "ad_user.u2", "ad_group.nested"),
			},
		},
	})
}

// TestAccGroupMember_importByID imports by `terraform import` and by an
// import block with the ID "<group-guid>/<member-guid>". With member given as
// the member GUID, the import block plan is a no-op.
func TestAccGroupMember_importByID(t *testing.T) {
	n := newGroupMemberTestNames()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: groupMemberFixture(n, n.Nested, groupMemberConfig("ad_user.u1.id")),
				Check:  checkGroupMemberAttrs("ad_group_member.test", "ad_user.u1"),
			},
			{
				ResourceName:      "ad_group_member.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:    "ad_group_member.test",
				ImportState:     true,
				ImportStateKind: resource.ImportBlockWithID,
				ImportPlanChecks: resource.ImportPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ad_group_member.test", plancheck.ResourceActionNoop),
					},
				},
			},
		},
	})
}
