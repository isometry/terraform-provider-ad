package provider_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccGroupDataSource_ByID(t *testing.T) {
	name := GenerateTestName(TestGroupPrefix + "byid-")
	samName := GenerateTestSAMName("TFGByID")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckGroupDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Read testing by objectGUID
			{
				Config: testAccGroupDataSourceConfig_ByID(name, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.ad_group.test", "id", "ad_group.test", "id"),
					resource.TestCheckResourceAttrPair("data.ad_group.test", "dn", "ad_group.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "scope"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "category"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "member_count"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "members.#"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "member_of.#"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "when_created"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "when_changed"),
					// Test specific expected values
					resource.TestCheckResourceAttr("data.ad_group.test", "description", "Test group for data source"),
					resource.TestCheckResourceAttr("data.ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("data.ad_group.test", "category", "security"),
				),
			},
		},
	})
}

func TestAccGroupDataSource_ByDN(t *testing.T) {
	name := GenerateTestName(TestGroupPrefix + "bydn-")
	samName := GenerateTestSAMName("TFGByDN")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckGroupDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Read testing by Distinguished Name
			{
				Config: testAccGroupDataSourceConfig_ByDN(name, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.ad_group.test", "id", "ad_group.test", "id"),
					resource.TestCheckResourceAttrPair("data.ad_group.test", "dn", "ad_group.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "member_of.#"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "when_created"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "when_changed"),
					resource.TestCheckResourceAttr("data.ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("data.ad_group.test", "category", "security"),
				),
			},
		},
	})
}

func TestAccGroupDataSource_ByName(t *testing.T) {
	name := GenerateTestName(TestGroupPrefix + "byname-")
	samName := GenerateTestSAMName("TFGByName")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckGroupDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Read testing by name and container
			{
				Config: testAccGroupDataSourceConfig_ByName(name, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.ad_group.test", "id", "ad_group.test", "id"),
					resource.TestCheckResourceAttrPair("data.ad_group.test", "dn", "ad_group.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "member_of.#"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "when_created"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "when_changed"),
					resource.TestCheckResourceAttr("data.ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("data.ad_group.test", "category", "security"),
				),
			},
		},
	})
}

func TestAccGroupDataSource_BySAMAccountName(t *testing.T) {
	name := GenerateTestName(TestGroupPrefix + "bysam-")
	samName := GenerateTestSAMName("TFGBySAM")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckGroupDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Read testing by SAM account name
			{
				Config: testAccGroupDataSourceConfig_BySAMAccountName(name, samName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.ad_group.test", "id", "ad_group.test", "id"),
					resource.TestCheckResourceAttrPair("data.ad_group.test", "dn", "ad_group.test", "dn"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "member_of.#"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "when_created"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "when_changed"),
					resource.TestCheckResourceAttr("data.ad_group.test", "scope", "global"),
					resource.TestCheckResourceAttr("data.ad_group.test", "category", "security"),
				),
			},
		},
	})
}

func TestAccGroupDataSource_WithMembers(t *testing.T) {
	name := GenerateTestName(TestGroupPrefix + "withmem-")
	samName := GenerateTestSAMName("TFGWithMem")
	memberName := GenerateTestName(TestGroupPrefix + "memof-")
	memberSAM := GenerateTestSAMName("TFGMemOf")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			return testCheckGroupDestroy(t.Context(), s)
		},
		Steps: []resource.TestStep{
			// Create a group with members, then read it
			{
				Config: testAccGroupDataSourceConfig_WithMembers(name, samName, memberName, memberSAM),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.ad_group.test", "id", "ad_group.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "members.#"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "member_count"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "member_of.#"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "when_created"),
					resource.TestCheckResourceAttrSet("data.ad_group.test", "when_changed"),
					// Check that we have at least one member
					resource.TestCheckResourceAttrWith("data.ad_group.test", "member_count", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected member_count to be greater than 0, got %s", value)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccGroupDataSource_ValidationErrors(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test that multiple lookup methods cause validation error
			{
				Config:      testAccGroupDataSourceConfig_MultipleLookupMethods(),
				ExpectError: regexp.MustCompile(`Exactly one of these attributes must be configured`),
			},
			// Test that no lookup method causes validation error
			{
				Config:      testAccGroupDataSourceConfig_NoLookupMethod(),
				ExpectError: regexp.MustCompile(`Exactly one of these attributes must be configured`),
			},
			// Test that name without container causes validation error
			{
				Config:      testAccGroupDataSourceConfig_NameWithoutContainer(),
				ExpectError: regexp.MustCompile(`(Exactly one of these attributes must be configured|These attributes must be configured together)`),
			},
			// Test that container without name causes validation error
			{
				Config:      testAccGroupDataSourceConfig_ContainerWithoutName(),
				ExpectError: regexp.MustCompile(`(Exactly one of these attributes must be configured|These attributes must be configured together)`),
			},
		},
	})
}

func TestAccGroupDataSource_NotFound(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test non-existent group by GUID
			{
				Config:      testAccGroupDataSourceConfig_NotFoundByID(),
				ExpectError: regexp.MustCompile(`Group Not Found|not found`),
			},
			// Test non-existent group by DN
			{
				Config:      testAccGroupDataSourceConfig_NotFoundByDN(),
				ExpectError: regexp.MustCompile(`Group Not Found|not found`),
			},
			// Test non-existent group by SAM account name
			{
				Config:      testAccGroupDataSourceConfig_NotFoundBySAM(),
				ExpectError: regexp.MustCompile(`Group Not Found|not found`),
			},
		},
	})
}

// Test configuration functions

func testAccGroupDataSourceConfig_ByID(name, samName string) string {
	return fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_group" "test" {
  name               = %[3]q
  sam_account_name   = %[4]q
  container          = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  scope              = "global"
  category           = "security"
  description        = "Test group for data source"
}

data "ad_group" "test" {
  id = ad_group.test.id
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName)
}

func testAccGroupDataSourceConfig_ByDN(name, samName string) string {
	return fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_group" "test" {
  name               = %[3]q
  sam_account_name   = %[4]q
  container          = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  scope              = "global"
  category           = "security"
  description        = "Test group for data source"
}

data "ad_group" "test" {
  dn = ad_group.test.dn
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName)
}

func testAccGroupDataSourceConfig_ByName(name, samName string) string {
	return fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_group" "test" {
  name               = %[3]q
  sam_account_name   = %[4]q
  container          = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  scope              = "global"
  category           = "security"
  description        = "Test group for data source"
}

data "ad_group" "test" {
  name      = ad_group.test.name
  container = ad_group.test.container
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName)
}

func testAccGroupDataSourceConfig_BySAMAccountName(name, samName string) string {
	return fmt.Sprintf(`
%[1]s

%[2]s

resource "ad_group" "test" {
  name               = %[3]q
  sam_account_name   = %[4]q
  container          = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  scope              = "global"
  category           = "security"
  description        = "Test group for data source"
}

data "ad_group" "test" {
  sam_account_name = ad_group.test.sam_account_name
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName)
}

func testAccGroupDataSourceConfig_WithMembers(name, samName, memberName, memberSAM string) string {
	return fmt.Sprintf(`
%[1]s

%[2]s

# Create a test group
resource "ad_group" "test" {
  name               = %[3]q
  sam_account_name   = %[4]q
  container          = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  scope              = "global"
  category           = "security"
  description        = "Test group with members for data source"
}

# Create another group to use as a member
resource "ad_group" "member" {
  name               = %[5]q
  sam_account_name   = %[6]q
  container          = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  scope              = "global"
  category           = "security"
  description        = "Test member group"
}

# Add the member group to the test group
resource "ad_group_membership" "test" {
  group_id = ad_group.test.id
  members  = [ad_group.member.dn]
}

# Read the group with members
data "ad_group" "test" {
  id = ad_group.test.id
  depends_on = [ad_group_membership.test]
}
`, testProviderConfig(), testRootDSEDataSource(), name, samName, memberName, memberSAM)
}

// Validation error test configurations

func testAccGroupDataSourceConfig_MultipleLookupMethods() string {
	return fmt.Sprintf(`
%s

%s

data "ad_group" "test" {
  id = "550e8400-e29b-41d4-a716-446655440000"
  dn = "CN=TestGroup,CN=Users,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource())
}

func testAccGroupDataSourceConfig_NoLookupMethod() string {
	return fmt.Sprintf(`
%s

%s

data "ad_group" "test" {
  # No lookup method specified
}
`, testProviderConfig(), testRootDSEDataSource())
}

func testAccGroupDataSourceConfig_NameWithoutContainer() string {
	return fmt.Sprintf(`
%s

%s

data "ad_group" "test" {
  name = "TestGroup"
  # container not specified
}
`, testProviderConfig(), testRootDSEDataSource())
}

func testAccGroupDataSourceConfig_ContainerWithoutName() string {
	return fmt.Sprintf(`
%s

%s

data "ad_group" "test" {
  container = "CN=Users,${data.ad_rootdse.test.default_naming_context}"
  # name not specified
}
`, testProviderConfig(), testRootDSEDataSource())
}

// Not found test configurations

func testAccGroupDataSourceConfig_NotFoundByID() string {
	return fmt.Sprintf(`
%s

%s

data "ad_group" "test" {
  id = "550e8400-e29b-41d4-a716-446655440000"  # Non-existent GUID
}
`, testProviderConfig(), testRootDSEDataSource())
}

func testAccGroupDataSourceConfig_NotFoundByDN() string {
	return fmt.Sprintf(`
%s

%s

data "ad_group" "test" {
  dn = "CN=NonExistentGroup,CN=Users,${data.ad_rootdse.test.default_naming_context}"
}
`, testProviderConfig(), testRootDSEDataSource())
}

func testAccGroupDataSourceConfig_NotFoundBySAM() string {
	return fmt.Sprintf(`
%s

%s

data "ad_group" "test" {
  sam_account_name = "NonExistentGroup"
}
`, testProviderConfig(), testRootDSEDataSource())
}

// TestAccGroupDataSource_FlattenMembers builds a nested group graph
// (group_a contains group_b; group_b contains user_u) and exercises the
// `flatten_members` attribute of the ad_group data source.
//
// Provider semantics (verified against internal/provider/data_source_group.go
// and internal/ldap/group.go GetFlattenedUserMembers at line 1502):
//   - `flatten_members = true` traverses nested groups recursively and returns
//     the set of USER DNs only; group DNs are excluded from the result.
//   - `flatten_members = false` (default / unset) returns the direct members
//     only — both users and groups that are directly listed on the group.
//
// This test asserts both behaviours against the same nested graph in a
// single resource.Test run. Step 1 queries with flatten_members=true and
// verifies user_u's DN appears in `members` while group_b's DN does not.
// Step 2 queries with flatten_members unset and verifies the inverse:
// group_b's DN appears, user_u's DN does not.
func TestAccGroupDataSource_FlattenMembers(t *testing.T) {
	parentName := GenerateTestName("tf-dsflat-a-")
	parentSAM := GenerateTestSAMName("TFDSFlatA")
	childName := GenerateTestName("tf-dsflat-b-")
	childSAM := GenerateTestSAMName("TFDSFlatB")
	userName := GenerateTestName("tf-dsflat-u-")
	userSAM := GenerateTestSAMName("tfdsflatu")
	ouName := GenerateTestName("tf-dsflat-ou-")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: flatten_members = true. Expect user_u DN present,
			// group_b DN absent.
			{
				Config: testAccGroupDataSourceConfig_FlattenMembers(
					ouName, parentName, parentSAM, childName, childSAM,
					userName, userSAM, true,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.ad_group.flat", "id", "ad_group.parent", "id",
					),
					checkSetContainsResourceAttr(
						"data.ad_group.flat", "members",
						"ad_user.leaf", "dn",
					),
					checkSetExcludesResourceAttr(
						"data.ad_group.flat", "members",
						"ad_group.child", "dn",
					),
				),
			},
			// Step 2: flatten_members unset (= false). Expect group_b DN
			// present, user_u DN absent (direct-members only).
			{
				Config: testAccGroupDataSourceConfig_FlattenMembers(
					ouName, parentName, parentSAM, childName, childSAM,
					userName, userSAM, false,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.ad_group.flat", "id", "ad_group.parent", "id",
					),
					checkSetContainsResourceAttr(
						"data.ad_group.flat", "members",
						"ad_group.child", "dn",
					),
					checkSetExcludesResourceAttr(
						"data.ad_group.flat", "members",
						"ad_user.leaf", "dn",
					),
				),
			},
		},
	})
}

// testAccGroupDataSourceConfig_FlattenMembers emits provider + rootdse + OU +
// parent/child groups + leaf user + nested memberships + a data.ad_group that
// queries the parent with the given `flatten_members` toggle.
func testAccGroupDataSourceConfig_FlattenMembers(
	ouName, parentName, parentSAM, childName, childSAM,
	userName, userSAM string,
	flatten bool,
) string {
	flattenBlock := ""
	if flatten {
		flattenBlock = "  flatten_members = true\n"
	}

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

resource "ad_group" "child" {
  name             = %[6]q
  sam_account_name = %[7]q
  container        = ad_ou.test.dn
  scope            = "global"
  category         = "security"
}

resource "ad_user" "leaf" {
  name             = %[8]q
  sam_account_name = %[9]q
  principal_name   = format("%[9]s@%%s", data.ad_rootdse.test.domain_name)
  container        = ad_ou.test.dn
}

# parent contains child
resource "ad_group_membership" "parent_child" {
  group_id = ad_group.parent.id
  members  = [ad_group.child.dn]
}

# child contains leaf
resource "ad_group_membership" "child_leaf" {
  group_id = ad_group.child.id
  members  = [ad_user.leaf.dn]
}

data "ad_group" "flat" {
  id = ad_group.parent.id
%[10]s
  depends_on = [
    ad_group_membership.parent_child,
    ad_group_membership.child_leaf,
  ]
}
`,
		testProviderConfig(),
		testRootDSEDataSource(),
		ouName,
		parentName, parentSAM,
		childName, childSAM,
		userName, userSAM,
		flattenBlock,
	)
}

// checkSetContainsResourceAttr asserts that the string-set attribute at
// (dataRes, setAttr) contains the value held by (memberRes, memberAttr), case-
// insensitively. This is needed because framework sets are flattened into
// numerically-indexed state attributes like "members.123456".
func checkSetContainsResourceAttr(dataRes, setAttr, memberRes, memberAttr string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ds, ok := s.RootModule().Resources[dataRes]
		if !ok {
			return fmt.Errorf("resource not found: %s", dataRes)
		}
		mr, ok := s.RootModule().Resources[memberRes]
		if !ok {
			return fmt.Errorf("resource not found: %s", memberRes)
		}
		want := strings.ToLower(mr.Primary.Attributes[memberAttr])
		if want == "" {
			return fmt.Errorf("attribute %s on %s is empty", memberAttr, memberRes)
		}

		values := collectSetAttr(ds.Primary.Attributes, setAttr)
		for _, v := range values {
			if strings.ToLower(v) == want {
				return nil
			}
		}
		return fmt.Errorf("expected %s.%s to contain %s (from %s.%s), got %v",
			dataRes, setAttr, want, memberRes, memberAttr, values)
	}
}

// checkSetExcludesResourceAttr asserts that the string-set attribute at
// (dataRes, setAttr) does NOT contain the value held by (memberRes,
// memberAttr), case-insensitively.
func checkSetExcludesResourceAttr(dataRes, setAttr, memberRes, memberAttr string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ds, ok := s.RootModule().Resources[dataRes]
		if !ok {
			return fmt.Errorf("resource not found: %s", dataRes)
		}
		mr, ok := s.RootModule().Resources[memberRes]
		if !ok {
			return fmt.Errorf("resource not found: %s", memberRes)
		}
		want := strings.ToLower(mr.Primary.Attributes[memberAttr])
		if want == "" {
			return fmt.Errorf("attribute %s on %s is empty", memberAttr, memberRes)
		}

		values := collectSetAttr(ds.Primary.Attributes, setAttr)
		for _, v := range values {
			if strings.ToLower(v) == want {
				return fmt.Errorf("expected %s.%s to NOT contain %s (from %s.%s), got %v",
					dataRes, setAttr, want, memberRes, memberAttr, values)
			}
		}
		return nil
	}
}

// collectSetAttr returns every value in the flat state-attribute map whose
// key is a child of the named set attribute (e.g. "members.123456"), ignoring
// the count sentinel "members.#".
func collectSetAttr(attrs map[string]string, setAttr string) []string {
	prefix := setAttr + "."
	var out []string
	for k, v := range attrs {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if k == setAttr+".#" {
			continue
		}
		out = append(out, v)
	}
	return out
}
