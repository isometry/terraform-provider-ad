package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// recordingMembershipClient is a minimal ldapclient.Client implementation
// that fakes a single AD group, for driving GroupMembershipResource.Create
// and Update against a real (in-memory) group-membership write path.
//
// Unlike stubMembershipClient (in resource_group_membership_internal_test.go,
// which drives ModifyPlan only: its Modify is a no-op and its Search fails
// loudly by design), this stub (a) records every Modify request issued so
// tests can assert on exactly what was submitted to AD's `member` attribute,
// and (b) answers the Search call GetGroupMembers/AddGroupMembers/
// RemoveGroupMembers issue (via GroupManager.GetGroup's GUID lookup) with a
// controllable, mutable fake current-membership list.
type recordingMembershipClient struct {
	baseDN string

	groupGUID string
	groupDN   string
	members   []string // current group membership (DNs); mutated by Modify

	modifyRequests []*ldapclient.ModifyRequest
	searchFilters  []string // every Search filter received, in call order
}

var _ ldapclient.Client = (*recordingMembershipClient)(nil)

// newRecordingMembershipClient constructs a recordingMembershipClient faking
// a single group identified by groupGUID/groupDN, with the given current
// members.
func newRecordingMembershipClient(groupGUID, groupDN string, initialMembers ...string) *recordingMembershipClient {
	members := make([]string, len(initialMembers))
	copy(members, initialMembers)
	return &recordingMembershipClient{
		baseDN:    "DC=example,DC=com",
		groupGUID: groupGUID,
		groupDN:   groupDN,
		members:   members,
	}
}

func (c *recordingMembershipClient) Connect(ctx context.Context) error { return nil }
func (c *recordingMembershipClient) Close() error                      { return nil }

func (c *recordingMembershipClient) Bind(ctx context.Context, username, password string) error {
	return nil
}

func (c *recordingMembershipClient) BindWithConfig(ctx context.Context) error { return nil }

func (c *recordingMembershipClient) GetBaseDN(ctx context.Context) (string, error) {
	return c.baseDN, nil
}

func (c *recordingMembershipClient) Ping(ctx context.Context) error { return nil }

func (c *recordingMembershipClient) Stats() ldapclient.PoolStats { return ldapclient.PoolStats{} }

func (c *recordingMembershipClient) GetRootDSE(ctx context.Context) (*ldapclient.RootDSEInfo, error) {
	return nil, fmt.Errorf("recordingMembershipClient: GetRootDSE not implemented")
}

func (c *recordingMembershipClient) WhoAmI(ctx context.Context) (*ldapclient.WhoAmIResult, error) {
	return nil, fmt.Errorf("recordingMembershipClient: WhoAmI not implemented")
}

func (c *recordingMembershipClient) Add(ctx context.Context, req *ldapclient.AddRequest) error {
	return fmt.Errorf("recordingMembershipClient: unexpected Add call")
}

func (c *recordingMembershipClient) ModifyDN(ctx context.Context, req *ldapclient.ModifyDNRequest) error {
	return fmt.Errorf("recordingMembershipClient: unexpected ModifyDN call")
}

func (c *recordingMembershipClient) Delete(ctx context.Context, dn string) error {
	return fmt.Errorf("recordingMembershipClient: unexpected Delete call")
}

func (c *recordingMembershipClient) SearchWithPaging(ctx context.Context, req *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
	return c.Search(ctx, req)
}

// Search answers only the group-by-GUID lookup issued by
// GroupManager.GetGroup (used by GetGroupMembers/AddGroupMembers/
// RemoveGroupMembers to fetch the group's DN and current member list). Any
// other Search call indicates a test setup bug (e.g. a member identifier
// that was not pre-seeded into the cache manager, forcing a live lookup)
// and fails loudly rather than silently attempting network I/O. Every
// filter received (including group-by-GUID lookups) is recorded in
// searchFilters so tests can assert on exactly what LDAP searches occurred.
func (c *recordingMembershipClient) Search(ctx context.Context, req *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
	filter := ""
	if req != nil {
		filter = req.Filter
	}
	c.searchFilters = append(c.searchFilters, filter)
	if strings.Contains(filter, "objectGUID=") {
		return &ldapclient.SearchResult{Entries: []*ldap.Entry{c.groupEntry()}, Total: 1}, nil
	}
	return nil, fmt.Errorf("recordingMembershipClient: unexpected Search(%q) — identifier should have been cache-resolved", filter)
}

func (c *recordingMembershipClient) groupEntry() *ldap.Entry {
	guidBytes, _ := ldapclient.NewGUIDHandler().StringToGUIDBytes(c.groupGUID)
	attributes := []*ldap.EntryAttribute{
		{Name: "objectGUID", ByteValues: [][]byte{guidBytes}},
		{Name: "distinguishedName", Values: []string{c.groupDN}},
		{Name: "cn", Values: []string{"TestGroup"}},
	}
	if len(c.members) > 0 {
		attributes = append(attributes, &ldap.EntryAttribute{
			Name:   "member",
			Values: append([]string(nil), c.members...),
		})
	}
	return &ldap.Entry{DN: c.groupDN, Attributes: attributes}
}

// Modify records every request submitted and applies it to the in-memory
// member list, so that subsequent Search-driven lookups within the same
// SetGroupMembers call (e.g. RemoveGroupMembers re-reading current state
// after AddGroupMembers already ran) see up-to-date membership.
func (c *recordingMembershipClient) Modify(ctx context.Context, req *ldapclient.ModifyRequest) error {
	c.modifyRequests = append(c.modifyRequests, req)

	if add, ok := req.AddAttributes["member"]; ok {
		c.members = append(c.members, add...)
	}
	if replace, ok := req.ReplaceAttributes["member"]; ok {
		c.members = append([]string(nil), replace...)
	}
	for _, attr := range req.DeleteAttributes {
		if attr == "member" {
			c.members = nil
		}
	}

	return nil
}

// addedMemberValues returns every value submitted via
// ModifyRequest.AddAttributes["member"] across all recorded Modify calls, in
// call order. This is what actually got written to AD's member attribute
// for newly-added members (post GUID-alt-DN substitution, if applicable).
func (c *recordingMembershipClient) addedMemberValues() []string {
	var out []string
	for _, req := range c.modifyRequests {
		out = append(out, req.AddAttributes["member"]...)
	}
	return out
}

// newTestGroupMembershipResourceWithClient constructs a
// GroupMembershipResource wired to the given client and cache manager, for
// driving Create/Update directly without a real provider server or live
// LDAP connection.
func newTestGroupMembershipResourceWithClient(client ldapclient.Client, cm *ldapclient.CacheManager) *GroupMembershipResource {
	return &GroupMembershipResource{
		client:               client,
		cacheManager:         cm,
		ignoreMissingMembers: false,
	}
}

// runMembershipCreate drives GroupMembershipResource.Create with the given
// plan model and returns the resulting state model alongside the response.
func runMembershipCreate(
	t *testing.T, ctx context.Context, r *GroupMembershipResource, planModel *GroupMembershipResourceModel,
) (*GroupMembershipResourceModel, *resource.CreateResponse) {
	t.Helper()

	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	tfType := schemaResp.Schema.Type().TerraformType(ctx)

	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: tftypes.NewValue(tfType, nil)}
	if diags := plan.Set(ctx, planModel); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags.Errors())
	}

	req := resource.CreateRequest{Plan: plan}
	// The real framework runtime pre-populates resp.State from req.Plan
	// before invoking Create; mirror that here.
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(tfType, nil)},
	}
	if diags := resp.State.Set(ctx, planModel); diags.HasError() {
		t.Fatalf("failed to seed resp.State from plan: %v", diags.Errors())
	}

	r.Create(ctx, req, resp)

	var out GroupMembershipResourceModel
	if !resp.State.Raw.IsNull() {
		if diags := resp.State.Get(ctx, &out); diags.HasError() {
			t.Fatalf("failed to extract resulting state: %v", diags.Errors())
		}
	}
	return &out, resp
}

// runMembershipUpdate drives GroupMembershipResource.Update with the given
// plan/prior-state models and returns the resulting state model alongside
// the response.
func runMembershipUpdate(
	t *testing.T, ctx context.Context, r *GroupMembershipResource, planModel, stateModel *GroupMembershipResourceModel,
) (*GroupMembershipResourceModel, *resource.UpdateResponse) {
	t.Helper()

	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	tfType := schemaResp.Schema.Type().TerraformType(ctx)

	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: tftypes.NewValue(tfType, nil)}
	if diags := plan.Set(ctx, planModel); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags.Errors())
	}

	state := tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(tfType, nil)}
	if diags := state.Set(ctx, stateModel); diags.HasError() {
		t.Fatalf("failed to build prior state: %v", diags.Errors())
	}

	req := resource.UpdateRequest{Plan: plan, State: state}
	// The real framework runtime pre-populates resp.State from req.Plan
	// before invoking Update; mirror that here.
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(tfType, nil)},
	}
	if diags := resp.State.Set(ctx, planModel); diags.HasError() {
		t.Fatalf("failed to seed resp.State from plan: %v", diags.Errors())
	}

	r.Update(ctx, req, resp)

	var out GroupMembershipResourceModel
	if !resp.State.Raw.IsNull() {
		if diags := resp.State.Get(ctx, &out); diags.HasError() {
			t.Fatalf("failed to extract resulting state: %v", diags.Errors())
		}
	}
	return &out, resp
}

// nonGroupLookupSearches returns every recorded Search filter that was NOT
// the "objectGUID=" group-by-GUID lookup GetGroupMembers/AddGroupMembers/
// RemoveGroupMembers legitimately issue. In the new plan-time-GUID-capture
// design this must always be empty for Create/Update's common case (fully
// known member_details): resolving member identities happens ZERO times at
// apply time, so the only Search traffic at all is the group's own DN/
// current-member lookup.
func (c *recordingMembershipClient) nonGroupLookupSearches() []string {
	var out []string
	for _, filter := range c.searchFilters {
		if !strings.Contains(filter, "objectGUID=") {
			out = append(out, filter)
		}
	}
	return out
}

// TestGroupMembershipResource_CreateUpdateTrustPlanTimeMemberDetails is the
// direct regression test for the design that replaced apply-time
// re-resolution (re-resolving `members` fresh, live/cached, immediately
// before the AD write) with plan-time GUID capture: `member_details` is
// resolved exactly once, by ModifyPlan, and trusted verbatim through apply.
// This is safe — even if a referenced object is renamed by an unordered
// sibling resource later in the very same apply — because an AD object's
// objectGUID never changes for its lifetime, and the write below always
// prefers the GUID-alt-DN form over the literal (possibly now-stale) DN
// string.
//
// Each subtest hand-constructs a model where MemberDetails already holds a
// resolved (dn, guid) pair whose dn deliberately looks "stale", as if
// captured before some unrelated rename — and deliberately does NOT seed
// the cache manager for that identifier. recordingMembershipClient fails
// loudly on any Search beyond the legitimate group-by-GUID lookup, so if
// Create/Update regressed to re-resolving `members` fresh (the old design),
// that re-resolution would require a live Search this stub does not answer
// for a bare identifier, failing the test loudly rather than silently
// succeeding. Invariants asserted:
//
//  1. The underlying AD write uses member_details' captured GUID (via its
//     "<GUID=...>" alternative-DN form) — proving the write is driven by
//     member_details, not by any re-resolution of `members`.
//  2. Every Search call recorded is the legitimate group-by-GUID lookup —
//     zero LDAP calls were made to resolve member identity.
//  3. resp.State's saved member_details equals exactly what ModifyPlan had
//     already captured in the input plan — proving Create/Update never
//     rewrite it in the common case.
func TestGroupMembershipResource_CreateUpdateTrustPlanTimeMemberDetails(t *testing.T) {
	ctx := t.Context()

	const (
		memberDN   = "CN=CapturedAtPlanTime,OU=Users,DC=example,DC=com"
		memberGUID = "11111111-1111-1111-1111-111111111111"

		groupGUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		groupDN   = "CN=TestGroup,OU=Groups,DC=example,DC=com"
	)

	expectedAltDN, err := ldapclient.GUIDToAltDN(memberGUID)
	if err != nil {
		t.Fatalf("failed to compute expected alt-DN: %v", err)
	}

	t.Run("Create", func(t *testing.T) {
		client := newRecordingMembershipClient(groupGUID, groupDN) // no members yet
		// Deliberately an empty, unseeded cache manager: extracting the
		// write from member_details must need no cache lookup at all.
		r := newTestGroupMembershipResourceWithClient(client, ldapclient.NewCacheManager())

		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringUnknown(),
			GroupID:              types.StringValue(groupGUID),
			Members:              newMembershipSet(t, memberGUID),
			MemberDetails:        newMemberDetailSet(t, ctx, []string{memberDN}, []string{memberGUID}),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipCreate(t, ctx, r, planModel)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		// Invariant 1: the AD write used member_details' GUID-alt-DN form.
		added := client.addedMemberValues()
		if len(added) != 1 || added[0] != expectedAltDN {
			t.Errorf("AD write used %v, want [%q] (member_details' GUID-alt-DN form)", added, expectedAltDN)
		}

		// Invariant 2: zero LDAP calls were made to resolve member identity.
		if extra := client.nonGroupLookupSearches(); len(extra) != 0 {
			t.Errorf("unexpected member-identity-resolution Search calls: %v", extra)
		}

		// Invariant 3 (consistency guard): member_details in the saved
		// state must remain exactly what the plan already had.
		gotDetails := extractMemberDetails(t, ctx, out.MemberDetails)
		wantDetails := extractMemberDetails(t, ctx, planModel.MemberDetails)
		if len(gotDetails) != len(wantDetails) {
			t.Fatalf("member_details = %v, want %v", gotDetails, wantDetails)
		}
		for dn, guid := range wantDetails {
			if gotDetails[dn] != guid {
				t.Errorf("member_details[%q] = %q, want %q (must equal plan's value verbatim)", dn, gotDetails[dn], guid)
			}
		}
	})

	t.Run("Update", func(t *testing.T) {
		const dnOld = "CN=OldMember,OU=Users,DC=example,DC=com"
		client := newRecordingMembershipClient(groupGUID, groupDN, dnOld) // pre-existing, unrelated member
		r := newTestGroupMembershipResourceWithClient(client, ldapclient.NewCacheManager())

		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupGUID),
			GroupID:              types.StringValue(groupGUID),
			Members:              newMembershipSet(t, memberGUID),
			MemberDetails:        newMemberDetailSet(t, ctx, []string{memberDN}, []string{memberGUID}),
			IgnoreMissingMembers: types.BoolNull(),
		}
		stateModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupGUID),
			GroupID:              types.StringValue(groupGUID),
			Members:              newMembershipSet(t, dnOld),
			MemberDetails:        newMemberDetailSet(t, ctx, []string{dnOld}, []string{""}),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipUpdate(t, ctx, r, planModel, stateModel)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		// Invariant 1: the AD write used member_details' GUID-alt-DN form.
		added := client.addedMemberValues()
		if len(added) != 1 || added[0] != expectedAltDN {
			t.Errorf("AD write used %v, want [%q] (member_details' GUID-alt-DN form)", added, expectedAltDN)
		}

		// The old, no-longer-desired member must have been removed.
		if len(client.members) != 1 || client.members[0] != expectedAltDN {
			t.Errorf("final group membership = %v, want [%q]", client.members, expectedAltDN)
		}

		// Invariant 2: zero LDAP calls were made to resolve member identity.
		if extra := client.nonGroupLookupSearches(); len(extra) != 0 {
			t.Errorf("unexpected member-identity-resolution Search calls: %v", extra)
		}

		// Invariant 3 (consistency guard): member_details in the saved
		// state must remain exactly what the plan already had.
		gotDetails := extractMemberDetails(t, ctx, out.MemberDetails)
		wantDetails := extractMemberDetails(t, ctx, planModel.MemberDetails)
		if len(gotDetails) != len(wantDetails) {
			t.Fatalf("member_details = %v, want %v", gotDetails, wantDetails)
		}
		for dn, guid := range wantDetails {
			if gotDetails[dn] != guid {
				t.Errorf("member_details[%q] = %q, want %q (must equal plan's value verbatim)", dn, gotDetails[dn], guid)
			}
		}
	})
}

// TestGroupMembershipResource_CreateUpdateFallBackWhenMemberDetailsUnknown
// covers the EXCEPTION path: when member_details is Unknown at apply time
// (ModifyPlan itself could not resolve members at plan time — e.g. `members`
// depended on a computed attribute of another resource being created in the
// very same apply, so its value only becomes known once that resource is
// applied), Create/Update must fall back to resolving `members` fresh
// (resolveMembersForWriteFallback) rather than trying to unpack an
// Unknown/Null member_details. Since data.Members is fully known by the
// time this fallback runs (the framework guarantees dependent apply-time
// values are resolved before this resource's Create/Update executes), the
// fallback's own live/cached resolution can succeed via a cache hit alone,
// requiring no additional live Search either — exercised here by
// pre-seeding the cache manager (mirroring the pattern in
// TestGroupMembershipResource_ModifyPlanNeverMutatesMembers, which drives
// this same "unknown" condition through ModifyPlan rather than directly
// through Create/Update).
//
// Critically, the fallback must also backfill data.MemberDetails from the
// fresh resolution before saving state: Terraform requires every computed
// attribute to be fully known once apply completes, so member_details can
// never be persisted as Unknown/Null.
func TestGroupMembershipResource_CreateUpdateFallBackWhenMemberDetailsUnknown(t *testing.T) {
	ctx := t.Context()

	const (
		memberDN   = "CN=ResolvedOnlyAtApplyTime,OU=Users,DC=example,DC=com"
		memberGUID = "22222222-2222-2222-2222-222222222222"

		groupGUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
		groupDN   = "CN=OtherTestGroup,OU=Groups,DC=example,DC=com"
	)

	expectedAltDN, err := ldapclient.GUIDToAltDN(memberGUID)
	if err != nil {
		t.Fatalf("failed to compute expected alt-DN: %v", err)
	}

	t.Run("Create", func(t *testing.T) {
		cm := ldapclient.NewCacheManager()
		seedMembershipCache(t, cm, memberDN, memberGUID)

		client := newRecordingMembershipClient(groupGUID, groupDN) // no members yet
		r := newTestGroupMembershipResourceWithClient(client, cm)

		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringUnknown(),
			GroupID:              types.StringValue(groupGUID),
			Members:              newMembershipSet(t, memberDN),
			MemberDetails:        types.SetUnknown(memberDetailObjectType), // ModifyPlan could not resolve at plan time
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipCreate(t, ctx, r, planModel)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		added := client.addedMemberValues()
		if len(added) != 1 || added[0] != expectedAltDN {
			t.Errorf("AD write used %v, want [%q] (fallback-resolved GUID-alt-DN form)", added, expectedAltDN)
		}

		// The fallback resolved via a cache hit; no live Search needed.
		if extra := client.nonGroupLookupSearches(); len(extra) != 0 {
			t.Errorf("unexpected live Search calls during fallback resolution: %v", extra)
		}

		// member_details must never be left Unknown/Null in the saved
		// state — it must be backfilled from the fallback resolution.
		if out.MemberDetails.IsUnknown() || out.MemberDetails.IsNull() {
			t.Fatalf("member_details left Unknown/Null after apply: %v", out.MemberDetails)
		}
		gotDetails := extractMemberDetails(t, ctx, out.MemberDetails)
		wantDetails := map[string]string{memberDN: memberGUID}
		if len(gotDetails) != len(wantDetails) || gotDetails[memberDN] != memberGUID {
			t.Errorf("member_details = %v, want %v", gotDetails, wantDetails)
		}
	})

	t.Run("Update", func(t *testing.T) {
		cm := ldapclient.NewCacheManager()
		seedMembershipCache(t, cm, memberDN, memberGUID)

		const dnOld = "CN=OldMember,OU=Users,DC=example,DC=com"
		client := newRecordingMembershipClient(groupGUID, groupDN, dnOld)
		r := newTestGroupMembershipResourceWithClient(client, cm)

		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupGUID),
			GroupID:              types.StringValue(groupGUID),
			Members:              newMembershipSet(t, memberDN),
			MemberDetails:        types.SetUnknown(memberDetailObjectType),
			IgnoreMissingMembers: types.BoolNull(),
		}
		stateModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupGUID),
			GroupID:              types.StringValue(groupGUID),
			Members:              newMembershipSet(t, dnOld),
			MemberDetails:        newMemberDetailSet(t, ctx, []string{dnOld}, []string{""}),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipUpdate(t, ctx, r, planModel, stateModel)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		added := client.addedMemberValues()
		if len(added) != 1 || added[0] != expectedAltDN {
			t.Errorf("AD write used %v, want [%q] (fallback-resolved GUID-alt-DN form)", added, expectedAltDN)
		}

		if len(client.members) != 1 || client.members[0] != expectedAltDN {
			t.Errorf("final group membership = %v, want [%q]", client.members, expectedAltDN)
		}

		if extra := client.nonGroupLookupSearches(); len(extra) != 0 {
			t.Errorf("unexpected live Search calls during fallback resolution: %v", extra)
		}

		if out.MemberDetails.IsUnknown() || out.MemberDetails.IsNull() {
			t.Fatalf("member_details left Unknown/Null after apply: %v", out.MemberDetails)
		}
		gotDetails := extractMemberDetails(t, ctx, out.MemberDetails)
		wantDetails := map[string]string{memberDN: memberGUID}
		if len(gotDetails) != len(wantDetails) || gotDetails[memberDN] != memberGUID {
			t.Errorf("member_details = %v, want %v", gotDetails, wantDetails)
		}
	})
}
