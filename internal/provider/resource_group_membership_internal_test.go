package provider

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// stubMembershipClient is a minimal ldapclient.Client implementation for
// driving GroupMembershipResource.ModifyPlan without live LDAP access. Every
// identifier exercised by the tests in this file is pre-seeded into the
// CacheManager so normalization resolves via cache hits; any Search call
// indicates a test setup bug (missing cache seed) and fails loudly rather
// than silently attempting network I/O.
type stubMembershipClient struct{}

var _ ldapclient.Client = (*stubMembershipClient)(nil)

func (s *stubMembershipClient) Connect(ctx context.Context) error { return nil }
func (s *stubMembershipClient) Close() error                      { return nil }

func (s *stubMembershipClient) Bind(ctx context.Context, username, password string) error {
	return nil
}

func (s *stubMembershipClient) BindWithConfig(ctx context.Context) error { return nil }

func (s *stubMembershipClient) Search(ctx context.Context, req *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
	baseDN := ""
	if req != nil {
		baseDN = req.BaseDN
	}
	return nil, fmt.Errorf("stubMembershipClient: unexpected Search(%q) call — identifier should have been cache-resolved", baseDN)
}

func (s *stubMembershipClient) SearchWithPaging(ctx context.Context, req *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
	return nil, fmt.Errorf("stubMembershipClient: unexpected SearchWithPaging call")
}

func (s *stubMembershipClient) Add(ctx context.Context, req *ldapclient.AddRequest) error { return nil }

func (s *stubMembershipClient) Modify(ctx context.Context, req *ldapclient.ModifyRequest) error {
	return nil
}

func (s *stubMembershipClient) ModifyDN(ctx context.Context, req *ldapclient.ModifyDNRequest) error {
	return nil
}

func (s *stubMembershipClient) Delete(ctx context.Context, dn string) error { return nil }

func (s *stubMembershipClient) Ping(ctx context.Context) error { return nil }

func (s *stubMembershipClient) Stats() ldapclient.PoolStats { return ldapclient.PoolStats{} }

func (s *stubMembershipClient) GetBaseDN(ctx context.Context) (string, error) {
	return "DC=example,DC=com", nil
}

func (s *stubMembershipClient) GetRootDSE(ctx context.Context) (*ldapclient.RootDSEInfo, error) {
	return nil, fmt.Errorf("stubMembershipClient: GetRootDSE not implemented")
}

func (s *stubMembershipClient) WhoAmI(ctx context.Context) (*ldapclient.WhoAmIResult, error) {
	return nil, fmt.Errorf("stubMembershipClient: WhoAmI not implemented")
}

// newTestGroupMembershipResource constructs a GroupMembershipResource wired
// to a stub client and the given cache manager, for driving ModifyPlan
// directly without a real provider server or live LDAP connection. All
// scenarios in this file resolve every configured member successfully (via
// pre-seeded cache entries), so ignore_missing_members is fixed at its
// strict (false) default; it is not exercised here.
func newTestGroupMembershipResource(cm *ldapclient.CacheManager) *GroupMembershipResource {
	return &GroupMembershipResource{
		client:               &stubMembershipClient{},
		cacheManager:         cm,
		ignoreMissingMembers: false,
	}
}

// seedMembershipCache registers a DN<->GUID pair in the cache manager so
// normalization of either the DN or GUID form resolves without a live LDAP
// Search call.
func seedMembershipCache(t *testing.T, cm *ldapclient.CacheManager, dn, guid string) {
	t.Helper()
	if err := cm.Put(&ldapclient.LDAPCacheEntry{
		DN:         dn,
		ObjectGUID: guid,
		Attributes: map[string][]string{},
	}); err != nil {
		t.Fatalf("failed to seed cache entry for %s: %v", dn, err)
	}
}

// newMembershipSet builds a types.Set of strings, failing the test on error.
// Used for the flat `members` attribute.
func newMembershipSet(t *testing.T, values ...string) types.Set {
	t.Helper()
	elems := make([]attr.Value, 0, len(values))
	for _, v := range values {
		elems = append(elems, types.StringValue(v))
	}
	s, diags := types.SetValue(types.StringType, elems)
	if diags.HasError() {
		t.Fatalf("failed to build set: %v", diags.Errors())
	}
	return s
}

// extractSortedMembers extracts the string elements of a types.Set, sorted
// for order-independent comparison. Null/unknown sets extract to nil. Used
// for the flat `members` attribute.
func extractSortedMembers(t *testing.T, ctx context.Context, s types.Set) []string {
	t.Helper()
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	var out []string
	diags := s.ElementsAs(ctx, &out, false)
	if diags.HasError() {
		t.Fatalf("failed to extract members: %v", diags.Errors())
	}
	sort.Strings(out)
	return out
}

// newMemberDetailSet builds a types.Set of `member_details` {dn, id}
// objects from parallel dn/guid slices (same length, same order), failing
// the test on error.
func newMemberDetailSet(t *testing.T, ctx context.Context, dns, guids []string) types.Set {
	t.Helper()
	if len(dns) != len(guids) {
		t.Fatalf("newMemberDetailSet: dns and guids must be the same length, got %d and %d", len(dns), len(guids))
	}
	details := make([]MemberDetailModel, 0, len(dns))
	for i, dn := range dns {
		details = append(details, MemberDetailModel{
			DN: types.StringValue(dn),
			ID: types.StringValue(guids[i]),
		})
	}
	s, diags := types.SetValueFrom(ctx, memberDetailObjectType, details)
	if diags.HasError() {
		t.Fatalf("failed to build member_details set: %v", diags.Errors())
	}
	return s
}

// extractMemberDetails extracts the {dn, id} elements of a `member_details`
// types.Set into a dn->guid map, for order-independent comparison. Null/
// unknown sets extract to nil.
func extractMemberDetails(t *testing.T, ctx context.Context, s types.Set) map[string]string {
	t.Helper()
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	var details []MemberDetailModel
	diags := s.ElementsAs(ctx, &details, false)
	if diags.HasError() {
		t.Fatalf("failed to extract member details: %v", diags.Errors())
	}
	out := make(map[string]string, len(details))
	for _, d := range details {
		out[d.DN.ValueString()] = d.ID.ValueString()
	}
	return out
}

// extractSortedMemberDetailDNs extracts just the `dn` field of each element
// of a `member_details` types.Set, sorted for order-independent comparison.
// Null/unknown sets extract to nil.
func extractSortedMemberDetailDNs(t *testing.T, ctx context.Context, s types.Set) []string {
	t.Helper()
	pairs := extractMemberDetails(t, ctx, s)
	if pairs == nil {
		return nil
	}
	out := make([]string, 0, len(pairs))
	for dn := range pairs {
		out = append(out, dn)
	}
	sort.Strings(out)
	return out
}

// runMembershipModifyPlan drives GroupMembershipResource.ModifyPlan with the
// given plan/state models (either may be nil to represent a null/absent
// value, e.g. no prior state on Create) and returns the resulting plan model
// alongside the response diagnostics.
func runMembershipModifyPlan(
	t *testing.T,
	ctx context.Context,
	r *GroupMembershipResource,
	planModel, stateModel *GroupMembershipResourceModel,
) (*GroupMembershipResourceModel, *resource.ModifyPlanResponse) {
	t.Helper()

	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	tfType := schemaResp.Schema.Type().TerraformType(ctx)

	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: tftypes.NewValue(tfType, nil)}
	if planModel != nil {
		if diags := plan.Set(ctx, planModel); diags.HasError() {
			t.Fatalf("failed to build plan: %v", diags.Errors())
		}
	}

	state := tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(tfType, nil)}
	if stateModel != nil {
		if diags := state.Set(ctx, stateModel); diags.HasError() {
			t.Fatalf("failed to build state: %v", diags.Errors())
		}
	}

	req := resource.ModifyPlanRequest{
		State: state,
		Plan:  plan,
	}
	// The real framework runtime pre-populates resp.Plan with req.Plan
	// before invoking ModifyPlan; mirror that here.
	resp := &resource.ModifyPlanResponse{Plan: plan}

	r.ModifyPlan(ctx, req, resp)

	var out GroupMembershipResourceModel
	if !resp.Plan.Raw.IsNull() {
		if diags := resp.Plan.Get(ctx, &out); diags.HasError() {
			t.Fatalf("failed to extract resulting plan: %v", diags.Errors())
		}
	}
	return &out, resp
}

// TestGroupMembershipResource_ModifyPlanNeverMutatesMembers is a regression
// guard for the bug where ModifyPlan rewrote the user's Required, verbatim
// `members` attribute at plan time (replacing configured identifiers with
// prior-state identifiers whenever they resolved to the same AD object).
// terraform-plugin-framework forbids changing a known config value during
// planning, and the rewrite was partial (newly-added members kept their
// configured format), so the planned `members` matched neither config nor
// prior state, producing "Provider produced invalid plan" errors.
//
// Invariant under test: ModifyPlan must never mutate `members` — the
// resulting plan's `members` attribute must always equal the input plan's
// `members` attribute verbatim (order-independent), regardless of prior
// state. Only `member_details` may be (and must be) derived/updated.
func TestGroupMembershipResource_ModifyPlanNeverMutatesMembers(t *testing.T) {
	ctx := t.Context()

	const (
		dn1 = "CN=Member1,OU=Users,DC=example,DC=com"
		dn2 = "CN=Member2,OU=Users,DC=example,DC=com"
		dn3 = "CN=Member3,OU=Users,DC=example,DC=com"

		guid1 = "11111111-1111-1111-1111-111111111111"
		guid2 = "22222222-2222-2222-2222-222222222222"
		guid3 = "33333333-3333-3333-3333-333333333333"

		groupID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	)

	assertMembersVerbatim := func(t *testing.T, ctx context.Context, want, got types.Set) {
		t.Helper()
		wantSorted := extractSortedMembers(t, ctx, want)
		gotSorted := extractSortedMembers(t, ctx, got)
		if !slices.Equal(wantSorted, gotSorted) {
			t.Errorf("members mutated by ModifyPlan: input plan members=%v, resulting plan members=%v", wantSorted, gotSorted)
		}
	}

	t.Run("CI repro: mixed transition (DN state, GUID config + new GUID member)", func(t *testing.T) {
		cm := ldapclient.NewCacheManager()
		seedMembershipCache(t, cm, dn1, guid1)
		seedMembershipCache(t, cm, dn2, guid2)
		seedMembershipCache(t, cm, dn3, guid3)

		r := newTestGroupMembershipResource(cm)

		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, guid1, guid2, guid3),
			MemberDetails:        types.SetUnknown(memberDetailObjectType),
			IgnoreMissingMembers: types.BoolNull(),
		}
		stateModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, dn1, dn2),
			MemberDetails:        newMemberDetailSet(t, ctx, []string{dn1, dn2}, []string{guid1, guid2}),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipModifyPlan(t, ctx, r, planModel, stateModel)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		assertMembersVerbatim(t, ctx, planModel.Members, out.Members)

		gotDetails := extractMemberDetails(t, ctx, out.MemberDetails)
		wantDetails := map[string]string{dn1: guid1, dn2: guid2, dn3: guid3}
		if len(gotDetails) != len(wantDetails) {
			t.Fatalf("member_details = %v, want %v", gotDetails, wantDetails)
		}
		for dn, guid := range wantDetails {
			if gotDetails[dn] != guid {
				t.Errorf("member_details[%q] = %q, want %q", dn, gotDetails[dn], guid)
			}
		}
	})

	t.Run("Create (no prior state)", func(t *testing.T) {
		cm := ldapclient.NewCacheManager()
		seedMembershipCache(t, cm, dn1, guid1)
		seedMembershipCache(t, cm, dn2, guid2)

		r := newTestGroupMembershipResource(cm)

		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringUnknown(),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, guid1, guid2),
			MemberDetails:        types.SetUnknown(memberDetailObjectType),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipModifyPlan(t, ctx, r, planModel, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		assertMembersVerbatim(t, ctx, planModel.Members, out.Members)

		gotNormalized := extractSortedMemberDetailDNs(t, ctx, out.MemberDetails)
		wantNormalized := []string{dn1, dn2}
		sort.Strings(wantNormalized)
		if !slices.Equal(gotNormalized, wantNormalized) {
			t.Errorf("member_details dns = %v, want %v", gotNormalized, wantNormalized)
		}
	})

	t.Run("verbatim passthrough, same format", func(t *testing.T) {
		cm := ldapclient.NewCacheManager()
		seedMembershipCache(t, cm, dn1, guid1)
		seedMembershipCache(t, cm, dn2, guid2)

		r := newTestGroupMembershipResource(cm)

		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, dn1, dn2),
			MemberDetails:        types.SetUnknown(memberDetailObjectType),
			IgnoreMissingMembers: types.BoolNull(),
		}
		stateModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, dn1, dn2),
			MemberDetails:        newMemberDetailSet(t, ctx, []string{dn1, dn2}, []string{guid1, guid2}),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipModifyPlan(t, ctx, r, planModel, stateModel)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		assertMembersVerbatim(t, ctx, planModel.Members, out.Members)
	})

	t.Run("format change, same principals (must NOT be reconciled back to state format)", func(t *testing.T) {
		cm := ldapclient.NewCacheManager()
		seedMembershipCache(t, cm, dn1, guid1)
		seedMembershipCache(t, cm, dn2, guid2)

		r := newTestGroupMembershipResource(cm)

		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, guid1, guid2),
			MemberDetails:        types.SetUnknown(memberDetailObjectType),
			IgnoreMissingMembers: types.BoolNull(),
		}
		stateModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, dn1, dn2),
			MemberDetails:        newMemberDetailSet(t, ctx, []string{dn1, dn2}, []string{guid1, guid2}),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipModifyPlan(t, ctx, r, planModel, stateModel)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		// The critical assertion: members must remain the configured GUIDs,
		// NOT be silently reconciled back to the prior-state DNs.
		assertMembersVerbatim(t, ctx, planModel.Members, out.Members)

		gotMembers := extractSortedMembers(t, ctx, out.Members)
		for _, dn := range []string{dn1, dn2} {
			if slices.Contains(gotMembers, dn) {
				t.Errorf("members were reconciled back to prior-state DN %q; members = %v", dn, gotMembers)
			}
		}
	})

	t.Run("unknown group_id: early return, no panic, members untouched", func(t *testing.T) {
		cm := ldapclient.NewCacheManager()
		r := newTestGroupMembershipResource(cm)

		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringUnknown(),
			GroupID:              types.StringUnknown(),
			Members:              newMembershipSet(t, guid1),
			MemberDetails:        types.SetUnknown(memberDetailObjectType),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipModifyPlan(t, ctx, r, planModel, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		assertMembersVerbatim(t, ctx, planModel.Members, out.Members)

		if !out.MemberDetails.IsUnknown() {
			t.Errorf("expected member_details to be unknown when group_id is unknown, got %v", out.MemberDetails)
		}
	})
}

// TestGroupMembershipResource_ModifyPlanUnknownMembersDetail is a focused
// regression guard for the "member_details must be Unknown, as a whole, when
// `members` itself is unknown" branch of ModifyPlan — mirroring the same
// unknown-members scenario already covered inside
// TestGroupMembershipResource_ModifyPlanNeverMutatesMembers's "unknown
// group_id" subtest, but isolating the case where group_id IS known and it
// is specifically `members` that is unknown (e.g. it references an
// attribute of a resource being created in the very same apply). This is
// also exactly the condition that later forces Create/Update's apply-time
// fallback path (see resolveMemberDetailsForWrite in
// resource_group_membership.go and
// TestGroupMembershipResource_CreateUpdateFallBackWhenMemberDetailsUnknown
// in resource_group_membership_apply_test.go).
func TestGroupMembershipResource_ModifyPlanUnknownMembersDetail(t *testing.T) {
	ctx := t.Context()

	const groupID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	cm := ldapclient.NewCacheManager()
	r := newTestGroupMembershipResource(cm)

	planModel := &GroupMembershipResourceModel{
		ID:                   types.StringValue(groupID),
		GroupID:              types.StringValue(groupID),
		Members:              types.SetUnknown(types.StringType),
		MemberDetails:        types.SetUnknown(memberDetailObjectType),
		IgnoreMissingMembers: types.BoolNull(),
	}

	out, resp := runMembershipModifyPlan(t, ctx, r, planModel, nil)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
	}

	if !out.MemberDetails.IsUnknown() {
		t.Errorf("expected member_details to be unknown (as a whole) when members is unknown, got %v", out.MemberDetails)
	}
}

// TestGroupMembershipResource_ModifyPlanResolvesEveryIdentifierFormat proves
// that ModifyPlan populates `member_details` with the correct (dn, id)
// pair for every supported `members` identifier format — DN, GUID, SID,
// UPN, and SAM — each resolved via a cache-seeded entry (no live LDAP
// call), following the same direct-ModifyPlan-invocation and cache-seeding
// conventions as TestGroupMembershipResource_ModifyPlanNeverMutatesMembers.
func TestGroupMembershipResource_ModifyPlanResolvesEveryIdentifierFormat(t *testing.T) {
	ctx := t.Context()

	const (
		groupID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

		// dnFormat is used AS the `members` identifier verbatim (it IS
		// already a DN), so resolving it is a validateDN cache hit.
		dnFormat = "CN=DNMember,OU=Users,DC=example,DC=com"
		guidOfDN = "11111111-1111-1111-1111-111111111111"

		guidMember     = "22222222-2222-2222-2222-222222222222"
		dnOfGUIDMember = "CN=GUIDMember,OU=Users,DC=example,DC=com"

		sidMember     = "S-1-5-21-123456789-123456789-123456789-1001"
		dnOfSIDMember = "CN=SIDMember,OU=Users,DC=example,DC=com"
		guidOfSID     = "33333333-3333-3333-3333-333333333333"

		upnMember = "upnmember@example.com"
		dnOfUPN   = "CN=UPNMember,OU=Users,DC=example,DC=com"
		guidOfUPN = "44444444-4444-4444-4444-444444444444"

		samMember = "DOMAIN\\SAMMember"
		dnOfSAM   = "CN=SAMMember,OU=Users,DC=example,DC=com"
		guidOfSAM = "55555555-5555-5555-5555-555555555555"
	)

	cm := ldapclient.NewCacheManager()
	// Seed by the identifier the cache will actually be queried with:
	// MemberNormalizer.Resolve checks the cache using the (trimmed) input
	// identifier first, so each entry below is keyed appropriately —
	// seedMembershipCache's DN/GUID pair is enough because CacheManager.Get
	// resolves via any indexed key (DN, GUID, SID, UPN, SAM) that Put
	// recorded for the entry, and validateDN/resolveGUID/etc. all populate
	// the full LDAPCacheEntry (including SID/UPN/SAM-specific fields) when
	// caching a live resolution. Since these tests must never hit Search,
	// we instead seed one full entry per member covering every index the
	// resolver for that identifier's type will look up.
	seedMembershipCache(t, cm, dnFormat, guidOfDN)
	seedMembershipCache(t, cm, dnOfGUIDMember, guidMember)
	if err := cm.Put(&ldapclient.LDAPCacheEntry{
		DN:         dnOfSIDMember,
		ObjectGUID: guidOfSID,
		ObjectSID:  sidMember,
		Attributes: map[string][]string{},
	}); err != nil {
		t.Fatalf("failed to seed SID cache entry: %v", err)
	}
	if err := cm.Put(&ldapclient.LDAPCacheEntry{
		DN:         dnOfUPN,
		ObjectGUID: guidOfUPN,
		Attributes: map[string][]string{"userPrincipalName": {upnMember}},
	}); err != nil {
		t.Fatalf("failed to seed UPN cache entry: %v", err)
	}
	if err := cm.Put(&ldapclient.LDAPCacheEntry{
		DN:         dnOfSAM,
		ObjectGUID: guidOfSAM,
		Attributes: map[string][]string{"sAMAccountName": {"SAMMember"}},
	}); err != nil {
		t.Fatalf("failed to seed SAM cache entry: %v", err)
	}

	r := newTestGroupMembershipResource(cm)

	planModel := &GroupMembershipResourceModel{
		ID:                   types.StringValue(groupID),
		GroupID:              types.StringValue(groupID),
		Members:              newMembershipSet(t, dnFormat, guidMember, sidMember, upnMember, samMember),
		MemberDetails:        types.SetUnknown(memberDetailObjectType),
		IgnoreMissingMembers: types.BoolNull(),
	}

	out, resp := runMembershipModifyPlan(t, ctx, r, planModel, nil)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
	}

	got := extractMemberDetails(t, ctx, out.MemberDetails)
	want := map[string]string{
		dnFormat:       guidOfDN,
		dnOfGUIDMember: guidMember,
		dnOfSIDMember:  guidOfSID,
		dnOfUPN:        guidOfUPN,
		dnOfSAM:        guidOfSAM,
	}
	if len(got) != len(want) {
		t.Fatalf("member_details = %v, want %v", got, want)
	}
	for dn, guid := range want {
		if got[dn] != guid {
			t.Errorf("member_details[%q] = %q, want %q", dn, got[dn], guid)
		}
	}
}
