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
// for order-independent comparison. Null/unknown sets extract to nil.
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
// state. Only `members_normalized` may be (and must be) derived/updated.
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
			MembersNormalized:    types.SetUnknown(types.StringType),
			IgnoreMissingMembers: types.BoolNull(),
		}
		stateModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, dn1, dn2),
			MembersNormalized:    newMembershipSet(t, dn1, dn2),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipModifyPlan(t, ctx, r, planModel, stateModel)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		assertMembersVerbatim(t, ctx, planModel.Members, out.Members)

		gotNormalized := extractSortedMembers(t, ctx, out.MembersNormalized)
		wantNormalized := []string{dn1, dn2, dn3}
		sort.Strings(wantNormalized)
		if !slices.Equal(gotNormalized, wantNormalized) {
			t.Errorf("members_normalized = %v, want %v", gotNormalized, wantNormalized)
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
			MembersNormalized:    types.SetUnknown(types.StringType),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipModifyPlan(t, ctx, r, planModel, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		assertMembersVerbatim(t, ctx, planModel.Members, out.Members)

		gotNormalized := extractSortedMembers(t, ctx, out.MembersNormalized)
		wantNormalized := []string{dn1, dn2}
		sort.Strings(wantNormalized)
		if !slices.Equal(gotNormalized, wantNormalized) {
			t.Errorf("members_normalized = %v, want %v", gotNormalized, wantNormalized)
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
			MembersNormalized:    types.SetUnknown(types.StringType),
			IgnoreMissingMembers: types.BoolNull(),
		}
		stateModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, dn1, dn2),
			MembersNormalized:    newMembershipSet(t, dn1, dn2),
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
			MembersNormalized:    types.SetUnknown(types.StringType),
			IgnoreMissingMembers: types.BoolNull(),
		}
		stateModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, dn1, dn2),
			MembersNormalized:    newMembershipSet(t, dn1, dn2),
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
			MembersNormalized:    types.SetUnknown(types.StringType),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipModifyPlan(t, ctx, r, planModel, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		assertMembersVerbatim(t, ctx, planModel.Members, out.Members)

		if !out.MembersNormalized.IsUnknown() {
			t.Errorf("expected members_normalized to be unknown when group_id is unknown, got %v", out.MembersNormalized)
		}
	})
}
