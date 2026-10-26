package provider

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
//
// Tests exercising live member matching (the group-member read performed by
// readCurrentMembersBestEffort) configure the optional fields below. A search
// carrying LDAP controls is the group's extended-DN member read; any other
// search is a member-resolver search. Both are counted/recorded. Unless
// configured, both kinds of search fail as before.
type stubMembershipClient struct {
	mu sync.Mutex

	// serveGroup makes the group-member read succeed, returning groupValues
	// as the group's raw "member" attribute values (extended-DN form).
	serveGroup  bool
	groupValues []string
	// groupNotFound makes the group read succeed with zero entries.
	groupNotFound bool
	// groupErr, if set, is returned by the group read.
	groupErr error

	// resolvable serves resolver searches: keyed by the search filter (UPN/
	// SAM/GUID/SID subtree searches) or by the base DN (DN validation).
	resolvable map[string]stubObject

	// legacyServe makes the plain (control-less) group read used by
	// GetGroupMembers succeed with legacyMembers as the raw member values.
	// If unset but serveGroup is, the legacy read serves the DNs of
	// groupValues, so both readers agree about the group.
	legacyServe   bool
	legacyMembers []string
	// legacyErr, if set, is returned by the legacy group read.
	legacyErr error
	// legacyNotFound makes the legacy group read succeed with zero entries.
	legacyNotFound bool

	groupReads      int
	legacyReads     int
	resolverQueries []string // filter, or base DN for base-object searches
}

// stubObject is a directory object served to resolver searches.
type stubObject struct {
	dn   string
	guid string
}

// extendedDNValue renders a group member value in AD's extended-DN form.
func extendedDNValue(guid, sid, dn string) string {
	v := "<GUID=" + guid + ">;"
	if sid != "" {
		v += "<SID=" + sid + ">;"
	}
	return v + dn
}

func (s *stubMembershipClient) counts() (groupReads int, resolver []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.groupReads, slices.Clone(s.resolverQueries)
}

var _ ldapclient.Client = (*stubMembershipClient)(nil)

func (s *stubMembershipClient) Connect(ctx context.Context) error { return nil }
func (s *stubMembershipClient) Close() error                      { return nil }

func (s *stubMembershipClient) Bind(ctx context.Context, username, password string) error {
	return nil
}

func (s *stubMembershipClient) Search(ctx context.Context, req *ldapclient.SearchRequest) (*ldapclient.SearchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	baseDN := ""
	if req != nil {
		baseDN = req.BaseDN
	}

	if req != nil && len(req.Controls) > 0 {
		s.groupReads++
		switch {
		case s.groupErr != nil:
			return nil, s.groupErr
		case s.groupNotFound:
			return &ldapclient.SearchResult{}, nil
		case s.serveGroup:
			entry := &ldap.Entry{
				DN: "CN=Group,OU=Groups,DC=example,DC=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "member", Values: slices.Clone(s.groupValues)},
				},
			}
			return &ldapclient.SearchResult{Entries: []*ldap.Entry{entry}, Total: 1}, nil
		}
		return nil, fmt.Errorf("stubMembershipClient: unexpected group member read Search(%q)", baseDN)
	}

	// The legacy group read (GroupManager.GetGroup, used by GetGroupMembers):
	// a subtree GUID search requesting the member attribute, no controls.
	if req != nil && req.Scope == ldapclient.ScopeWholeSubtree && slices.Contains(req.Attributes, "member") {
		s.legacyReads++
		var values []string
		switch {
		case s.legacyErr != nil:
			return nil, s.legacyErr
		case s.legacyNotFound:
			return &ldapclient.SearchResult{}, nil
		case s.legacyServe:
			values = slices.Clone(s.legacyMembers)
		case s.serveGroup:
			for _, v := range s.groupValues {
				parsed, err := ldapclient.ParseExtendedDN(v)
				if err != nil {
					return nil, err
				}
				values = append(values, parsed.DN)
			}
		default:
			return nil, fmt.Errorf("stubMembershipClient: unexpected legacy group read Search(%q)", baseDN)
		}
		raw, err := ldapclient.NewGUIDHandler().StringToGUIDBytes(liveGroupID)
		if err != nil {
			return nil, err
		}
		entry := &ldap.Entry{
			DN: "CN=Group,OU=Groups,DC=example,DC=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "objectGUID", Values: []string{string(raw)}, ByteValues: [][]byte{raw}},
				{Name: "member", Values: values},
			},
		}
		return &ldapclient.SearchResult{Entries: []*ldap.Entry{entry}, Total: 1}, nil
	}

	key := baseDN
	if req != nil && req.Scope == ldapclient.ScopeWholeSubtree {
		key = req.Filter
	}
	// The normalizer's NetBIOS-name lookups (rootDSE, then the Partitions
	// container) are not member resolutions: don't record them, and fail them
	// so the resolver's fail-open path is exercised.
	if req != nil && ((req.BaseDN == "" && req.Scope == ldapclient.ScopeBaseObject) ||
		strings.HasPrefix(req.BaseDN, "CN=Partitions,")) {
		return nil, fmt.Errorf("stubMembershipClient: unexpected Search(%q) call — identifier should have been cache-resolved", baseDN)
	}
	s.resolverQueries = append(s.resolverQueries, key)
	if obj, ok := s.resolvable[key]; ok {
		attrs := []*ldap.EntryAttribute{}
		if obj.guid != "" {
			raw, err := ldapclient.NewGUIDHandler().StringToGUIDBytes(obj.guid)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectGUID", Values: []string{string(raw)}, ByteValues: [][]byte{raw}})
		}
		return &ldapclient.SearchResult{Entries: []*ldap.Entry{{DN: obj.dn, Attributes: attrs}}, Total: 1}, nil
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
// directly without a real provider server or live LDAP connection. The
// provider-level ignore_missing_members default is fixed at its strict
// (false) value; scenarios exercising ignore-missing semantics set the
// resource-level `ignore_missing_members` attribute instead. Any identifier
// NOT pre-seeded into the cache manager fails to resolve (the stub's Search
// errors), which is how these tests model "object does not exist (yet)".
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

		// guid1/guid2 are in prior state (case K, anchored to state's
		// DN); guid3 is new (case G: id known, dn known after apply).
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{
			known:    map[string]string{dn1: guid1, dn2: guid2},
			guidOnly: []string{guid3},
		})
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

		// No prior state: every resolved member is case G.
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{
			guidOnly: []string{guid1, guid2},
		})
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

	members := newMembershipSet(t, dnFormat, guidMember, sidMember, upnMember, samMember)
	want := map[string]string{
		dnFormat:       guidOfDN,
		dnOfGUIDMember: guidMember,
		dnOfSIDMember:  guidOfSID,
		dnOfUPN:        guidOfUPN,
		dnOfSAM:        guidOfSAM,
	}

	// Create (no prior state): every format resolves to the right object,
	// planned as case G (id known, dn known after apply) because no DN is
	// stable across plan and the apply-time re-plan yet.
	t.Run("Create: every format resolves to its GUID", func(t *testing.T) {
		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringUnknown(),
			GroupID:              types.StringValue(groupID),
			Members:              members,
			MemberDetails:        types.SetUnknown(memberDetailObjectType),
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipModifyPlan(t, ctx, r, planModel, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{
			guidOnly: []string{guidOfDN, guidMember, guidOfSID, guidOfUPN, guidOfSAM},
		})
	})

	// Update against a prior state holding every member: every format is
	// matched by GUID to its prior-state element (case K, fully known).
	t.Run("Update: every format anchors to its prior-state element", func(t *testing.T) {
		dns := make([]string, 0, len(want))
		guids := make([]string, 0, len(want))
		for dn, guid := range want {
			dns = append(dns, dn)
			guids = append(guids, guid)
		}
		stateDetails := newMemberDetailSet(t, ctx, dns, guids)

		planModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              members,
			MemberDetails:        types.SetUnknown(memberDetailObjectType),
			IgnoreMissingMembers: types.BoolNull(),
		}
		stateModel := &GroupMembershipResourceModel{
			ID:                   types.StringValue(groupID),
			GroupID:              types.StringValue(groupID),
			Members:              newMembershipSet(t, dns...), // differs from config: not a no-op
			MemberDetails:        stateDetails,
			IgnoreMissingMembers: types.BoolNull(),
		}

		out, resp := runMembershipModifyPlan(t, ctx, r, planModel, stateModel)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}

		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{known: want})
	})
}

// ---------------------------------------------------------------------------
// Per-element member_details planning (cases K / G / P).
//
// Terraform re-plans every changing resource during apply (after its
// dependencies have been applied) and requires the re-plan to be compatible
// with the original plan, and the apply result to be compatible with the
// re-plan. The helpers below model both checks without AD so the
// plan -> re-plan -> apply pattern is unit-testable.
// ---------------------------------------------------------------------------

// knownDetail builds a fully known `member_details` element (case K, or a
// final post-apply element).
func knownDetail(t *testing.T, dn, id string) attr.Value {
	t.Helper()
	return newDetailObject(t, types.StringValue(dn), types.StringValue(id))
}

// guidOnlyDetail builds a case G element: id known, dn unknown.
func guidOnlyDetail(t *testing.T, id string) attr.Value {
	t.Helper()
	return newDetailObject(t, types.StringUnknown(), types.StringValue(id))
}

// placeholderDetail builds a case P element: both attributes unknown.
func placeholderDetail(t *testing.T) attr.Value {
	t.Helper()
	return newDetailObject(t, types.StringUnknown(), types.StringUnknown())
}

func newDetailObject(t *testing.T, dn, id types.String) attr.Value {
	t.Helper()
	obj, diags := types.ObjectValue(memberDetailAttrTypes, map[string]attr.Value{"dn": dn, "id": id})
	if diags.HasError() {
		t.Fatalf("failed to build member_details element: %v", diags.Errors())
	}
	return obj
}

// newMemberDetailSetOf builds a `member_details` set from explicit elements
// (which may contain unknowns).
func newMemberDetailSetOf(t *testing.T, elems ...attr.Value) types.Set {
	t.Helper()
	s, diags := types.SetValue(memberDetailObjectType, elems)
	if diags.HasError() {
		t.Fatalf("failed to build member_details set: %v", diags.Errors())
	}
	return s
}

// classifiedDetails is a planned `member_details` set broken down by case.
type classifiedDetails struct {
	known        map[string]string // case K: dn -> id, fully known
	guidOnly     []string          // case G: ids (sorted), dn unknown
	placeholders int               // case P: both unknown
}

// classifyMemberDetails breaks a known `member_details` set down into cases
// K/G/P. It fails the test for a wholly unknown/null set, or for an element
// shape ModifyPlan must never produce (dn known but id unknown).
func classifyMemberDetails(t *testing.T, s types.Set) classifiedDetails {
	t.Helper()
	if s.IsNull() || s.IsUnknown() {
		t.Fatalf("expected a known member_details set, got %v", s)
	}
	out := classifiedDetails{known: map[string]string{}}
	for _, elem := range s.Elements() {
		obj, ok := elem.(types.Object)
		if !ok {
			t.Fatalf("member_details element is %T, want types.Object", elem)
		}
		dn, _ := obj.Attributes()["dn"].(types.String)
		id, _ := obj.Attributes()["id"].(types.String)
		switch {
		case !dn.IsUnknown() && !id.IsUnknown():
			out.known[dn.ValueString()] = id.ValueString()
		case dn.IsUnknown() && !id.IsUnknown():
			out.guidOnly = append(out.guidOnly, id.ValueString())
		case dn.IsUnknown() && id.IsUnknown():
			out.placeholders++
		default:
			t.Fatalf("invalid member_details element (dn known, id unknown): %v", obj)
		}
	}
	sort.Strings(out.guidOnly)
	return out
}

// assertClassifiedDetails asserts a planned `member_details` set has exactly
// the given K elements, G ids and P count.
func assertClassifiedDetails(t *testing.T, s types.Set, want classifiedDetails) {
	t.Helper()
	got := classifyMemberDetails(t, s)
	if want.known == nil {
		want.known = map[string]string{}
	}
	wantGUIDOnly := slices.Clone(want.guidOnly)
	sort.Strings(wantGUIDOnly)

	if len(got.known) != len(want.known) {
		t.Errorf("known (case K) elements = %d %v, want %d %v", len(got.known), got.known, len(want.known), want.known)
	} else {
		for dn, id := range want.known {
			gotID, ok := got.known[dn]
			if !ok || gotID != id {
				t.Errorf("known (case K) element {dn=%q}: got id %q (present=%v), want %q", dn, gotID, ok, id)
			}
		}
	}
	if !slices.Equal(got.guidOnly, wantGUIDOnly) {
		t.Errorf("GUID-only (case G) ids = %v, want %v", got.guidOnly, wantGUIDOnly)
	}
	if got.placeholders != want.placeholders {
		t.Errorf("placeholder (case P) elements = %d, want %d", got.placeholders, want.placeholders)
	}
	if total := len(got.known) + len(got.guidOnly) + got.placeholders; total != len(s.Elements()) {
		t.Errorf("classification lost elements: classified %d, set has %d", total, len(s.Elements()))
	}
}

// detailElemCompatible mirrors Terraform's per-value compatibility rule
// (objchange.assertValueCompatible) for a single member_details element: a
// planned unknown matches anything; a planned known value must be matched by
// an equal known actual value (known -> unknown is incompatible).
func detailElemCompatible(planned, actual attr.Value) bool {
	if planned.IsUnknown() {
		return true
	}
	if actual.IsUnknown() || planned.IsNull() != actual.IsNull() {
		return false
	}
	pObj, pOK := planned.(types.Object)
	aObj, aOK := actual.(types.Object)
	if !pOK || !aOK {
		return planned.Equal(actual)
	}
	for name := range memberDetailAttrTypes {
		pv, av := pObj.Attributes()[name], aObj.Attributes()[name]
		if pv == nil || av == nil {
			return false
		}
		if pv.IsUnknown() {
			continue
		}
		if av.IsUnknown() || !pv.Equal(av) {
			return false
		}
	}
	return true
}

// finalPlanCompatibilityErrors mirrors Terraform's set-compatibility rules
// (objchange.AssertObjectCompatible), applied both between the original plan
// and the apply-time re-plan ("inconsistent final plan") and between the
// final plan and the apply result ("inconsistent result after apply"):
//   - a wholly unknown planned set matches anything;
//   - each planned element must correlate with some actual element;
//   - each actual element must correlate with some planned element;
//   - an unknown attribute matches anything;
//   - the set may shrink (unknown elements may coalesce) but never grow.
func finalPlanCompatibilityErrors(planned, actual types.Set) []string {
	if planned.IsUnknown() {
		return nil
	}
	if actual.IsUnknown() {
		return []string{"member_details: was known, but now unknown"}
	}
	if planned.IsNull() || actual.IsNull() {
		if planned.IsNull() != actual.IsNull() {
			return []string{fmt.Sprintf("member_details: null mismatch (planned null=%v, actual null=%v)", planned.IsNull(), actual.IsNull())}
		}
		return nil
	}

	var errs []string
	plannedElems, actualElems := planned.Elements(), actual.Elements()
	for _, p := range plannedElems {
		if !slices.ContainsFunc(actualElems, func(a attr.Value) bool { return detailElemCompatible(p, a) }) {
			errs = append(errs, fmt.Sprintf("planned set element %s does not correlate with any element in actual", p))
		}
	}
	for _, a := range actualElems {
		if !slices.ContainsFunc(plannedElems, func(p attr.Value) bool { return detailElemCompatible(p, a) }) {
			errs = append(errs, fmt.Sprintf("actual set element %s does not correlate with any element in plan", a))
		}
	}
	if len(actualElems) > len(plannedElems) {
		errs = append(errs, fmt.Sprintf("member_details: length changed from %d to %d", len(plannedElems), len(actualElems)))
	}
	return errs
}

// assertFinalPlanCompatible fails the test if `actual` (an apply-time
// re-plan, or an apply result) is not compatible with `planned` under
// Terraform's set rules (see finalPlanCompatibilityErrors).
func assertFinalPlanCompatible(t *testing.T, planned, actual types.Set) {
	t.Helper()
	for _, e := range finalPlanCompatibilityErrors(planned, actual) {
		t.Errorf("Provider produced inconsistent final plan: %s", e)
	}
}

// TestGroupMembershipAssertFinalPlanCompatible_Rules pins down the compatibility helper
// itself, so the regression tests built on it can be trusted.
func TestGroupMembershipAssertFinalPlanCompatible_Rules(t *testing.T) {
	const (
		dnA, idA = "CN=A,DC=example,DC=com", "11111111-1111-1111-1111-111111111111"
		dnB, idB = "CN=B,DC=example,DC=com", "22222222-2222-2222-2222-222222222222"
	)

	tests := []struct {
		name     string
		planned  types.Set
		actual   types.Set
		wantErrs bool
	}{
		{"identical known sets", newMemberDetailSetOf(t, knownDetail(t, dnA, idA)), newMemberDetailSetOf(t, knownDetail(t, dnA, idA)), false},
		{"wholly unknown plan matches anything", types.SetUnknown(memberDetailObjectType), newMemberDetailSetOf(t, knownDetail(t, dnA, idA)), false},
		{"known set grows (production failure)", newMemberDetailSetOf(t, knownDetail(t, dnA, idA)), newMemberDetailSetOf(t, knownDetail(t, dnA, idA), knownDetail(t, dnB, idB)), true},
		{"known element renamed", newMemberDetailSetOf(t, knownDetail(t, dnA, idA)), newMemberDetailSetOf(t, knownDetail(t, dnB, idA)), true},
		{"placeholder matches a new element", newMemberDetailSetOf(t, knownDetail(t, dnA, idA), placeholderDetail(t)), newMemberDetailSetOf(t, knownDetail(t, dnA, idA), knownDetail(t, dnB, idB)), false},
		{"placeholders may coalesce (shrink)", newMemberDetailSetOf(t, knownDetail(t, dnA, idA), placeholderDetail(t), placeholderDetail(t)), newMemberDetailSetOf(t, knownDetail(t, dnA, idA)), false},
		{"GUID-only matches same id", newMemberDetailSetOf(t, guidOnlyDetail(t, idA)), newMemberDetailSetOf(t, knownDetail(t, dnA, idA)), false},
		{"GUID-only does not match other id", newMemberDetailSetOf(t, guidOnlyDetail(t, idA)), newMemberDetailSetOf(t, knownDetail(t, dnB, idB)), true},
		{"known became unknown", newMemberDetailSetOf(t, knownDetail(t, dnA, idA)), newMemberDetailSetOf(t, guidOnlyDetail(t, idA)), true},
		{"planned known element missing from actual", newMemberDetailSetOf(t, knownDetail(t, dnA, idA), knownDetail(t, dnB, idB)), newMemberDetailSetOf(t, knownDetail(t, dnA, idA)), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := finalPlanCompatibilityErrors(tc.planned, tc.actual)
			if gotErrs := len(errs) > 0; gotErrs != tc.wantErrs {
				t.Errorf("compatibility errors = %v, want errors=%v", errs, tc.wantErrs)
			}
		})
	}
}

// membershipTestGroupID is the group objectGUID used by membershipModel.
const membershipTestGroupID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

// membershipModel is a small constructor for GroupMembershipResourceModel
// used by the per-element planning tests below.
func membershipModel(members, details types.Set, ignoreMissing types.Bool) *GroupMembershipResourceModel {
	return &GroupMembershipResourceModel{
		ID:                   types.StringValue(membershipTestGroupID),
		GroupID:              types.StringValue(membershipTestGroupID),
		Members:              members,
		MemberDetails:        details,
		IgnoreMissingMembers: ignoreMissing,
	}
}

// hasWarningSummary reports whether diags contains a warning with the given summary.
func hasWarningSummary(diags diag.Diagnostics, summary string) bool {
	for _, d := range diags.Warnings() {
		if d.Summary() == summary {
			return true
		}
	}
	return false
}

// TestGroupMembershipResource_ModifyPlanPerElementMemberDetails covers the
// ModifyPlan test matrix (rows 1-12, 15, 16) for per-element member_details
// planning. Rows 13-14 (the regressions) are in
// TestGroupMembershipResource_ModifyPlanReplanCompatible; row 17 is
// TestGroupMembershipResource_ModifyPlanNeverMutatesMembers.
func TestGroupMembershipResource_ModifyPlanPerElementMemberDetails(t *testing.T) {
	ctx := t.Context()

	const (
		dn1   = "CN=Member1,OU=Users,DC=example,DC=com"
		dn2   = "CN=Member2,OU=Users,DC=example,DC=com"
		dn3   = "CN=Member3,OU=Users,DC=example,DC=com"
		guid1 = "11111111-1111-1111-1111-111111111111"
		guid2 = "22222222-2222-2222-2222-222222222222"
		guid3 = "33333333-3333-3333-3333-333333333333"

		dnMissing1 = "CN=NotYetCreated1,OU=Groups,DC=example,DC=com"
		dnMissing2 = "CN=NotYetCreated2,OU=Groups,DC=example,DC=com"

		dnDrift   = "CN=OutOfBand,OU=Users,DC=example,DC=com"
		guidDrift = "99999999-9999-9999-9999-999999999999"
	)

	ignoreMissing := types.BoolValue(true)

	seeded := func(t *testing.T) *ldapclient.CacheManager {
		t.Helper()
		cm := ldapclient.NewCacheManager()
		seedMembershipCache(t, cm, dn1, guid1)
		seedMembershipCache(t, cm, dn2, guid2)
		seedMembershipCache(t, cm, dn3, guid3)
		return cm
	}

	// Row 1 is covered by the FIXed Create subtests of
	// ModifyPlanNeverMutatesMembers and ModifyPlanResolvesEveryIdentifierFormat;
	// this is the DN-format variant.
	t.Run("row 1: create, all members resolve -> every element case G", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		plan := membershipModel(newMembershipSet(t, dn1, dn2), types.SetUnknown(memberDetailObjectType), types.BoolNull())
		plan.ID = types.StringUnknown()

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{guidOnly: []string{guid1, guid2}})
	})

	t.Run("row 2: create, one member unresolved (ignore-missing) -> G + 1 P + warning", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		plan := membershipModel(newMembershipSet(t, dn1, dn2, dnMissing1), types.SetUnknown(memberDetailObjectType), ignoreMissing)
		plan.ID = types.StringUnknown()

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		if !hasWarningSummary(resp.Diagnostics, "Member could not be resolved") {
			t.Errorf("expected a 'Member could not be resolved' warning, got %v", resp.Diagnostics)
		}
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{guidOnly: []string{guid1, guid2}, placeholders: 1})
	})

	t.Run("row 3: production shape, 432 in state + 2 unresolved added -> 432 K + 2 P", func(t *testing.T) {
		const existing = 432
		cm := ldapclient.NewCacheManager()
		dns := make([]string, 0, existing)
		guids := make([]string, 0, existing)
		want := make(map[string]string, existing)
		for i := range existing {
			dn := fmt.Sprintf("CN=Existing%03d,OU=Users,DC=example,DC=com", i)
			guid := fmt.Sprintf("00000000-0000-0000-0000-%012d", i)
			seedMembershipCache(t, cm, dn, guid)
			dns = append(dns, dn)
			guids = append(guids, guid)
			want[dn] = guid
		}
		r := newTestGroupMembershipResource(cm)

		stateDetails := newMemberDetailSet(t, ctx, dns, guids)
		state := membershipModel(newMembershipSet(t, dns...), stateDetails, ignoreMissing)
		plan := membershipModel(newMembershipSet(t, append(slices.Clone(dns), dnMissing1, dnMissing2)...), types.SetUnknown(memberDetailObjectType), ignoreMissing)

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{known: want, placeholders: 2})
		if n := len(out.MemberDetails.Elements()); n != existing+2 {
			t.Errorf("planned member_details has %d elements, want %d (one placeholder per unresolved member)", n, existing+2)
		}
	})

	t.Run("row 4: update, member added that resolves -> K + 1 G", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		state := membershipModel(newMembershipSet(t, dn1, dn2), newMemberDetailSet(t, ctx, []string{dn1, dn2}, []string{guid1, guid2}), types.BoolNull())
		plan := membershipModel(newMembershipSet(t, dn1, dn2, dn3), types.SetUnknown(memberDetailObjectType), types.BoolNull())

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{
			known:    map[string]string{dn1: guid1, dn2: guid2},
			guidOnly: []string{guid3},
		})
	})

	t.Run("row 5: update, member removed -> K only, fully known", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		state := membershipModel(newMembershipSet(t, dn1, dn2, dn3), newMemberDetailSet(t, ctx, []string{dn1, dn2, dn3}, []string{guid1, guid2, guid3}), types.BoolNull())
		plan := membershipModel(newMembershipSet(t, dn1, dn2), types.SetUnknown(memberDetailObjectType), types.BoolNull())

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{known: map[string]string{dn1: guid1, dn2: guid2}})
		want := newMemberDetailSet(t, ctx, []string{dn1, dn2}, []string{guid1, guid2})
		if !out.MemberDetails.Equal(want) {
			t.Errorf("member_details = %v, want fully known %v", out.MemberDetails, want)
		}
	})

	t.Run("row 6: no-op -> exactly state.member_details", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		stateDetails := newMemberDetailSet(t, ctx, []string{dn1, dn2}, []string{guid1, guid2})
		state := membershipModel(newMembershipSet(t, guid1, dn2), stateDetails, types.BoolNull())
		// The framework proposes the prior-state value for an unchanged
		// computed attribute.
		plan := membershipModel(newMembershipSet(t, guid1, dn2), stateDetails, types.BoolNull())

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		if !out.MemberDetails.Equal(stateDetails) {
			t.Errorf("member_details = %v, want exactly state %v", out.MemberDetails, stateDetails)
		}
	})

	t.Run("row 7: no-op with a permanently missing member (ignore-missing) -> exactly state, no placeholder", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		stateDetails := newMemberDetailSet(t, ctx, []string{dn1, dn2}, []string{guid1, guid2})
		state := membershipModel(newMembershipSet(t, dn1, dn2, dnMissing1), stateDetails, ignoreMissing)
		plan := membershipModel(newMembershipSet(t, dn1, dn2, dnMissing1), stateDetails, ignoreMissing)

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		if !hasWarningSummary(resp.Diagnostics, "Member could not be resolved") {
			t.Errorf("expected the missing member to still be reported as a warning, got %v", resp.Diagnostics)
		}
		if !out.MemberDetails.Equal(stateDetails) {
			t.Errorf("member_details = %v, want exactly state %v (no diff on every plan)", out.MemberDetails, stateDetails)
		}
	})

	t.Run("row 7b: ignore_missing_members changed vs state -> not exempt, K + P", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		stateDetails := newMemberDetailSet(t, ctx, []string{dn1}, []string{guid1})
		state := membershipModel(newMembershipSet(t, dn1, dnMissing1), stateDetails, types.BoolNull())
		plan := membershipModel(newMembershipSet(t, dn1, dnMissing1), stateDetails, ignoreMissing)

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{known: map[string]string{dn1: guid1}, placeholders: 1})
	})

	t.Run("row 8: drift, out-of-band member in state not configured -> K only (drifted element removed)", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		stateDetails := newMemberDetailSet(t, ctx, []string{dn1, dn2, dnDrift}, []string{guid1, guid2, guidDrift})
		state := membershipModel(newMembershipSet(t, dn1, dn2), stateDetails, types.BoolNull())
		plan := membershipModel(newMembershipSet(t, dn1, dn2), stateDetails, types.BoolNull())

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{known: map[string]string{dn1: guid1, dn2: guid2}})
	})

	t.Run("row 8b: drift, configured member removed out-of-band -> K + G (re-added), not exempt", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		stateDetails := newMemberDetailSet(t, ctx, []string{dn1}, []string{guid1})
		state := membershipModel(newMembershipSet(t, dn1, dn2), stateDetails, types.BoolNull())
		plan := membershipModel(newMembershipSet(t, dn1, dn2), stateDetails, types.BoolNull())

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{known: map[string]string{dn1: guid1}, guidOnly: []string{guid2}})
	})

	t.Run("row 9: case K uses the state DN when the fresh DN differs (rename)", func(t *testing.T) {
		const dnRenamed = "CN=Member1Renamed,OU=Users,DC=example,DC=com"
		cm := ldapclient.NewCacheManager()
		seedMembershipCache(t, cm, dnRenamed, guid1) // AD now reports the new DN
		seedMembershipCache(t, cm, dn2, guid2)
		r := newTestGroupMembershipResource(cm)

		state := membershipModel(newMembershipSet(t, guid1), newMemberDetailSet(t, ctx, []string{dn1}, []string{guid1}), types.BoolNull())
		plan := membershipModel(newMembershipSet(t, guid1, guid2), types.SetUnknown(memberDetailObjectType), types.BoolNull())

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{
			known:    map[string]string{dn1: guid1}, // state DN, not dnRenamed
			guidOnly: []string{guid2},
		})
	})

	t.Run("row 10: two unresolved members -> 2 distinct placeholders survive the round-trip", func(t *testing.T) {
		// One resolvable member is included so the all-members-failed
		// safety net does not fire.
		r := newTestGroupMembershipResource(seeded(t))
		state := membershipModel(newMembershipSet(t, dn1), newMemberDetailSet(t, ctx, []string{dn1}, []string{guid1}), ignoreMissing)
		plan := membershipModel(newMembershipSet(t, dn1, dnMissing1, dnMissing2), types.SetUnknown(memberDetailObjectType), ignoreMissing)

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		// runMembershipModifyPlan round-trips through tfsdk.Plan Set/Get.
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{known: map[string]string{dn1: guid1}, placeholders: 2})
		if n := len(out.MemberDetails.Elements()); n != 3 {
			t.Errorf("planned member_details has %d elements, want 3", n)
		}
	})

	t.Run("row 11: two identifiers for the same object, not in state -> one G; final result shrinks compatibly", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		plan := membershipModel(newMembershipSet(t, dn1, guid1), types.SetUnknown(memberDetailObjectType), types.BoolNull())
		plan.ID = types.StringUnknown()

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertClassifiedDetails(t, out.MemberDetails, classifiedDetails{guidOnly: []string{guid1}})
		assertFinalPlanCompatible(t, out.MemberDetails, newMemberDetailSetOf(t, knownDetail(t, dn1, guid1)))
	})

	t.Run("row 12: member resolving without objectGUID is an error in plan and write, even with ignore_missing_members", func(t *testing.T) {
		const dnNoGUID = "CN=NoGUID,OU=Users,DC=example,DC=com"
		for _, ignore := range []types.Bool{types.BoolNull(), types.BoolValue(true)} {
			cm := ldapclient.NewCacheManager()
			seedMembershipCache(t, cm, dnNoGUID, "")
			r := newTestGroupMembershipResource(cm)
			plan := membershipModel(newMembershipSet(t, dnNoGUID), types.SetUnknown(memberDetailObjectType), ignore)

			_, planResp := runMembershipModifyPlan(t, ctx, r, plan, nil)
			_, _, _, writeDiags := r.resolveMembersForWriteFallback(ctx, plan)
			for name, diags := range map[string]diag.Diagnostics{"plan": planResp.Diagnostics, "write": writeDiags} {
				errs := diags.Errors()
				if len(errs) == 0 || errs[0].Summary() != "Member objectGUID could not be read" ||
					!strings.Contains(errs[0].Detail(), dnNoGUID) || !strings.Contains(errs[0].Detail(), "objectGUID") {
					t.Errorf("%s (ignore_missing_members=%v): want an objectGUID error naming the member, got %v", name, ignore, diags)
				}
			}
		}
	})

	t.Run("row 15: strict mode, one unresolved member -> plan error", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		plan := membershipModel(newMembershipSet(t, dn1, dnMissing1), types.SetUnknown(memberDetailObjectType), types.BoolValue(false))

		_, resp := runMembershipModifyPlan(t, ctx, r, plan, nil)
		if !resp.Diagnostics.HasError() {
			t.Fatalf("expected a plan error in strict mode, got %v", resp.Diagnostics)
		}
		found := false
		for _, d := range resp.Diagnostics.Errors() {
			if d.Summary() == "Member could not be resolved" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a 'Member could not be resolved' error, got %v", resp.Diagnostics.Errors())
		}
	})

	t.Run("row 15b: ignore-missing, every member unresolved -> safety-net error", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		plan := membershipModel(newMembershipSet(t, dnMissing1, dnMissing2), types.SetUnknown(memberDetailObjectType), ignoreMissing)

		_, resp := runMembershipModifyPlan(t, ctx, r, plan, nil)
		if !resp.Diagnostics.HasError() {
			t.Fatalf("expected the all-members-failed safety net error, got %v", resp.Diagnostics)
		}
	})

	t.Run("row 16: members null -> member_details null", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		plan := membershipModel(types.SetNull(types.StringType), types.SetUnknown(memberDetailObjectType), types.BoolNull())

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		if !out.MemberDetails.IsNull() {
			t.Errorf("member_details = %v, want null", out.MemberDetails)
		}
	})

	t.Run("row 16: members empty -> member_details known empty", func(t *testing.T) {
		r := newTestGroupMembershipResource(seeded(t))
		state := membershipModel(newMembershipSet(t, dn1), newMemberDetailSet(t, ctx, []string{dn1}, []string{guid1}), types.BoolNull())
		plan := membershipModel(newMembershipSet(t), types.SetUnknown(memberDetailObjectType), types.BoolNull())

		out, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		if out.MemberDetails.IsNull() || out.MemberDetails.IsUnknown() || len(out.MemberDetails.Elements()) != 0 {
			t.Errorf("member_details = %v, want known empty", out.MemberDetails)
		}
	})
}

// pair is a DN and its objectGUID, for seeding the cache manager.
type pair struct{ dn, guid string }

// TestGroupMembershipResource_ModifyPlanReplanCompatible covers rows 13 and
// 14: the apply-time re-plan (same prior state, dependencies now applied)
// must be compatible with the original plan.
func TestGroupMembershipResource_ModifyPlanReplanCompatible(t *testing.T) {
	ctx := t.Context()

	const (
		dn1   = "CN=Member1,OU=Users,DC=example,DC=com"
		dn2   = "CN=Member2,OU=Users,DC=example,DC=com"
		guid1 = "11111111-1111-1111-1111-111111111111"
		guid2 = "22222222-2222-2222-2222-222222222222"

		dnNew1   = "CN=CreatedInSameApply1,OU=Groups,DC=example,DC=com"
		dnNew2   = "CN=CreatedInSameApply2,OU=Groups,DC=example,DC=com"
		guidNew1 = "aaaaaaaa-0000-0000-0000-000000000001"
		guidNew2 = "aaaaaaaa-0000-0000-0000-000000000002"
	)

	ignoreMissing := types.BoolValue(true)
	unknownDetails := types.SetUnknown(memberDetailObjectType)

	tests := []struct {
		name string
		seed []pair // known when planning
		late []pair // appear before the re-plan (dependencies applied)
		// build returns the plan and prior state (nil on create).
		build func(t *testing.T) (plan, state *GroupMembershipResourceModel)
	}{
		{
			name: "row 13: members created in the same apply, referenced by known DN (update)",
			seed: []pair{{dn1, guid1}, {dn2, guid2}},
			late: []pair{{dnNew1, guidNew1}, {dnNew2, guidNew2}},
			build: func(t *testing.T) (*GroupMembershipResourceModel, *GroupMembershipResourceModel) {
				state := membershipModel(newMembershipSet(t, dn1, dn2), newMemberDetailSet(t, ctx, []string{dn1, dn2}, []string{guid1, guid2}), ignoreMissing)
				return membershipModel(newMembershipSet(t, dn1, dn2, dnNew1, dnNew2), unknownDetails, ignoreMissing), state
			},
		},
		{
			name: "row 13: members created in the same apply, referenced by known DN (create)",
			seed: []pair{{dn1, guid1}},
			late: []pair{{dnNew1, guidNew1}},
			build: func(t *testing.T) (*GroupMembershipResourceModel, *GroupMembershipResourceModel) {
				plan := membershipModel(newMembershipSet(t, dn1, dnNew1), unknownDetails, ignoreMissing)
				plan.ID = types.StringUnknown()
				return plan, nil
			},
		},
		{
			// Prior state has {dn1, ""} (GUID lookup failed in Read): planned as
			// G, which survives member 1 being renamed before the re-plan.
			name: "empty prior id healed, member renamed in the same apply, referenced by GUID",
			seed: []pair{{dn1, guid1}},
			late: []pair{{"CN=Member1Renamed,OU=Users,DC=example,DC=com", guid1}},
			build: func(t *testing.T) (*GroupMembershipResourceModel, *GroupMembershipResourceModel) {
				state := membershipModel(newMembershipSet(t, guid1), newMemberDetailSet(t, ctx, []string{dn1}, []string{""}), types.BoolNull())
				return membershipModel(newMembershipSet(t, guid1), unknownDetails, types.BoolNull()), state
			},
		},
		{
			// The sibling ad_group resource renames member 1 during apply.
			name: "row 14: member renamed in the same apply, referenced by GUID",
			seed: []pair{{dn1, guid1}, {dn2, guid2}},
			late: []pair{{"CN=Member1Renamed,OU=Users,DC=example,DC=com", guid1}},
			build: func(t *testing.T) (*GroupMembershipResourceModel, *GroupMembershipResourceModel) {
				state := membershipModel(newMembershipSet(t, guid1), newMemberDetailSet(t, ctx, []string{dn1}, []string{guid1}), types.BoolNull())
				return membershipModel(newMembershipSet(t, guid1, guid2), unknownDetails, types.BoolNull()), state
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm := ldapclient.NewCacheManager()
			for _, p := range tc.seed {
				seedMembershipCache(t, cm, p.dn, p.guid)
			}
			r := newTestGroupMembershipResource(cm)
			plan, state := tc.build(t)

			plan1, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
			if resp.Diagnostics.HasError() {
				t.Fatalf("plan: unexpected error: %v", resp.Diagnostics.Errors())
			}

			for _, p := range tc.late {
				seedMembershipCache(t, cm, p.dn, p.guid)
			}

			plan2, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
			if resp.Diagnostics.HasError() {
				t.Fatalf("re-plan: unexpected error: %v", resp.Diagnostics.Errors())
			}

			assertFinalPlanCompatible(t, plan1.MemberDetails, plan2.MemberDetails)
		})
	}
}

// TestGroupMembershipResource_ModifyPlanHealsEmptyPriorID covers review
// finding 2: Read stores {dn, id=""} when a member's GUID lookup fails
// transiently; on the next plan the same member resolves to a real GUID.
//
// Chosen behaviour: the member is planned as case G, {dn: unknown, g}, whether
// or not its DN still matches the state DN. That is a one-time healing Update
// (id ""->g) rather than a no-op, because (a) keeping the state's {dn, ""}
// would be unwritable: the apply result {dn, g} would not match a known planned
// {dn, ""}; (b) anchoring {dn_state, g} would not survive the member being
// renamed before the apply-time re-plan, whereas {unknown, g} correlates with
// the result by GUID whatever the DN; and (c) after apply and refresh, the next
// plan is a no-op.
func TestGroupMembershipResource_ModifyPlanHealsEmptyPriorID(t *testing.T) {
	ctx := t.Context()

	const (
		dn1       = "CN=Member1,OU=Users,DC=example,DC=com"
		dn1Rename = "CN=Member1Renamed,OU=Users,DC=example,DC=com"
		dn2       = "CN=Member2,OU=Users,DC=example,DC=com"
		guid1     = "11111111-1111-1111-1111-111111111111"
		guid2     = "22222222-2222-2222-2222-222222222222"
	)

	emptyIDState := func(t *testing.T, members ...string) *GroupMembershipResourceModel {
		return membershipModel(newMembershipSet(t, members...),
			newMemberDetailSetOf(t, knownDetail(t, dn1, "")), types.BoolNull())
	}

	tests := []struct {
		name    string
		seed    pair
		members []string
	}{
		{"prior id empty + fresh GUID + DN match -> G", pair{dn1, guid1}, []string{dn1}},
		{"prior id empty + fresh GUID + DN differs (rename) -> G", pair{dn1Rename, guid1}, []string{guid1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm := ldapclient.NewCacheManager()
			seedMembershipCache(t, cm, tc.seed.dn, tc.seed.guid)
			r := newTestGroupMembershipResource(cm)

			state := emptyIDState(t, dn1)
			plan := membershipModel(newMembershipSet(t, tc.members...), types.SetUnknown(memberDetailObjectType), types.BoolNull())

			got, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
			}
			assertClassifiedDetails(t, got.MemberDetails, classifiedDetails{guidOnly: []string{guid1}})
			if got.MemberDetails.Equal(state.MemberDetails) {
				t.Errorf("member_details planned as prior state; the empty id must be healed")
			}
		})
	}

	t.Run("convergence: plan, apply result, refresh, re-plan is a no-op", func(t *testing.T) {
		cm := ldapclient.NewCacheManager()
		seedMembershipCache(t, cm, dn1, guid1)
		seedMembershipCache(t, cm, dn2, guid2)
		r := newTestGroupMembershipResource(cm)

		// Heal alongside an added member, so the write path is exercised too.
		state := emptyIDState(t, dn1)
		plan := membershipModel(newMembershipSet(t, dn1, dn2), types.SetUnknown(memberDetailObjectType), types.BoolNull())

		plan1, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("plan: unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertClassifiedDetails(t, plan1.MemberDetails, classifiedDetails{guidOnly: []string{guid1, guid2}})

		// Apply-time re-plan with the same prior state is compatible.
		plan2, resp := runMembershipModifyPlan(t, ctx, r, plan, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("re-plan: unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertFinalPlanCompatible(t, plan1.MemberDetails, plan2.MemberDetails)

		// The write path's result is compatible with the plan, also when
		// member 1 was renamed earlier in the same apply.
		apply := func(dn1Now string) types.Set {
			details, diags := reconcileMemberDetailsWithPlan(ctx, plan1.MemberDetails,
				[]string{dn1Now, dn2}, map[string]string{dn1Now: guid1, dn2: guid2})
			if diags.HasError() {
				t.Fatalf("reconcile: %v", diags.Errors())
			}
			applied, setDiags := types.SetValueFrom(ctx, memberDetailObjectType, details)
			if setDiags.HasError() {
				t.Fatalf("applied set: %v", setDiags.Errors())
			}
			assertFinalPlanCompatible(t, plan1.MemberDetails, applied)
			return applied
		}
		applied := apply(dn1)
		apply(dn1Rename)

		// New state = applied result; the next plan is a no-op.
		newState := membershipModel(plan.Members, applied, types.BoolNull())
		plan3, resp := runMembershipModifyPlan(t, ctx, r, plan, newState)
		if resp.Diagnostics.HasError() {
			t.Fatalf("converged plan: unexpected error: %v", resp.Diagnostics.Errors())
		}
		if !plan3.MemberDetails.Equal(applied) {
			t.Errorf("converged plan member_details = %v, want unchanged %v", plan3.MemberDetails, applied)
		}
	})

	t.Run("helper: empty-id prior is never anchored by a resolved GUID; non-empty prior ids unaffected", func(t *testing.T) {
		prior := []MemberDetailModel{
			{DN: types.StringValue(dn1), ID: types.StringValue("")},
			{DN: types.StringValue(dn2), ID: types.StringValue(guid2)},
		}
		planned := buildPlannedMemberDetails(
			[]string{dn1, dn2},
			map[string]ldapclient.ResolvedIdentifier{
				dn1: {DN: strings.ToUpper(dn1), GUID: guid1},
				dn2: {DN: dn2, GUID: guid2},
			},
			nil, prior,
		)
		if len(planned.guidOnly) != 1 || planned.guidOnly[0] != guid1 || len(planned.known) != 1 || planned.known[0].DN.ValueString() != dn2 {
			t.Fatalf("planned = %+v, want G for member 1 and K for member 2", planned)
		}
	})
}

// TestGroupMembershipResource_BuildPlannedMemberDetails exercises the
// per-element classification helper directly, independent of ModifyPlan's
// resolution and safety nets.
func TestGroupMembershipResource_BuildPlannedMemberDetails(t *testing.T) {
	ctx := t.Context()

	const (
		dn1   = "CN=Member1,OU=Users,DC=example,DC=com"
		guid1 = "11111111-1111-1111-1111-111111111111"
		dn2   = "CN=Member2,OU=Users,DC=example,DC=com"
		guid2 = "22222222-2222-2222-2222-222222222222"
	)

	// roundTrip pushes member_details through a tfsdk.Plan Set/Get, as the
	// framework does with ModifyPlan's response.
	roundTrip := func(t *testing.T, details types.Set) types.Set {
		t.Helper()
		r := newTestGroupMembershipResource(ldapclient.NewCacheManager())
		schemaResp := &resource.SchemaResponse{}
		r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
		plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)}
		in := membershipModel(newMembershipSet(t, "x"), details, types.BoolNull())
		if diags := plan.Set(ctx, in); diags.HasError() {
			t.Fatalf("plan.Set: %v", diags.Errors())
		}
		var out GroupMembershipResourceModel
		if diags := plan.Get(ctx, &out); diags.HasError() {
			t.Fatalf("plan.Get: %v", diags.Errors())
		}
		return out.MemberDetails
	}

	t.Run("row 10: exactly two unresolved members -> 2 placeholders, count 2 after round-trip", func(t *testing.T) {
		planned := buildPlannedMemberDetails(
			[]string{"CN=Missing1,DC=example,DC=com", "CN=Missing2,DC=example,DC=com"},
			map[string]ldapclient.ResolvedIdentifier{},
			map[string]error{"CN=Missing1,DC=example,DC=com": fmt.Errorf("not found"), "CN=Missing2,DC=example,DC=com": fmt.Errorf("not found")},
			nil,
		)
		set, diags := planned.toSet()
		if diags.HasError() {
			t.Fatalf("toSet: %v", diags.Errors())
		}
		got := roundTrip(t, set)
		assertClassifiedDetails(t, got, classifiedDetails{placeholders: 2})
		if n := len(got.Elements()); n != 2 {
			t.Errorf("member_details has %d elements after round-trip, want 2", n)
		}
	})

	t.Run("duplicate identifiers for one in-state object -> one K element", func(t *testing.T) {
		prior := []MemberDetailModel{{DN: types.StringValue(dn1), ID: types.StringValue(guid1)}}
		planned := buildPlannedMemberDetails(
			[]string{dn1, guid1},
			map[string]ldapclient.ResolvedIdentifier{dn1: {DN: dn1, GUID: guid1}, guid1: {DN: dn1, GUID: guid1}},
			nil,
			prior,
		)
		set, diags := planned.toSet()
		if diags.HasError() {
			t.Fatalf("toSet: %v", diags.Errors())
		}
		assertClassifiedDetails(t, roundTrip(t, set), classifiedDetails{known: map[string]string{dn1: guid1}})
	})

	t.Run("GUID matched case-insensitively against prior state -> K", func(t *testing.T) {
		prior := []MemberDetailModel{{DN: types.StringValue(dn1), ID: types.StringValue(guid1)}}
		planned := buildPlannedMemberDetails(
			[]string{dn1},
			map[string]ldapclient.ResolvedIdentifier{dn1: {DN: dn1, GUID: strings.ToUpper(guid1)}},
			nil,
			prior,
		)
		if len(planned.known) != 1 || len(planned.guidOnly) != 0 {
			t.Errorf("planned = %+v, want one K element", planned)
		}
	})

	t.Run("whitespace-only identifier (in neither map) -> no element", func(t *testing.T) {
		planned := buildPlannedMemberDetails(
			[]string{"   ", dn2},
			map[string]ldapclient.ResolvedIdentifier{dn2: {DN: dn2, GUID: guid2}},
			map[string]error{},
			nil,
		)
		set, diags := planned.toSet()
		if diags.HasError() {
			t.Fatalf("toSet: %v", diags.Errors())
		}
		assertClassifiedDetails(t, roundTrip(t, set), classifiedDetails{guidOnly: []string{guid2}})
	})

	t.Run("no-op exemption requires no G and K == prior", func(t *testing.T) {
		priorSet := newMemberDetailSet(t, ctx, []string{dn1}, []string{guid1})
		prior := []MemberDetailModel{{DN: types.StringValue(dn1), ID: types.StringValue(guid1)}}

		cases := []struct {
			name    string
			planned plannedMemberDetails
			want    bool
		}{
			{"K == prior", plannedMemberDetails{known: prior}, true},
			{"K == prior + unresolved P", plannedMemberDetails{known: prior, unresolved: 1}, true},
			{"K == prior + G", plannedMemberDetails{known: prior, guidOnly: []string{guid2}}, false},
			{"K subset of prior", plannedMemberDetails{}, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, diags := tc.planned.isNoOpAgainst(ctx, priorSet)
				if diags.HasError() {
					t.Fatalf("isNoOpAgainst: %v", diags.Errors())
				}
				if got != tc.want {
					t.Errorf("isNoOpAgainst = %v, want %v", got, tc.want)
				}
			})
		}
	})
}

func TestReportMemberFailures_ValidationIsAlwaysFatal(t *testing.T) {
	notFound := ldapclient.NewNotFoundError("resolve", "no such object")
	wrongDomain := &ldapclient.LDAPError{
		Operation: "normalize",
		Category:  ldapclient.ErrorCategoryValidation,
		Message:   "domain OTHER does not match",
	}

	tests := []struct {
		name         string
		failures     map[string]error
		ignore       bool
		wantFatal    bool
		wantErrors   int
		wantWarnings int
	}{
		{"ignore: not-found stays a warning", map[string]error{"a": notFound}, true, false, 0, 1},
		{"ignore: mixed aborts on validation", map[string]error{"a": notFound, "OTHER\\b": wrongDomain}, true, true, 1, 1},
		{"ignore: validation alone is an error", map[string]error{"OTHER\\b": wrongDomain}, true, true, 1, 0},
		{"strict: everything is an error", map[string]error{"a": notFound, "OTHER\\b": wrongDomain}, false, true, 2, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			diags, fatal := reportMemberFailures(context.Background(), tc.failures, tc.ignore)
			if fatal != tc.wantFatal || diags.ErrorsCount() != tc.wantErrors || diags.WarningsCount() != tc.wantWarnings {
				t.Fatalf("fatal=%v errors=%d warnings=%d, want %v/%d/%d: %v",
					fatal, diags.ErrorsCount(), diags.WarningsCount(), tc.wantFatal, tc.wantErrors, tc.wantWarnings, diags)
			}
		})
	}
}
