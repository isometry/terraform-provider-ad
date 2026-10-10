package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// Read and ImportState build member_details from the same single
// GetCurrentMembers snapshot ModifyPlan uses for member identity, so a member
// outside the resolver's base DN carries its GUID in state and the following
// plan is a no-op.

const (
	snapGroupDN = "CN=Group,OU=Groups,DC=example,DC=com"

	// A member the base-DN-scoped resolver cannot find (another domain).
	snapDNExt   = "CN=Ext,OU=Users,DC=other,DC=org"
	snapGUIDExt = "77777777-7777-7777-7777-777777777777"
)

var snapExt = liveObj{snapDNExt, snapGUIDExt, ""}

func snapServe(objs ...liveObj) func(*stubMembershipClient) {
	return allObjsGroupValues(objs...)
}

func newSnapResource(t *testing.T, setup func(*stubMembershipClient)) (*GroupMembershipResource, *stubMembershipClient) {
	t.Helper()
	r := newTestGroupMembershipResource(ldapclient.NewCacheManager())
	stub := &stubMembershipClient{}
	if setup != nil {
		setup(stub)
	}
	r.client = stub
	return r, stub
}

func snapState(t *testing.T, members []string, details types.Set) *GroupMembershipResourceModel {
	t.Helper()
	return &GroupMembershipResourceModel{
		ID:            types.StringValue(liveGroupID),
		GroupID:       types.StringValue(liveGroupID),
		Members:       newMembershipSet(t, members...),
		MemberDetails: details,
	}
}

func snapSchemaState(t *testing.T, ctx context.Context, r *GroupMembershipResource, m *GroupMembershipResourceModel) tfsdk.State {
	t.Helper()
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	st := tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)}
	if m != nil {
		if d := st.Set(ctx, m); d.HasError() {
			t.Fatalf("building state: %v", d.Errors())
		}
	}
	return st
}

// runRead drives Read; the returned model is nil when the resource was removed.
func runRead(t *testing.T, ctx context.Context, r *GroupMembershipResource, in *GroupMembershipResourceModel) (*GroupMembershipResourceModel, *resource.ReadResponse) {
	t.Helper()
	st := snapSchemaState(t, ctx, r, in)
	resp := &resource.ReadResponse{State: st}
	r.Read(ctx, resource.ReadRequest{State: st}, resp)
	if resp.State.Raw.IsNull() {
		return nil, resp
	}
	var out GroupMembershipResourceModel
	if d := resp.State.Get(ctx, &out); d.HasError() {
		t.Fatalf("reading resulting state: %v", d.Errors())
	}
	return &out, resp
}

func runImport(t *testing.T, ctx context.Context, r *GroupMembershipResource) (*GroupMembershipResourceModel, *resource.ImportStateResponse) {
	t.Helper()
	st := snapSchemaState(t, ctx, r, nil)
	resp := &resource.ImportStateResponse{State: st}
	r.ImportState(ctx, resource.ImportStateRequest{ID: snapGroupDN}, resp)
	if resp.Diagnostics.HasError() {
		return nil, resp
	}
	var out GroupMembershipResourceModel
	if d := resp.State.Get(ctx, &out); d.HasError() {
		t.Fatalf("reading imported state: %v", d.Errors())
	}
	return &out, resp
}

func importSetup(inner func(*stubMembershipClient)) func(*stubMembershipClient) {
	return func(s *stubMembershipClient) {
		s.resolvable = map[string]stubObject{snapGroupDN: {dn: snapGroupDN, guid: liveGroupID}}
		if inner != nil {
			inner(s)
		}
	}
}

func detailsOf(t *testing.T, ctx context.Context, m *GroupMembershipResourceModel) map[string]string {
	t.Helper()
	if m.MemberDetails.IsNull() || m.MemberDetails.IsUnknown() {
		t.Fatalf("member_details is null/unknown: %v", m.MemberDetails)
	}
	return extractMemberDetails(t, ctx, m.MemberDetails)
}

// Read builds member_details from one snapshot (no resolver or legacy reads),
// leaves the configured `members` untouched, and keeps an empty id for a
// member whose snapshot value carries no GUID.
func TestGroupMembershipRead_Snapshot(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*stubMembershipClient)
		configured []string
		want       map[string]string
	}{
		{
			name:       "members outside the base DN carry their GUID",
			setup:      snapServe(liveA, liveB, snapExt),
			configured: []string{liveDNA},
			want:       map[string]string{liveDNA: liveGUIDA, liveDNB: liveGUIDB, snapDNExt: snapGUIDExt},
		},
		{
			name:       "members are not AD's DNs",
			setup:      snapServe(liveA, liveB),
			configured: []string{liveGUIDA, "upn@example.com"},
			want:       map[string]string{liveDNA: liveGUIDA, liveDNB: liveGUIDB},
		},
		{
			name: "snapshot value without GUID keeps empty id",
			setup: func(s *stubMembershipClient) {
				s.serveGroup = true
				s.groupValues = []string{liveA.groupValue(), "<SID=" + liveSIDB + ">;" + liveDNB}
			},
			want: map[string]string{liveDNA: liveGUIDA, liveDNB: ""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			r, stub := newSnapResource(t, tc.setup)

			out, resp := runRead(t, ctx, r, snapState(t, tc.configured, types.SetNull(memberDetailObjectType)))
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
			}
			if got := detailsOf(t, ctx, out); !maps.Equal(got, tc.want) {
				t.Fatalf("member_details = %v, want %v", got, tc.want)
			}
			wantMembers := slices.Clone(tc.configured)
			sort.Strings(wantMembers)
			if got := extractSortedMembers(t, ctx, out.Members); !slices.Equal(got, wantMembers) {
				t.Fatalf("members mutated: got %v want %v", got, wantMembers)
			}
			reads, queries := stub.counts()
			if reads != 1 || len(queries) != 0 || stub.legacyReads != 0 {
				t.Fatalf("want 1 snapshot read, 0 resolver searches, 0 legacy reads; got %d, %v, %d", reads, queries, stub.legacyReads)
			}
		})
	}
}

func TestGroupMembershipRead_EmptyGroup(t *testing.T) {
	ctx := t.Context()
	r, _ := newSnapResource(t, snapServe())

	out, resp := runRead(t, ctx, r, snapState(t, nil, newMemberDetailSet(t, ctx, []string{liveDNA}, []string{liveGUIDA})))
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if out.MemberDetails.IsNull() || out.MemberDetails.IsUnknown() || len(out.MemberDetails.Elements()) != 0 {
		t.Fatalf("want empty non-null set, got %v", out.MemberDetails)
	}
}

func TestGroupMembershipRead_DeterministicOrdering(t *testing.T) {
	ctx := t.Context()
	var first []string
	for i, order := range [][]liveObj{{liveC, liveA, liveB}, {liveB, liveC, liveA}} {
		r, _ := newSnapResource(t, snapServe(order...))
		out, resp := runRead(t, ctx, r, snapState(t, nil, types.SetNull(memberDetailObjectType)))
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
		}
		view, err := r.loadMembershipView(ctx, mustManager(t, ctx, r), liveGroupID)
		if err != nil {
			t.Fatal(err)
		}
		if !sort.StringsAreSorted(view.dns) {
			t.Fatalf("dns not sorted: %v", view.dns)
		}
		if i == 0 {
			first = view.dns
		} else if !slices.Equal(first, view.dns) {
			t.Fatalf("ordering depends on AD order: %v vs %v", first, view.dns)
		}
		_ = out
	}
}

func mustManager(t *testing.T, ctx context.Context, r *GroupMembershipResource) *ldapclient.GroupMembershipManager {
	t.Helper()
	m, err := r.getMembershipManager(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A missing group removes the resource, whichever reader notices it.
func TestGroupMembershipRead_GroupNotFoundRemovesResource(t *testing.T) {
	tests := map[string]func(*stubMembershipClient){
		"snapshot read": func(s *stubMembershipClient) { s.groupNotFound = true },
		"fallback read": func(s *stubMembershipClient) {
			s.groupErr = critExtErr()
			s.legacyNotFound = true
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			r, _ := newSnapResource(t, setup)
			out, resp := runRead(t, t.Context(), r, snapState(t, []string{liveDNA}, types.SetNull(memberDetailObjectType)))
			if resp.Diagnostics.HasError() || out != nil {
				t.Fatalf("want removal; out=%v diags=%v", out, resp.Diagnostics)
			}
		})
	}
}

// critExtErr is what a server lacking the extended-DN control returns.
func critExtErr() error {
	return ldap.NewError(ldap.LDAPResultUnavailableCriticalExtension, errors.New("critical extension is unavailable"))
}

// Only unavailableCriticalExtension (bare or wrapped) triggers the per-member
// fallback.
func TestGroupMembershipRead_CriticalExtensionFallsBack(t *testing.T) {
	for name, groupErr := range map[string]error{
		"bare":    critExtErr(),
		"wrapped": fmt.Errorf("pool: %w", ldapclient.NewLDAPError("search", critExtErr())),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			r, stub := newSnapResource(t, func(s *stubMembershipClient) {
				s.groupErr = groupErr
				s.legacyServe = true
				s.legacyMembers = []string{liveDNB, liveDNA}
			})
			seedMembershipCache(t, r.cacheManager, liveDNA, liveGUIDA)
			seedMembershipCache(t, r.cacheManager, liveDNB, liveGUIDB)

			out, resp := runRead(t, ctx, r, snapState(t, []string{liveDNA}, types.SetNull(memberDetailObjectType)))
			if resp.Diagnostics.HasError() {
				t.Fatalf("fallback must not error: %v", resp.Diagnostics)
			}
			got := detailsOf(t, ctx, out)
			if len(got) != 2 || got[liveDNA] != liveGUIDA || got[liveDNB] != liveGUIDB {
				t.Fatalf("member_details = %v", got)
			}
			if stub.legacyReads != 1 {
				t.Fatalf("legacyReads = %d, want 1", stub.legacyReads)
			}
		})
	}
}

// Every other snapshot failure is an error diagnostic: exactly one group
// read, no legacy read, no resolver searches, and the resource is neither
// removed nor modified. This includes generic not-found-ish text ("No Such
// Object", "does not exist"), which must never remove the resource.
func TestGroupMembershipRead_OtherSnapshotErrorsSurface(t *testing.T) {
	cases := map[string]error{
		"search error":           errors.New("search failed"),
		"timeout":                ldap.NewError(ldap.LDAPResultTimeLimitExceeded, errors.New("time limit exceeded")),
		"context canceled":       context.Canceled,
		"deadline exceeded":      context.DeadlineExceeded,
		"insufficient access":    ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied")),
		"transient disconnect":   errors.New("connection reset"),
		"ldap no such object":    ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("No Such Object")),
		"generic no such obj":    errors.New("No Such Object"),
		"generic does not exist": errors.New("object does not exist"),
	}
	for name, groupErr := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			r, stub := newSnapResource(t, func(s *stubMembershipClient) {
				s.groupErr = groupErr
				s.legacyServe = true
				s.legacyMembers = []string{liveDNA}
			})
			in := snapState(t, []string{liveDNA}, newMemberDetailSet(t, ctx, []string{liveDNA}, []string{liveGUIDA}))
			st := snapSchemaState(t, ctx, r, in)
			resp := &resource.ReadResponse{State: st}
			r.Read(ctx, resource.ReadRequest{State: st}, resp)

			if !resp.Diagnostics.HasError() {
				t.Fatal("expected an error diagnostic")
			}
			if resp.State.Raw.IsNull() {
				t.Fatal("resource must not be removed from state")
			}
			var out GroupMembershipResourceModel
			if d := resp.State.Get(ctx, &out); d.HasError() {
				t.Fatal(d.Errors())
			}
			if !out.MemberDetails.Equal(in.MemberDetails) || !out.Members.Equal(in.Members) {
				t.Fatalf("state modified: %v", out)
			}
			reads, queries := stub.counts()
			if reads != 1 || stub.legacyReads != 0 || len(queries) != 0 {
				t.Fatalf("want 1 group read, 0 legacy, 0 resolver; got %d, %d, %v", reads, stub.legacyReads, queries)
			}
		})
	}
}

func TestGroupMembershipRead_FallbackHardFailureIsAnError(t *testing.T) {
	for name, legacyErr := range map[string]error{
		"generic":             errors.New("boom again"),
		"no such object":      errors.New("No Such Object"),
		"does not exist":      errors.New("object does not exist"),
		"ldap no such object": ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("No Such Object")),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			r, _ := newSnapResource(t, func(s *stubMembershipClient) {
				s.groupErr = critExtErr()
				s.legacyErr = legacyErr
			})
			in := snapState(t, nil, types.SetNull(memberDetailObjectType))
			st := snapSchemaState(t, ctx, r, in)
			resp := &resource.ReadResponse{State: st}
			r.Read(ctx, resource.ReadRequest{State: st}, resp)
			if !resp.Diagnostics.HasError() {
				t.Fatal("expected an error when the fallback reader fails")
			}
			if resp.State.Raw.IsNull() {
				t.Fatal("resource must not be removed from state")
			}
		})
	}
}

// The genuine "group does not exist" errors from both readers must satisfy
// isGroupNotFoundError (the original narrow check).
func TestIsGroupNotFoundError_GenuineReaderErrors(t *testing.T) {
	ctx := t.Context()
	r, _ := newSnapResource(t, func(s *stubMembershipClient) {
		s.groupNotFound = true
		s.legacyNotFound = true
	})
	m := mustManager(t, ctx, r)

	_, err := m.GetCurrentMembers(liveGroupID)
	if err == nil || !isGroupNotFoundError(err) {
		t.Fatalf("GetCurrentMembers not-found error not classified: %v", err)
	}
	t.Logf("GetCurrentMembers not-found: %T %q", err, err)
	_, err = m.GetGroupMembers(liveGroupID)
	if err == nil || !isGroupNotFoundError(err) {
		t.Fatalf("GetGroupMembers not-found error not classified: %v", err)
	}
	t.Logf("GetGroupMembers not-found: %T %q", err, err)

	for _, generic := range []error{
		errors.New("No Such Object"),
		errors.New("object does not exist"),
		ldapclient.NewLDAPError("search", ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("No Such Object"))),
		fmt.Errorf("wrapped: %w", ldapclient.NewLDAPError("search", errors.New("does not exist"))),
	} {
		if isGroupNotFoundError(generic) {
			t.Fatalf("generic error %q must not count as group-not-found", generic)
		}
	}
}

// Convergence regression: for a member outside the base DN, Read must store
// the GUID plan-time resolution finds, so the plan is a no-op - before and
// after an apply - with no healing update.
func TestGroupMembershipRead_OutOfBaseDNMemberConverges(t *testing.T) {
	ctx := t.Context()
	r, _ := newSnapResource(t, snapServe(liveA, snapExt))

	members := []string{liveDNA, snapDNExt}
	state := snapState(t, members, types.SetNull(memberDetailObjectType))

	for round := 1; round <= 2; round++ {
		read, resp := runRead(t, ctx, r, state)
		if resp.Diagnostics.HasError() {
			t.Fatalf("round %d read: %v", round, resp.Diagnostics)
		}
		if got := detailsOf(t, ctx, read)[snapDNExt]; got != snapGUIDExt {
			t.Fatalf("round %d: Read stored id %q for out-of-base-DN member, want %q", round, got, snapGUIDExt)
		}

		plan := &GroupMembershipResourceModel{
			ID:            read.ID,
			GroupID:       read.GroupID,
			Members:       newMembershipSet(t, members...),
			MemberDetails: types.SetUnknown(memberDetailObjectType),
		}
		planned, presp := runMembershipModifyPlan(t, ctx, r, plan, read)
		if presp.Diagnostics.HasError() {
			t.Fatalf("round %d plan: %v", round, presp.Diagnostics)
		}
		if !planned.MemberDetails.Equal(read.MemberDetails) {
			t.Fatalf("round %d: plan is not a no-op (healing update):\n state: %v\n plan:  %v", round, read.MemberDetails, planned.MemberDetails)
		}
		// "Apply" the plan and go round again.
		state = planned
	}
}

func TestGroupMembershipImportState_Snapshot(t *testing.T) {
	ctx := t.Context()
	r, stub := newSnapResource(t, importSetup(snapServe(liveB, snapExt, liveA)))
	seedMembershipCache(t, r.cacheManager, snapGroupDN, liveGroupID)

	out, resp := runImport(t, ctx, r)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	wantDNs := []string{liveDNA, liveDNB, snapDNExt}
	if got := extractSortedMembers(t, ctx, out.Members); !slices.Equal(got, wantDNs) {
		t.Fatalf("members = %v, want %v", got, wantDNs)
	}
	got := detailsOf(t, ctx, out)
	if got[snapDNExt] != snapGUIDExt || got[liveDNA] != liveGUIDA || got[liveDNB] != liveGUIDB || len(got) != 3 {
		t.Fatalf("member_details = %v", got)
	}
	if stub.legacyReads != 0 {
		t.Fatalf("legacy reads = %d, want 0", stub.legacyReads)
	}
	for _, q := range stub.resolverQueries {
		for _, dn := range wantDNs {
			if q == dn {
				t.Fatalf("member %s was resolved by search; queries: %v", dn, stub.resolverQueries)
			}
		}
	}
}

func TestGroupMembershipImportState_FallsBack(t *testing.T) {
	ctx := t.Context()
	r, stub := newSnapResource(t, importSetup(func(s *stubMembershipClient) {
		s.groupErr = critExtErr()
		s.legacyServe = true
		s.legacyMembers = []string{liveDNB, liveDNA}
	}))
	seedMembershipCache(t, r.cacheManager, snapGroupDN, liveGroupID)
	seedMembershipCache(t, r.cacheManager, liveDNA, liveGUIDA)
	seedMembershipCache(t, r.cacheManager, liveDNB, liveGUIDB)

	out, resp := runImport(t, ctx, r)
	if resp.Diagnostics.HasError() {
		t.Fatalf("fallback must not error: %v", resp.Diagnostics)
	}
	if got := extractSortedMembers(t, ctx, out.Members); !slices.Equal(got, []string{liveDNA, liveDNB}) {
		t.Fatalf("members = %v", got)
	}
	got := detailsOf(t, ctx, out)
	if got[liveDNA] != liveGUIDA || got[liveDNB] != liveGUIDB || len(got) != 2 {
		t.Fatalf("member_details = %v", got)
	}
	if stub.legacyReads != 1 {
		t.Fatalf("legacyReads = %d, want 1", stub.legacyReads)
	}
}

func TestGroupMembershipImportState_EmptyGroup(t *testing.T) {
	ctx := t.Context()
	r, _ := newSnapResource(t, importSetup(snapServe()))
	seedMembershipCache(t, r.cacheManager, snapGroupDN, liveGroupID)

	out, resp := runImport(t, ctx, r)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if out.Members.IsNull() || len(out.Members.Elements()) != 0 || out.MemberDetails.IsNull() || len(out.MemberDetails.Elements()) != 0 {
		t.Fatalf("want empty non-null sets: %v %v", out.Members, out.MemberDetails)
	}
}

func TestGroupMembershipImportState_OtherSnapshotErrorsSurface(t *testing.T) {
	for name, groupErr := range map[string]error{
		"search error":     errors.New("search failed"),
		"context canceled": context.Canceled,
		"timeout":          ldap.NewError(ldap.LDAPResultTimeLimitExceeded, errors.New("time limit")),
		"generic no such":  errors.New("No Such Object"),
		"insufficient":     ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied")),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			r, stub := newSnapResource(t, importSetup(func(s *stubMembershipClient) {
				s.groupErr = groupErr
				s.legacyServe = true
				s.legacyMembers = []string{liveDNA}
			}))
			seedMembershipCache(t, r.cacheManager, snapGroupDN, liveGroupID)
			_, resp := runImport(t, ctx, r)
			if !resp.Diagnostics.HasError() {
				t.Fatal("expected an error diagnostic")
			}
			if reads, _ := stub.counts(); reads != 1 || stub.legacyReads != 0 {
				t.Fatalf("want 1 group read and 0 legacy; got %d, %d", reads, stub.legacyReads)
			}
		})
	}
}
