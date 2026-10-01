package provider

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// Live member matching (readCurrentMembersBestEffort +
// MemberNormalizer.ResolveBatchAgainst) is a pure performance optimisation:
// every scenario below runs the SAME input through the legacy path (group
// read unavailable, DN/GUID/SID identifiers resolved from a pre-seeded cache,
// i.e. plain ResolveBatch) and through the live path (empty cache, group read
// served) and requires identical plans/diagnostics, while asserting how many
// group reads and resolver searches each path performed.

const (
	liveGroupID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	liveDNA   = "CN=A,OU=Users,DC=example,DC=com"
	liveGUIDA = "11111111-1111-1111-1111-111111111111"
	liveSIDA  = "S-1-5-21-1-2-3-1001"

	liveDNB   = "CN=B,OU=Users,DC=example,DC=com"
	liveGUIDB = "22222222-2222-2222-2222-222222222222"
	liveSIDB  = "S-1-5-21-1-2-3-1002"

	liveDNC   = "CN=C,OU=Users,DC=example,DC=com"
	liveGUIDC = "33333333-3333-3333-3333-333333333333"
	liveSIDC  = "S-1-5-21-1-2-3-1003"

	liveDNNew   = "CN=New,OU=Users,DC=example,DC=com"
	liveGUIDNew = "44444444-4444-4444-4444-444444444444"

	liveUPNKey  = "(userPrincipalName=upn@example.com)"
	liveSAMKey  = "(sAMAccountName=sam)"
	liveUPNOnly = "upn@example.com"
	liveSAMOnly = "DOMAIN\\sam"
	liveDNUPN   = "CN=UPNUser,OU=Users,DC=example,DC=com"
	liveGUIDUPN = "55555555-5555-5555-5555-555555555555"
	liveDNSAM   = "CN=SAMUser,OU=Users,DC=example,DC=com"
	liveGUIDSAM = "66666666-6666-6666-6666-666666666666"
)

type liveObj struct{ dn, guid, sid string }

var (
	liveA = liveObj{liveDNA, liveGUIDA, liveSIDA}
	liveB = liveObj{liveDNB, liveGUIDB, liveSIDB}
	liveC = liveObj{liveDNC, liveGUIDC, liveSIDC}
)

func (o liveObj) groupValue() string { return extendedDNValue(o.guid, o.sid, o.dn) }

// defaultResolvable serves the objects only reachable through resolver
// searches (UPN, SAM, and a DN not yet a member).
func defaultResolvable() map[string]stubObject {
	return map[string]stubObject{
		liveUPNKey: {dn: liveDNUPN, guid: liveGUIDUPN},
		liveSAMKey: {dn: liveDNSAM, guid: liveGUIDSAM},
		liveDNNew:  {dn: liveDNNew, guid: liveGUIDNew},
	}
}

type liveWorld struct {
	cacheObjs   []liveObj // seeded in the legacy path's cache
	liveCache   []liveObj // seeded in the live path's cache
	stubSetup   func(*stubMembershipClient)
	members     []string
	state       func(t *testing.T, ctx context.Context) *GroupMembershipResourceModel
	ignoreMissG types.Bool
}

type liveRun struct {
	out        *GroupMembershipResourceModel
	resp       *resource.ModifyPlanResponse
	groupReads int
	resolverQ  []string
}

func (w liveWorld) newResource(t *testing.T, seed []liveObj, setup func(*stubMembershipClient)) (*GroupMembershipResource, *stubMembershipClient) {
	t.Helper()
	cm := ldapclient.NewCacheManager()
	for _, o := range seed {
		if err := cm.Put(&ldapclient.LDAPCacheEntry{DN: o.dn, ObjectGUID: o.guid, ObjectSID: o.sid, Attributes: map[string][]string{}}); err != nil {
			t.Fatalf("seeding cache: %v", err)
		}
	}
	r := newTestGroupMembershipResource(cm)
	stub := &stubMembershipClient{resolvable: defaultResolvable()}
	if setup != nil {
		setup(stub)
	}
	r.client = stub
	return r, stub
}

func (w liveWorld) plan(t *testing.T) *GroupMembershipResourceModel {
	t.Helper()
	ignore := w.ignoreMissG
	if ignore.IsNull() && !ignore.IsUnknown() {
		ignore = types.BoolNull()
	}
	return &GroupMembershipResourceModel{
		ID:                   types.StringValue(liveGroupID),
		GroupID:              types.StringValue(liveGroupID),
		Members:              newMembershipSet(t, w.members...),
		MemberDetails:        types.SetUnknown(memberDetailObjectType),
		IgnoreMissingMembers: ignore,
	}
}

func (w liveWorld) run(t *testing.T, ctx context.Context, live bool) liveRun {
	t.Helper()
	var r *GroupMembershipResource
	var stub *stubMembershipClient
	if live {
		r, stub = w.newResource(t, w.liveCache, w.stubSetup)
	} else {
		// Legacy: the group read is unavailable (default stub error), and
		// DN/GUID/SID identifiers resolve from the cache.
		r, stub = w.newResource(t, w.cacheObjs, nil)
	}
	var state *GroupMembershipResourceModel
	if w.state != nil {
		state = w.state(t, ctx)
	}
	out, resp := runMembershipModifyPlan(t, ctx, r, w.plan(t), state)
	reads, q := stub.counts()
	sort.Strings(q)
	return liveRun{out: out, resp: resp, groupReads: reads, resolverQ: q}
}

func diagStrings(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, fmt.Sprintf("%s|%s|%s", x.Severity(), x.Summary(), x.Detail()))
	}
	sort.Strings(out)
	return out
}

// assertSamePlan requires identical diagnostics and (when no error) identical
// classified member_details.
func assertSamePlan(t *testing.T, old, live liveRun) {
	t.Helper()
	if od, ld := diagStrings(old.resp.Diagnostics), diagStrings(live.resp.Diagnostics); !slices.Equal(od, ld) {
		t.Fatalf("diagnostics differ:\n legacy: %v\n live:   %v", od, ld)
	}
	if old.resp.Diagnostics.HasError() {
		return
	}
	oc := classifyMemberDetails(t, old.out.MemberDetails)
	lc := classifyMemberDetails(t, live.out.MemberDetails)
	assertClassifiedDetails(t, live.out.MemberDetails, oc)
	if len(oc.known) != len(lc.known) {
		t.Fatalf("classification differs: legacy %v live %v", oc, lc)
	}
}

func allObjsGroupValues(objs ...liveObj) func(*stubMembershipClient) {
	return func(s *stubMembershipClient) {
		s.serveGroup = true
		for _, o := range objs {
			s.groupValues = append(s.groupValues, o.groupValue())
		}
	}
}

func TestGroupMembershipLiveMatching_AllDNGUIDSIDZeroResolverSearches(t *testing.T) {
	ctx := t.Context()
	w := liveWorld{
		cacheObjs: []liveObj{liveA, liveB, liveC},
		stubSetup: allObjsGroupValues(liveA, liveB, liveC),
		members:   []string{liveDNA, liveGUIDB, liveSIDC},
	}

	t.Run("create", func(t *testing.T) {
		old, live := w.run(t, ctx, false), w.run(t, ctx, true)
		assertSamePlan(t, old, live)
		if live.resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", live.resp.Diagnostics.Errors())
		}
		if live.groupReads != 1 || len(live.resolverQ) != 0 {
			t.Errorf("live path: groupReads=%d resolverSearches=%v, want 1 and none", live.groupReads, live.resolverQ)
		}
		// Matched members yield AD's live DN + GUID, whatever identifier form was configured.
		got := classifyMemberDetails(t, live.out.MemberDetails)
		oldC := classifyMemberDetails(t, old.out.MemberDetails)
		if fmt.Sprint(got) != fmt.Sprint(oldC) {
			t.Errorf("planned details differ: legacy %v live %v", oldC, got)
		}
	})

	t.Run("update with prior state anchors case K identically", func(t *testing.T) {
		w := w
		w.state = func(t *testing.T, ctx context.Context) *GroupMembershipResourceModel {
			return &GroupMembershipResourceModel{
				ID:                   types.StringValue(liveGroupID),
				GroupID:              types.StringValue(liveGroupID),
				Members:              newMembershipSet(t, liveDNA, liveDNB),
				MemberDetails:        newMemberDetailSet(t, ctx, []string{liveDNA, liveDNB}, []string{liveGUIDA, liveGUIDB}),
				IgnoreMissingMembers: types.BoolNull(),
			}
		}
		old, live := w.run(t, ctx, false), w.run(t, ctx, true)
		assertSamePlan(t, old, live)
		got := classifyMemberDetails(t, live.out.MemberDetails)
		if got.known[liveDNA] != liveGUIDA || got.known[liveDNB] != liveGUIDB {
			t.Errorf("expected A and B anchored as case K, got %v", got)
		}
		if live.groupReads != 1 || len(live.resolverQ) != 0 {
			t.Errorf("live path: groupReads=%d resolverSearches=%v, want 1 and none", live.groupReads, live.resolverQ)
		}
	})

	t.Run("legacy baseline resolves from cache without searching", func(t *testing.T) {
		old := w.run(t, ctx, false)
		if len(old.resolverQ) != 0 {
			t.Errorf("legacy baseline unexpectedly searched: %v", old.resolverQ)
		}
	})
}

func TestGroupMembershipLiveMatching_MixedOnlyUnmatchedSearch(t *testing.T) {
	ctx := t.Context()
	w := liveWorld{
		cacheObjs: []liveObj{liveA, liveB},
		stubSetup: allObjsGroupValues(liveA, liveB),
		members:   []string{liveDNA, liveGUIDB, liveUPNOnly, liveSAMOnly, liveDNNew},
	}
	old, live := w.run(t, ctx, false), w.run(t, ctx, true)
	assertSamePlan(t, old, live)
	if live.resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", live.resp.Diagnostics.Errors())
	}

	want := []string{liveDNNew, liveSAMKey, liveUPNKey}
	sort.Strings(want)
	if !slices.Equal(live.resolverQ, want) {
		t.Errorf("live resolver searches = %v, want exactly the unmatched %v", live.resolverQ, want)
	}
	if !slices.Equal(old.resolverQ, want) {
		t.Errorf("legacy resolver searches = %v, want %v (same unmatched set)", old.resolverQ, want)
	}
	if live.groupReads != 1 {
		t.Errorf("group reads = %d, want 1", live.groupReads)
	}
	got := classifyMemberDetails(t, live.out.MemberDetails)
	total := len(got.known) + len(got.guidOnly) + got.placeholders
	if total != 5 {
		t.Errorf("planned %d member_details elements, want 5: %v", total, got)
	}
}

func TestGroupMembershipLiveMatching_GroupReadFailureFallsBack(t *testing.T) {
	ctx := t.Context()
	cases := map[string]func(*stubMembershipClient){
		"group not found": func(s *stubMembershipClient) { s.groupNotFound = true },
		"search error":    func(s *stubMembershipClient) { s.groupErr = fmt.Errorf("LDAP Result Code 1 \"Operations Error\"") },
		"critical extension unsupported": func(s *stubMembershipClient) {
			s.groupErr = fmt.Errorf("LDAP Result Code 12 \"Unavailable Critical Extension\": unavailableCriticalExtension")
		},
		"malformed member value": func(s *stubMembershipClient) {
			s.serveGroup = true
			s.groupValues = []string{"<GUID=not-a-guid>;CN=A,OU=Users,DC=example,DC=com"}
		},
		"not served (default stub error)": func(s *stubMembershipClient) {},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			// The live cache holds the DN/GUID/SID objects, exactly as the
			// legacy path's does, so the fallback resolves via ResolveBatch.
			w := liveWorld{
				cacheObjs: []liveObj{liveA, liveB, liveC},
				liveCache: []liveObj{liveA, liveB, liveC},
				stubSetup: setup,
				members:   []string{liveDNA, liveGUIDB, liveSIDC, liveUPNOnly},
			}
			old, live := w.run(t, ctx, false), w.run(t, ctx, true)
			assertSamePlan(t, old, live)
			if live.resp.Diagnostics.HasError() || len(live.resp.Diagnostics) != 0 {
				t.Fatalf("group read failure must be silent, got diagnostics: %v", live.resp.Diagnostics)
			}
			if live.groupReads != 1 {
				t.Errorf("group reads = %d, want exactly 1", live.groupReads)
			}
			if !slices.Equal(live.resolverQ, []string{liveUPNKey}) {
				t.Errorf("live resolver searches = %v, want only the UPN", live.resolverQ)
			}
		})
	}
}

func TestGroupMembershipLiveMatching_PartialOrEmptyView(t *testing.T) {
	ctx := t.Context()
	resolvable := func(s *stubMembershipClient) {
		s.resolvable[liveDNB] = stubObject{dn: liveDNB, guid: liveGUIDB}
		s.resolvable[liveDNC] = stubObject{dn: liveDNC, guid: liveGUIDC}
	}
	t.Run("partial view: unmatched members resolve through fallback", func(t *testing.T) {
		w := liveWorld{
			cacheObjs: []liveObj{liveA, liveB, liveC},
			stubSetup: func(s *stubMembershipClient) { allObjsGroupValues(liveA)(s); resolvable(s) },
			members:   []string{liveDNA, liveDNB, liveDNC},
		}
		old, live := w.run(t, ctx, false), w.run(t, ctx, true)
		assertSamePlan(t, old, live)
		if live.resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", live.resp.Diagnostics.Errors())
		}
		if want := []string{liveDNB, liveDNC}; !slices.Equal(live.resolverQ, want) {
			t.Errorf("resolver searches = %v, want %v", live.resolverQ, want)
		}
		if live.groupReads != 1 {
			t.Errorf("group reads = %d, want 1", live.groupReads)
		}
	})
	t.Run("empty view behaves exactly like the legacy path", func(t *testing.T) {
		w := liveWorld{
			cacheObjs: []liveObj{liveA, liveB, liveC},
			stubSetup: func(s *stubMembershipClient) {
				s.serveGroup = true
				resolvable(s)
				s.resolvable[liveDNA] = stubObject{dn: liveDNA, guid: liveGUIDA}
			},
			members: []string{liveDNA, liveDNB, liveDNC},
		}
		old, live := w.run(t, ctx, false), w.run(t, ctx, true)
		assertSamePlan(t, old, live)
		if want := []string{liveDNA, liveDNB, liveDNC}; !slices.Equal(live.resolverQ, want) {
			t.Errorf("resolver searches = %v, want %v", live.resolverQ, want)
		}
	})
}

func TestGroupMembershipLiveMatching_StaleDNOfRenamedMember(t *testing.T) {
	ctx := t.Context()
	const oldDNB = "CN=B-oldname,OU=Users,DC=example,DC=com"
	// AD now reports B under its new DN; the config still names the old DN,
	// which only the cache (from a previous run) still knows.
	renamedB := liveObj{liveDNB, liveGUIDB, liveSIDB}
	staleB := liveObj{oldDNB, liveGUIDB, ""}

	w := liveWorld{
		cacheObjs: []liveObj{liveA, staleB},
		liveCache: []liveObj{staleB},
		stubSetup: allObjsGroupValues(liveA, renamedB),
		members:   []string{liveDNA, oldDNB},
	}
	old, live := w.run(t, ctx, false), w.run(t, ctx, true)
	assertSamePlan(t, old, live)
	if live.resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", live.resp.Diagnostics.Errors())
	}
	if len(live.resolverQ) != 0 {
		t.Errorf("stale DN should resolve from cache without searching, got %v", live.resolverQ)
	}
	got := classifyMemberDetails(t, live.out.MemberDetails)
	// Both are new to this resource (create), so case G: GUID known, DN not.
	assertClassifiedDetails(t, live.out.MemberDetails, classifiedDetails{guidOnly: []string{liveGUIDA, liveGUIDB}})
	// Same GUID as the legacy path, resolved through the cache.
	if oc := classifyMemberDetails(t, old.out.MemberDetails); fmt.Sprint(oc) != fmt.Sprint(got) {
		t.Errorf("legacy %v, live %v", oc, got)
	}
}

func TestGroupMembershipLiveMatching_DiagnosticsUnchanged(t *testing.T) {
	ctx := t.Context()
	base := func(members []string, ignore types.Bool) liveWorld {
		return liveWorld{
			cacheObjs:   []liveObj{liveA},
			stubSetup:   allObjsGroupValues(liveA),
			members:     members,
			ignoreMissG: ignore,
		}
	}
	missing := "missing@example.com"

	t.Run("strict: unmatched unresolvable member is an error", func(t *testing.T) {
		w := base([]string{liveDNA, missing}, types.BoolNull())
		old, live := w.run(t, ctx, false), w.run(t, ctx, true)
		assertSamePlan(t, old, live)
		if !live.resp.Diagnostics.HasError() {
			t.Fatal("expected strict-mode error")
		}
		if live.groupReads != 1 {
			t.Errorf("group reads = %d, want 1", live.groupReads)
		}
	})
	t.Run("ignore-missing: warning, matched member still planned", func(t *testing.T) {
		w := base([]string{liveDNA, missing}, types.BoolValue(true))
		old, live := w.run(t, ctx, false), w.run(t, ctx, true)
		assertSamePlan(t, old, live)
		if live.resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", live.resp.Diagnostics.Errors())
		}
		if len(live.resp.Diagnostics.Warnings()) != 1 {
			t.Errorf("expected exactly one warning, got %v", live.resp.Diagnostics)
		}
		// A (matched live) is case G; the unresolvable member is a placeholder (case P).
		assertClassifiedDetails(t, live.out.MemberDetails, classifiedDetails{guidOnly: []string{liveGUIDA}, placeholders: 1})
	})
	t.Run("ignore-missing: safety net when nothing resolves", func(t *testing.T) {
		w := base([]string{missing}, types.BoolValue(true))
		old, live := w.run(t, ctx, false), w.run(t, ctx, true)
		assertSamePlan(t, old, live)
		if !live.resp.Diagnostics.HasError() {
			t.Fatal("expected All Members Failed to Resolve error")
		}
	})
}

func TestGroupMembershipLiveMatching_WriteFallback(t *testing.T) {
	ctx := t.Context()
	w := liveWorld{
		cacheObjs: []liveObj{liveA, liveB, liveC},
		stubSetup: allObjsGroupValues(liveA, liveB, liveC),
		members:   []string{liveDNA, liveGUIDB, liveSIDC, liveUPNOnly},
	}
	data := func() *GroupMembershipResourceModel { return w.plan(t) }

	legacyR, _ := w.newResource(t, w.cacheObjs, nil)
	oldDNs, oldGUIDs, oldDiags := legacyR.resolveMembersForWriteFallback(ctx, data())

	liveR, liveStub := w.newResource(t, nil, w.stubSetup)
	dns, guids, diags := liveR.resolveMembersForWriteFallback(ctx, data())
	if diags.HasError() || oldDiags.HasError() {
		t.Fatalf("unexpected errors: live %v legacy %v", diags.Errors(), oldDiags.Errors())
	}
	if !slices.Equal(dns, oldDNs) {
		t.Errorf("DNs differ: live %v legacy %v", dns, oldDNs)
	}
	if fmt.Sprint(guids) != fmt.Sprint(oldGUIDs) {
		t.Errorf("GUID map differs: live %v legacy %v", guids, oldGUIDs)
	}
	wantDNs := []string{liveDNA, liveDNB, liveDNC, liveDNUPN}
	if !slices.Equal(dns, wantDNs) {
		t.Errorf("DNs = %v, want %v", dns, wantDNs)
	}
	reads, q := liveStub.counts()
	if reads != 1 {
		t.Errorf("group reads = %d, want exactly 1", reads)
	}
	if !slices.Equal(q, []string{liveUPNKey}) {
		t.Errorf("resolver searches = %v, want only the UPN", q)
	}
}

func TestGroupMembershipLiveMatching_NoLDAPWhenNothingToResolve(t *testing.T) {
	ctx := t.Context()
	w := liveWorld{stubSetup: allObjsGroupValues(liveA)}

	assertNoCalls := func(t *testing.T, stub *stubMembershipClient) {
		t.Helper()
		if reads, q := stub.counts(); reads != 0 || len(q) != 0 {
			t.Errorf("expected no LDAP calls, got groupReads=%d resolver=%v", reads, q)
		}
	}

	t.Run("ModifyPlan with zero members", func(t *testing.T) {
		w := w
		w.members = nil
		r, stub := w.newResource(t, nil, w.stubSetup)
		_, resp := runMembershipModifyPlan(t, ctx, r, w.plan(t), nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertNoCalls(t, stub)
	})

	t.Run("ModifyPlan with unknown group_id", func(t *testing.T) {
		w := w
		w.members = []string{liveDNA}
		r, stub := w.newResource(t, nil, w.stubSetup)
		plan := w.plan(t)
		plan.GroupID = types.StringUnknown()
		_, resp := runMembershipModifyPlan(t, ctx, r, plan, nil)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics.Errors())
		}
		assertNoCalls(t, stub)
	})

	t.Run("write fallback with zero members", func(t *testing.T) {
		w := w
		w.members = nil
		r, stub := w.newResource(t, nil, w.stubSetup)
		if _, _, diags := r.resolveMembersForWriteFallback(ctx, w.plan(t)); diags.HasError() {
			t.Fatalf("unexpected error: %v", diags.Errors())
		}
		assertNoCalls(t, stub)
	})

	t.Run("write fallback with unknown group_id skips the group read", func(t *testing.T) {
		w := w
		w.members = []string{liveDNA}
		r, stub := w.newResource(t, []liveObj{liveA}, w.stubSetup)
		data := w.plan(t)
		data.GroupID = types.StringUnknown()
		if _, _, diags := r.resolveMembersForWriteFallback(ctx, data); diags.HasError() {
			t.Fatalf("unexpected error: %v", diags.Errors())
		}
		if reads, _ := stub.counts(); reads != 0 {
			t.Errorf("group reads = %d, want 0", reads)
		}
	})
}
