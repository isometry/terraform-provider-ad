package ldap

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Directory test double ---------------------------------------------------

// addPrincipal adds a directory object. sidFlag0 selects how the SID is
// emitted in the member's extended DN: true = Flag 0 (hex of the binary SID,
// what NewExtendedDNControl requests), false = Flag 1 ("S-..." string).
func (d *renameAwareMembershipClient) addPrincipal(t testing.TB, guid, dn, sid, upn, sam string, sidFlag0 bool) *raObject {
	t.Helper()
	o := d.addObject(guid, dn)
	if sid != "" {
		if sidFlag0 {
			b, err := NewSIDHandler().StringToSIDBytes(sid)
			require.NoError(t, err)
			o.sid = hex.EncodeToString(b)
		} else {
			o.sid = sid
		}
	}
	o.dirSID, o.upn, o.sam = sid, upn, sam
	return o
}

func inScope(dn, base string) bool {
	if DNEqual(dn, base) {
		return true
	}
	child, err := IsDNChild(dn, base)
	return err == nil && child
}

// directorySearch answers every search MemberNormalizer.ResolveBatch issues
// (DN base-object validation, objectGUID, objectSid, userPrincipalName and
// sAMAccountName subtree searches). Subtree searches only see objects at or
// below the search base, modelling a single-domain DC that cannot see other
// naming contexts. Every such search is recorded in resolverSearches so tests
// can prove which identifiers caused LDAP traffic.
func (d *renameAwareMembershipClient) directorySearch(req *SearchRequest) (*SearchResult, error) {
	d.resolverSearches = append(d.resolverSearches, req)

	var found *raObject
	for _, o := range d.objects {
		if req.Scope == ScopeBaseObject {
			if DNEqual(o.dn, req.BaseDN) {
				found = o
				break
			}
			continue
		}
		if !inScope(o.dn, req.BaseDN) {
			continue
		}
		var want string
		switch {
		case strings.HasPrefix(req.Filter, "(objectGUID="):
			if o.guid != "" {
				want, _ = NewGUIDHandler().GUIDToSearchFilter(o.guid)
			}
		case strings.HasPrefix(req.Filter, "(objectSid="):
			if o.dirSID != "" {
				want, _ = NewSIDHandler().SIDToSearchFilter(o.dirSID)
			}
		case strings.HasPrefix(req.Filter, "(userPrincipalName="):
			if o.upn != "" {
				want = fmt.Sprintf("(userPrincipalName=%s)", ldap.EscapeFilter(o.upn))
			}
		case strings.HasPrefix(req.Filter, "(sAMAccountName="):
			if o.sam != "" {
				want = fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(o.sam))
			}
		}
		if want != "" && want == req.Filter {
			found = o
			break
		}
	}

	if found == nil {
		return &SearchResult{Entries: []*ldap.Entry{}}, nil
	}
	entry := &ldap.Entry{
		DN:         found.dn,
		Attributes: []*ldap.EntryAttribute{{Name: "distinguishedName", Values: []string{found.dn}}},
	}
	if found.guid != "" {
		raw, err := NewGUIDHandler().StringToGUIDBytes(found.guid)
		if err != nil {
			return nil, err
		}
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: "objectGUID", ByteValues: [][]byte{raw}})
	}
	return &SearchResult{Entries: []*ldap.Entry{entry}, Total: 1}, nil
}

const (
	mmBaseDN  = "DC=example,DC=com"
	mmSIDA    = "S-1-5-21-100-200-300-1101"
	mmSIDB    = "S-1-5-21-100-200-300-1102"
	mmSIDC    = "S-1-5-21-100-200-300-1103"
	mmFSPSID  = "S-1-5-21-900-900-900-1001"
	mmFSPDN   = "CN=S-1-5-21-900-900-900-1001,CN=ForeignSecurityPrincipals,DC=example,DC=com"
	mmFSPGUID = "eeeeeeee-1111-2222-3333-444444444444"
	mmXDomDN  = "CN=Eve,CN=Users,DC=other,DC=org"
	mmXGUID   = "ffffffff-1111-2222-3333-444444444444"
)

// directorySetup populates a renameAwareMembershipClient; it is run against two
// independent clients so ResolveBatchAgainst and ResolveBatch can be compared
// on identical directories.
type directorySetup func(t testing.TB, d *renameAwareMembershipClient)

func newMatchingFixture(t *testing.T, setup directorySetup) (*MemberNormalizer, *GroupMembershipManager, *renameAwareMembershipClient) {
	t.Helper()
	d := newRenameAwareMembershipClient()
	setup(t, d)
	gmm := NewGroupMembershipManager(t.Context(), d, mmBaseDN, nil)
	n := NewMemberNormalizer(d, mmBaseDN, nil)
	return n, gmm, d
}

func errStrings(failures map[string]error) map[string]string {
	out := make(map[string]string, len(failures))
	for k, v := range failures {
		out[k] = v.Error()
	}
	return out
}

// legacyResolve runs plain ResolveBatch against a freshly built directory.
func legacyResolve(t *testing.T, setup directorySetup, ids []string) (map[string]ResolvedIdentifier, map[string]string, int) {
	t.Helper()
	n, _, d := newMatchingFixture(t, setup)
	res, fail := n.ResolveBatch(ids)
	return res, errStrings(fail), len(d.resolverSearches)
}

// againstResolve reads current members once and runs ResolveBatchAgainst.
func againstResolve(t *testing.T, setup directorySetup, ids []string) (map[string]ResolvedIdentifier, map[string]string, *renameAwareMembershipClient) {
	t.Helper()
	n, gmm, d := newMatchingFixture(t, setup)
	current, err := gmm.GetCurrentMembers(raGroupGUID)
	require.NoError(t, err)
	res, fail := n.ResolveBatchAgainst(ids, current)
	return res, errStrings(fail), d
}

// standardDirectory: A, B, C are members (A: SID in Flag 0 hex form, B: SID
// in Flag 1 string form, C: no SID); D exists but is not a member.
func standardDirectory(t testing.TB, d *renameAwareMembershipClient) {
	a := d.addPrincipal(t, raGUIDA, raDNANew, mmSIDA, "alice@example.com", "alice", true)
	b := d.addPrincipal(t, raGUIDB, raDNB, mmSIDB, "bob@example.com", "bob", false)
	c := d.addPrincipal(t, raGUIDC, raDNC, "", "carol@example.com", "carol", true)
	d.addPrincipal(t, raGUIDD, raDND, mmSIDC, "dave@example.com", "dave", true)
	d.setMembers(a, b, c)
}

// --- GetCurrentMembers -------------------------------------------------------

func TestGetCurrentMembers_Fields(t *testing.T) {
	_, gmm, d := newMatchingFixture(t, func(t testing.TB, d *renameAwareMembershipClient) {
		a := d.addPrincipal(t, raGUIDA, raDNANew, mmSIDA, "", "", true)                                 // hex SID
		b := d.addPrincipal(t, raGUIDB, raDNB, mmSIDB, "", "", false)                                   // S- SID
		c := d.addPrincipal(t, "", raDNC, "", "", "", true)                                             // no GUID, no SID
		e := d.addPrincipal(t, raGUIDD, "cn=dave,ou=users,dc=example,dc=com", "", "", "", true)         // lower-case types
		f := d.addPrincipal(t, mmFSPGUID, mmFSPDN, mmFSPSID, "", "", true)                              // FSP
		g := d.addPrincipal(t, mmXGUID, `CN=Smith\, John,OU=Users,DC=example,DC=com`, "", "", "", true) // escaped
		d.setMembers(a, b, c, e, f, g)
	})

	got, err := gmm.GetCurrentMembers(raGroupGUID)
	require.NoError(t, err)
	assert.Equal(t, []CurrentMember{
		{DN: raDNANew, RawDN: raDNANew, GUID: raGUIDA, SID: mmSIDA},
		{DN: raDNB, RawDN: raDNB, GUID: raGUIDB, SID: mmSIDB},
		{DN: raDNC, RawDN: raDNC},
		{DN: "CN=dave,OU=users,DC=example,DC=com", RawDN: "cn=dave,ou=users,dc=example,dc=com", GUID: raGUIDD},
		{DN: mmFSPDN, RawDN: mmFSPDN, GUID: mmFSPGUID, SID: mmFSPSID},
		{DN: `CN=Smith\, John,OU=Users,DC=example,DC=com`, RawDN: `CN=Smith\, John,OU=Users,DC=example,DC=com`, GUID: mmXGUID},
	}, got)
	assert.Equal(t, 1, d.extendedDNSearches(), "exactly one extended-DN read")
	assert.Empty(t, d.resolverSearches, "no per-member lookups")
}

func TestGetCurrentMembers_NoMembersReturned(t *testing.T) {
	tests := map[string]struct {
		setup      directorySetup
		rangeLimit int
		wantNil    bool
	}{
		"empty group": {setup: func(testing.TB, *renameAwareMembershipClient) {}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, gmm, d := newMatchingFixture(t, tc.setup)
			d.rangeLimit = tc.rangeLimit

			got, err := gmm.GetCurrentMembers(raGroupGUID)
			require.NoError(t, err)
			assert.Equal(t, tc.wantNil, got == nil)
			assert.Empty(t, got)
		})
	}
}

func TestGetCurrentMembers_MalformedSIDIsNonFatal(t *testing.T) {
	inner := newRenameAwareMembershipClient()
	fc := &failingSearchClient{
		renameAwareMembershipClient: inner,
		memberValue:                 "<GUID=" + rawGUIDHex(t, raGUIDA) + ">;<SID=zz-not-a-sid>;" + raDNANew,
	}
	gmm := NewGroupMembershipManager(t.Context(), fc, mmBaseDN, nil)

	got, err := gmm.GetCurrentMembers(raGroupGUID)
	require.NoError(t, err)
	assert.Equal(t, []CurrentMember{{DN: raDNANew, RawDN: raDNANew, GUID: raGUIDA}}, got, "unparseable SID is dropped, member still reported")

	// SetGroupMembers shares the reader and must be unaffected too.
	require.NoError(t, gmm.SetGroupMembers(raGroupGUID, []string{raDNANew}, map[string]string{raDNANew: raGUIDA}, nil))
	assert.Empty(t, inner.modifies)
}

func TestGetCurrentMembers_Errors(t *testing.T) {
	t.Run("empty group GUID", func(t *testing.T) {
		_, gmm, _ := newMatchingFixture(t, standardDirectory)
		_, err := gmm.GetCurrentMembers("")
		assert.Error(t, err)
	})
	t.Run("invalid group GUID", func(t *testing.T) {
		_, gmm, _ := newMatchingFixture(t, standardDirectory)
		_, err := gmm.GetCurrentMembers("zzz")
		assert.Error(t, err)
	})
	t.Run("group not found", func(t *testing.T) {
		_, gmm, d := newMatchingFixture(t, standardDirectory)
		d.groupGUID = raGUIDC
		_, err := gmm.GetCurrentMembers(raGroupGUID)
		assert.True(t, IsNotFoundError(err), "got %v", err)
	})
	t.Run("search error", func(t *testing.T) {
		inner := newRenameAwareMembershipClient()
		fc := &failingSearchClient{renameAwareMembershipClient: inner, err: ldap.NewError(ldap.LDAPResultUnavailableCriticalExtension, fmt.Errorf("unsupported"))}
		gmm := NewGroupMembershipManager(t.Context(), fc, mmBaseDN, nil)
		_, err := gmm.GetCurrentMembers(raGroupGUID)
		assert.True(t, ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailableCriticalExtension), "got %v", err)
	})
	t.Run("malformed extended DN", func(t *testing.T) {
		inner := newRenameAwareMembershipClient()
		fc := &failingSearchClient{renameAwareMembershipClient: inner, memberValue: "<GUID=nothex>;CN=X,DC=example,DC=com"}
		gmm := NewGroupMembershipManager(t.Context(), fc, mmBaseDN, nil)
		_, err := gmm.GetCurrentMembers(raGroupGUID)
		assert.Error(t, err)
	})
}

func TestExtendedDNSIDToString(t *testing.T) {
	h := NewSIDHandler()
	// MS-ADTS 3.1.1.3.4.1.5 vector: same SID in Flag 0 (hex) and Flag 1 form.
	const msHex = "01050000000000051500000061eb5b8c50ef705befda808bf4010000"
	const msStr = "S-1-5-21-2354834273-1534127952-2340477679-500"

	tests := []struct {
		name, in, want string
		wantErr        bool
	}{
		{name: "MS-ADTS hex vector", in: msHex, want: msStr},
		{name: "uppercase hex", in: strings.ToUpper(msHex), want: msStr},
		{name: "string form", in: msStr, want: msStr},
		{name: "string form with whitespace", in: "  " + msStr + " ", want: msStr},
		{name: "well-known SID hex (S-1-5-11)", in: "01010000000000050b000000", want: "S-1-5-11"},
		{name: "empty", in: "", wantErr: true},
		{name: "odd-length hex", in: "0101000", wantErr: true},
		{name: "truncated binary SID", in: "0105000000000005", wantErr: true},
		{name: "garbage", in: "zz", wantErr: true},
		{name: "bad string form", in: "S-1-x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := h.ExtendedDNSIDToString(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- ResolveBatchAgainst: parity with ResolveBatch on hits -------------------

// For every identifier that matches a current member, ResolveBatchAgainst must
// return exactly what ResolveBatch would (same DN string, same GUID) while
// issuing zero resolver searches.
func TestResolveBatchAgainst_HitsMatchResolveBatchWithZeroLookups(t *testing.T) {
	escapedDir := func(t testing.TB, d *renameAwareMembershipClient) {
		standardDirectory(t, d)
		s := d.addPrincipal(t, mmXGUID, `CN=Smith\, John,OU=Users,DC=example,DC=com`, "", "", "", true)
		d.setMembers(append(d.members, s)...)
	}
	fspDir := func(t testing.TB, d *renameAwareMembershipClient) {
		standardDirectory(t, d)
		f := d.addPrincipal(t, mmFSPGUID, mmFSPDN, mmFSPSID, "", "", true)
		d.setMembers(append(d.members, f)...)
	}
	lowerTypesDir := func(t testing.TB, d *renameAwareMembershipClient) {
		o := d.addPrincipal(t, raGUIDD, "cn=Dave,ou=Users,dc=example,dc=com", mmSIDC, "", "", true)
		d.setMembers(o)
	}

	tests := []struct {
		name  string
		setup directorySetup
		ids   []string
	}{
		{name: "DN exact", setup: standardDirectory, ids: []string{raDNANew}},
		{name: "DN lower-case types and values", setup: standardDirectory, ids: []string{strings.ToLower(raDNB)}},
		{name: "DN upper-case values", setup: standardDirectory, ids: []string{strings.ToUpper(raDNC)}},
		{name: "DN with spaces after commas", setup: standardDirectory, ids: []string{"CN=Bob, OU=Users, DC=example, DC=com"}},
		{name: "DN reported by AD with lower-case types", setup: lowerTypesDir, ids: []string{"CN=DAVE,OU=USERS,DC=EXAMPLE,DC=COM"}},
		{name: "GUID canonical", setup: standardDirectory, ids: []string{raGUIDA}},
		{name: "GUID upper-case", setup: standardDirectory, ids: []string{strings.ToUpper(raGUIDB)}},
		{name: "GUID compact", setup: standardDirectory, ids: []string{strings.ReplaceAll(raGUIDC, "-", "")}},
		{name: "SID from Flag 0 hex", setup: standardDirectory, ids: []string{mmSIDA}},
		{name: "SID from Flag 1 string", setup: standardDirectory, ids: []string{mmSIDB}},
		{name: "escaped DN, hex-escaped and lower-cased identifier", setup: escapedDir, ids: []string{`cn=smith\2c john,ou=users,dc=example,dc=com`}},
		{name: "escaped DN, identical identifier", setup: escapedDir, ids: []string{`CN=Smith\, John,OU=Users,DC=example,DC=com`}},
		{name: "FSP by SID", setup: fspDir, ids: []string{mmFSPSID}},
		{name: "FSP by DN", setup: fspDir, ids: []string{strings.ToLower(mmFSPDN)}},
		{name: "FSP by GUID", setup: fspDir, ids: []string{mmFSPGUID}},
		{
			name:  "duplicates: same object via DN, GUID and SID",
			setup: standardDirectory,
			ids:   []string{raDNANew, strings.ToLower(raDNANew), raGUIDA, strings.ToUpper(raGUIDA), mmSIDA},
		},
		{name: "whitespace-padded DN/GUID/SID", setup: standardDirectory, ids: []string{"  " + raDNANew + "\t", "\n" + raGUIDB + " ", " " + mmSIDB + " "}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, wantFail, _ := legacyResolve(t, tt.setup, tt.ids)
			require.Empty(t, wantFail, "fixture sanity: ResolveBatch must succeed")

			got, gotFail, d := againstResolve(t, tt.setup, tt.ids)
			assert.Empty(t, gotFail)
			assert.Equal(t, want, got)
			assert.Empty(t, d.resolverSearches, "matched identifiers must not cause any lookup")
		})
	}
}

// The duplicate case explicitly: every key present, all mapping to one object.
func TestResolveBatchAgainst_DuplicatesAllKeysSameObject(t *testing.T) {
	ids := []string{raDNANew, strings.ToLower(raDNANew), raGUIDA, mmSIDA, raDNANew}
	got, fail, d := againstResolve(t, standardDirectory, ids)
	assert.Empty(t, fail)
	require.Len(t, got, 4)
	for _, id := range ids {
		assert.Equal(t, ResolvedIdentifier{DN: raDNANew, GUID: raGUIDA}, got[id], id)
	}
	assert.Empty(t, d.resolverSearches)
}

// --- ResolveBatchAgainst: fall-through cases ---------------------------------

// Every identifier in these cases must NOT be short-circuited; the result must
// equal ResolveBatch's (results, failures and lookup count).
func TestResolveBatchAgainst_FallThroughEqualsResolveBatch(t *testing.T) {
	guidlessDir := func(t testing.TB, d *renameAwareMembershipClient) {
		o := d.addPrincipal(t, "", raDNC, mmSIDC, "", "", true)
		d.setMembers(o)
	}
	renamedDir := func(t testing.TB, d *renameAwareMembershipClient) {
		standardDirectory(t, d) // A is at raDNANew; raDNAOld no longer exists
	}
	// Two current members share one SID (an FSP for S and a real object
	// carrying S, e.g. in another domain): a SID identifier is ambiguous.
	sidCollisionDir := func(t testing.TB, d *renameAwareMembershipClient) {
		f := d.addPrincipal(t, mmFSPGUID, mmFSPDN, mmFSPSID, "", "", true)
		x := d.addPrincipal(t, mmXGUID, mmXDomDN, mmFSPSID, "", "", true)
		d.setMembers(f, x)
	}
	// Two current members whose DNs are equal ignoring case but which are
	// different objects: a DN identifier is ambiguous.
	dnCollisionDir := func(t testing.TB, d *renameAwareMembershipClient) {
		o1 := d.addPrincipal(t, raGUIDA, raDNC, "", "", "", true)
		o2 := &raObject{guid: raGUIDB, dn: strings.ToUpper(raDNC)}
		d.setMembers(o1, o2)
	}

	tests := []struct {
		name         string
		setup        directorySetup
		ids          []string
		wantLookups  int
		wantFailures int
	}{
		{name: "UPN of a current member", setup: standardDirectory, ids: []string{"alice@example.com"}, wantLookups: 1},
		{name: "SAM of a current member", setup: standardDirectory, ids: []string{`EXAMPLE\bob`}, wantLookups: 1},
		{name: "bare SAM of a current member", setup: standardDirectory, ids: []string{"carol"}, wantLookups: 1},
		{name: "non-member DN", setup: standardDirectory, ids: []string{raDND}, wantLookups: 1},
		{name: "non-member GUID", setup: standardDirectory, ids: []string{raGUIDD}, wantLookups: 1},
		{name: "non-member SID", setup: standardDirectory, ids: []string{mmSIDC}, wantLookups: 1},
		{name: "stale (renamed) DN", setup: renamedDir, ids: []string{raDNAOld}, wantLookups: 1, wantFailures: 1},
		{name: "nonexistent GUID", setup: standardDirectory, ids: []string{"01234567-89ab-cdef-0123-456789abcdef"}, wantLookups: 1, wantFailures: 1},
		{name: "unknown identifier type", setup: standardDirectory, ids: []string{"a b@c"}, wantFailures: 1},
		{name: "unparseable DN-shaped identifier", setup: standardDirectory, ids: []string{"CN=a,=b"}, wantFailures: 1},
		{name: "current member without GUID, by DN", setup: guidlessDir, ids: []string{raDNC}, wantLookups: 1},
		{name: "current member without GUID, by SID", setup: guidlessDir, ids: []string{mmSIDC}, wantLookups: 1},
		{name: "SID shared by two current members (FSP ambiguity)", setup: sidCollisionDir, ids: []string{mmFSPSID}, wantLookups: 1},
		{name: "DN shared by two current objects", setup: dnCollisionDir, ids: []string{raDNC}, wantLookups: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, wantFail, wantLookups := legacyResolve(t, tt.setup, tt.ids)
			got, gotFail, d := againstResolve(t, tt.setup, tt.ids)

			assert.Equal(t, want, got, "results")
			assert.Equal(t, wantFail, gotFail, "failures (incl. error messages)")
			assert.Len(t, gotFail, tt.wantFailures)
			assert.Len(t, d.resolverSearches, wantLookups, "same lookups as ResolveBatch")
			assert.Len(t, d.resolverSearches, tt.wantLookups)
		})
	}
}

// A member from outside the normalizer's base DN (e.g. another domain of the
// forest in a universal group) is reported by AD itself, so a DN/GUID/SID that
// matches it resolves to AD's own identity even though ResolveBatch's
// base-DN-scoped searches could not find it. Documented divergence: it only
// ever turns a lookup failure into the correct, AD-authoritative answer.
func TestResolveBatchAgainst_OutOfBaseDNMemberResolvesFromCurrent(t *testing.T) {
	setup := func(t testing.TB, d *renameAwareMembershipClient) {
		x := d.addPrincipal(t, mmXGUID, mmXDomDN, mmFSPSID, "", "", true)
		d.setMembers(x)
	}
	ids := []string{mmXGUID, mmFSPSID}

	_, legacyFail, _ := legacyResolve(t, setup, ids)
	assert.Len(t, legacyFail, 2, "fixture sanity: ResolveBatch cannot see outside its base DN")

	got, fail, d := againstResolve(t, setup, ids)
	assert.Empty(t, fail)
	for _, id := range ids {
		assert.Equal(t, ResolvedIdentifier{DN: mmXDomDN, GUID: mmXGUID}, got[id], id)
	}
	assert.Empty(t, d.resolverSearches)
}

// --- Empty / nil current and identifiers -------------------------------------

func TestResolveBatchAgainst_EmptyCurrentEqualsResolveBatch(t *testing.T) {
	ids := []string{raDNANew, raGUIDB, mmSIDA, "alice@example.com", `EXAMPLE\bob`, raDNAOld, "", "   ", "a b@c"}
	for name, current := range map[string][]CurrentMember{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			want, wantFail, wantLookups := legacyResolve(t, standardDirectory, ids)

			n, _, d := newMatchingFixture(t, standardDirectory)
			got, gotFail := n.ResolveBatchAgainst(ids, current)
			assert.Equal(t, want, got)
			assert.Equal(t, wantFail, errStrings(gotFail))
			assert.Len(t, d.resolverSearches, wantLookups)
			assert.Zero(t, d.extendedDNSearches())
		})
	}
}

// A range-limited member attribute is followed to completion, so the view is
// the full membership and resolution against it matches legacy resolution.
func TestResolveBatchAgainst_RangedGroupUsesFullView(t *testing.T) {
	ids := []string{raDNANew, raGUIDB, mmSIDA, raDNC}
	want, wantFail, wantLookups := legacyResolve(t, standardDirectory, ids)

	n, gmm, d := newMatchingFixture(t, standardDirectory)
	d.rangeLimit = 1
	current, err := gmm.GetCurrentMembers(raGroupGUID)
	require.NoError(t, err)
	require.NotEmpty(t, current)

	got, gotFail := n.ResolveBatchAgainst(ids, current)
	assert.Equal(t, want, got)
	assert.Equal(t, wantFail, errStrings(gotFail))
	_ = wantLookups
}

// A partial view (some members missing) is also safe: present members match,
// missing ones fall through, and results equal ResolveBatch.
func TestResolveBatchAgainst_PartialViewIsSafe(t *testing.T) {
	ids := []string{raDNANew, raGUIDB, raDNC}
	want, _, _ := legacyResolve(t, standardDirectory, ids)

	n, gmm, d := newMatchingFixture(t, standardDirectory)
	current, err := gmm.GetCurrentMembers(raGroupGUID)
	require.NoError(t, err)
	require.Len(t, current, 3)

	got, fail := n.ResolveBatchAgainst(ids, current[:1]) // only A visible
	assert.Empty(t, fail)
	assert.Equal(t, want, got)
	assert.Len(t, d.resolverSearches, 2, "B and C looked up, A matched")
}

func TestResolveBatchAgainst_EmptyIdentifiers(t *testing.T) {
	n, gmm, d := newMatchingFixture(t, standardDirectory)
	current, err := gmm.GetCurrentMembers(raGroupGUID)
	require.NoError(t, err)

	for name, ids := range map[string][]string{"nil": nil, "empty": {}, "blank only": {"", "  ", "\t\n"}} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			got, fail := n.resolveBatchAgainst(ids, current, func(ids []string) (map[string]ResolvedIdentifier, map[string]error) {
				calls++
				return n.ResolveBatch(ids)
			})
			assert.NotNil(t, got)
			assert.NotNil(t, fail)
			assert.Empty(t, got)
			assert.Empty(t, fail)
			assert.Zero(t, calls, "nothing to fall back for")
		})
	}
	assert.Empty(t, d.resolverSearches)
}

// --- Mixed batch: single fallback call, matched cause no searches ------------

func TestResolveBatchAgainst_MixedBatchSingleFallbackCall(t *testing.T) {
	n, gmm, d := newMatchingFixture(t, func(t testing.TB, d *renameAwareMembershipClient) {
		standardDirectory(t, d)
	})
	current, err := gmm.GetCurrentMembers(raGroupGUID)
	require.NoError(t, err)

	ids := []string{
		strings.ToLower(raDNANew), // match by DN
		"alice@example.com",       // UPN: always falls through
		strings.ToUpper(raGUIDB),  // match by GUID
		`EXAMPLE\bob`,             // SAM: always falls through
		mmSIDA,                    // match by SID
		raDND,                     // new member: falls through
		raDNAOld,                  // stale DN: falls through, fails
		"alice@example.com",       // verbatim duplicate of an unmatched identifier
		"  ",                      // skipped
		"",                        // skipped
	}

	var calls [][]string
	got, fail := n.resolveBatchAgainst(ids, current, func(ids []string) (map[string]ResolvedIdentifier, map[string]error) {
		calls = append(calls, append([]string(nil), ids...))
		return n.ResolveBatch(ids)
	})

	require.Len(t, calls, 1, "unmatched identifiers resolved in ONE ResolveBatch call")
	assert.Equal(t, []string{"alice@example.com", `EXAMPLE\bob`, raDND, raDNAOld}, calls[0], "unmatched, input order, deduplicated, blanks dropped")

	assert.Equal(t, map[string]ResolvedIdentifier{
		strings.ToLower(raDNANew): {DN: raDNANew, GUID: raGUIDA},
		"alice@example.com":       {DN: raDNANew, GUID: raGUIDA},
		strings.ToUpper(raGUIDB):  {DN: raDNB, GUID: raGUIDB},
		`EXAMPLE\bob`:             {DN: raDNB, GUID: raGUIDB},
		mmSIDA:                    {DN: raDNANew, GUID: raGUIDA},
		raDND:                     {DN: raDND, GUID: raGUIDD},
	}, got)
	require.Len(t, fail, 1)
	assert.Contains(t, fail, raDNAOld)

	// Exactly one lookup per unmatched identifier; none for matched ones.
	require.Len(t, d.resolverSearches, 4)
	guidFilterB, _ := NewGUIDHandler().GUIDToSearchFilter(raGUIDB)
	sidFilterA, _ := NewSIDHandler().SIDToSearchFilter(mmSIDA)
	for _, req := range d.resolverSearches {
		assert.False(t, DNEqual(req.BaseDN, raDNANew), "matched DN looked up")
		assert.NotEqual(t, guidFilterB, req.Filter, "matched GUID looked up")
		assert.NotEqual(t, sidFilterA, req.Filter, "matched SID looked up")
	}
}

func TestResolveBatchAgainst_AllMatchedNoFallbackCall(t *testing.T) {
	n, gmm, _ := newMatchingFixture(t, standardDirectory)
	current, err := gmm.GetCurrentMembers(raGroupGUID)
	require.NoError(t, err)

	calls := 0
	got, fail := n.resolveBatchAgainst([]string{raDNANew, raGUIDB, mmSIDA}, current, func(ids []string) (map[string]ResolvedIdentifier, map[string]error) {
		calls++
		return n.ResolveBatch(ids)
	})
	assert.Zero(t, calls)
	assert.Empty(t, fail)
	assert.Len(t, got, 3)
}

// --- Cache interaction --------------------------------------------------------

// Matched identifiers use AD's fresh current-member data and neither read nor
// write the cache (a stale cached DN for the same identifier is not returned,
// and no entry is overwritten); unmatched ones keep ResolveBatch's cache use.
func TestResolveBatchAgainst_CacheInteraction(t *testing.T) {
	d := newRenameAwareMembershipClient()
	standardDirectory(t, d)
	cache := NewCacheManager()
	// Stale cache: GUID A still points at A's old DN.
	require.NoError(t, cache.Put(&LDAPCacheEntry{DN: raDNAOld, ObjectGUID: raGUIDA, Attributes: map[string][]string{}}))
	// Cached UPN for D (not a member): must be served from cache.
	require.NoError(t, cache.Put(&LDAPCacheEntry{DN: raDND, ObjectGUID: raGUIDD, Attributes: map[string][]string{"userPrincipalName": {"dave@example.com"}}}))

	gmm := NewGroupMembershipManager(t.Context(), d, mmBaseDN, nil)
	n := NewMemberNormalizer(d, mmBaseDN, cache)
	current, err := gmm.GetCurrentMembers(raGroupGUID)
	require.NoError(t, err)

	before := cache.GetStats()
	got, fail := n.ResolveBatchAgainst([]string{raGUIDA, "dave@example.com"}, current)
	after := cache.GetStats()

	assert.Empty(t, fail)
	assert.Equal(t, ResolvedIdentifier{DN: raDNANew, GUID: raGUIDA}, got[raGUIDA], "fresh current DN wins over stale cache")
	assert.Equal(t, ResolvedIdentifier{DN: raDND, GUID: raGUIDD}, got["dave@example.com"], "unmatched served from cache")
	assert.Empty(t, d.resolverSearches)
	assert.Equal(t, before.Entries, after.Entries, "matched identifiers do not write the cache")

	cached, ok := cache.Get(raGUIDA)
	require.True(t, ok)
	assert.Equal(t, raDNAOld, cached.DN, "cache entry untouched by matching")
}

// --- Scale --------------------------------------------------------------------

func largeCurrent(n int) ([]CurrentMember, []string) {
	current := make([]CurrentMember, n)
	ids := make([]string, n)
	for i := range n {
		current[i] = CurrentMember{
			DN:   fmt.Sprintf("CN=User%06d,OU=Users,DC=example,DC=com", i),
			GUID: fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i),
			SID:  fmt.Sprintf("S-1-5-21-100-200-300-%d", 10000+i),
		}
		switch i % 3 {
		case 0:
			ids[i] = strings.ToLower(current[i].DN)
		case 1:
			ids[i] = strings.ToUpper(current[i].GUID)
		default:
			ids[i] = current[i].SID
		}
	}
	return current, ids
}

// countingClient fails the test on any search: matched identifiers must never
// reach LDAP.
type countingClient struct {
	*MockGroupMembershipClient
	searches int
}

func (c *countingClient) Search(context.Context, *SearchRequest) (*SearchResult, error) {
	c.searches++
	return &SearchResult{Entries: []*ldap.Entry{}}, nil
}

func TestResolveBatchAgainst_LargeSetNoLookups(t *testing.T) {
	const size = 20000
	current, ids := largeCurrent(size)
	c := &countingClient{MockGroupMembershipClient: NewMockGroupMembershipClient()}
	n := NewMemberNormalizer(c, mmBaseDN, nil)

	got, fail := n.ResolveBatchAgainst(ids, current)
	assert.Empty(t, fail)
	require.Len(t, got, size)
	assert.Zero(t, c.searches)
	for i, id := range ids {
		if got[id].DN != current[i].DN || got[id].GUID != current[i].GUID {
			t.Fatalf("identifier %q resolved to %+v, want %+v", id, got[id], current[i])
		}
	}
}

func BenchmarkResolveBatchAgainst_AllMatched(b *testing.B) {
	for _, size := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("n=%d", size), func(b *testing.B) {
			current, ids := largeCurrent(size)
			c := &countingClient{MockGroupMembershipClient: NewMockGroupMembershipClient()}
			n := NewMemberNormalizer(c, mmBaseDN, nil)
			b.ResetTimer()
			for b.Loop() {
				_, _ = n.ResolveBatchAgainst(ids, current)
			}
			if c.searches != 0 {
				b.Fatalf("unexpected searches: %d", c.searches)
			}
		})
	}
}
