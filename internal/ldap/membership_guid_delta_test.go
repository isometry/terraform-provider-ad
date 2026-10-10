package ldap

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// raObject is an AD object tracked by identity (pointer), so it can be
// renamed while remaining "the same" member - exactly as AD tracks group
// membership by object identity rather than by DN string.
type raObject struct {
	guid string // canonical dashed GUID; "" simulates a member lacking a GUID in the extended DN
	dn   string // current DN as AD would report it
	sid  string // optional hex SID emitted in the extended DN

	// Directory attributes served to resolver searches (see directorySearch).
	dirSID string // S-... string form; "" = object has no objectSid
	upn    string
	sam    string
}

// renameAwareMembershipClient is a Client test double that models AD member
// semantics faithfully enough to exercise the stale-DN rename scenario:
//   - membership is stored by object identity, so renames are reflected in
//     every subsequent read;
//   - LDAP_SERVER_EXTENDED_DN_OID is honoured on reads (hex GUID form);
//   - "<GUID=...>" alternative-DN values are resolved on writes, and literal
//     DNs that no longer exist (stale) are rejected with noSuchObject;
//   - optional MaxValRange emulation returns "member;range=0-N" instead of
//     "member" for large groups;
//   - every write records a membership snapshot so tests can prove a member
//     was never transiently absent.
//
// Searches for anything other than the group are answered as a directory
// lookup (see directorySearch).
//
// Client methods not overridden here are delegated to the embedded
// MockGroupMembershipClient.
type renameAwareMembershipClient struct {
	*MockGroupMembershipClient

	groupGUID string
	groupDN   string
	objects   []*raObject
	members   []*raObject

	rangeLimit int // >0 emulates AD MaxValRange

	modifies         []*ModifyRequest
	history          [][]*raObject
	searchControls   [][]ldap.Control
	resolverSearches []*SearchRequest
}

// newRenameAwareMembershipClient models the group raGroupGUID at raGroupDN; tests
// that need a different group GUID (e.g. not-found cases) overwrite groupGUID.
func newRenameAwareMembershipClient() *renameAwareMembershipClient {
	return &renameAwareMembershipClient{
		MockGroupMembershipClient: NewMockGroupMembershipClient(),
		groupGUID:                 raGroupGUID,
		groupDN:                   raGroupDN,
	}
}

func (c *renameAwareMembershipClient) addObject(guid, dn string) *raObject {
	o := &raObject{guid: guid, dn: dn}
	c.objects = append(c.objects, o)
	return o
}

func (c *renameAwareMembershipClient) setMembers(objs ...*raObject) {
	c.members = append([]*raObject(nil), objs...)
}

func (c *renameAwareMembershipClient) rename(o *raObject, newDN string) {
	o.dn = newDN
}

func (c *renameAwareMembershipClient) isMember(o *raObject) bool {
	return slices.Contains(c.members, o)
}

func (c *renameAwareMembershipClient) memberDNs() []string {
	out := make([]string, 0, len(c.members))
	for _, m := range c.members {
		out = append(out, m.dn)
	}
	slices.Sort(out)
	return out
}

// neverAbsent reports whether o was a member after every recorded write.
func (c *renameAwareMembershipClient) neverAbsent(o *raObject) bool {
	for _, snap := range c.history {
		if !slices.Contains(snap, o) {
			return false
		}
	}
	return true
}

// rawGUIDHex renders a canonical GUID as AD's hex extended-DN form: the hex of
// the raw 16 objectGUID bytes in AD's mixed-endian on-the-wire order.
func rawGUIDHex(t testing.TB, guid string) string {
	t.Helper()
	b, err := NewGUIDHandler().StringToGUIDBytes(guid)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

func hasControl(controls []ldap.Control, oid string) bool {
	for _, ctl := range controls {
		if ctl.GetControlType() == oid {
			return true
		}
	}
	return false
}

func (c *renameAwareMembershipClient) Search(_ context.Context, req *SearchRequest) (*SearchResult, error) {
	c.searchControls = append(c.searchControls, req.Controls)

	wantFilter, err := NewGUIDHandler().GUIDToSearchFilter(c.groupGUID)
	if err != nil {
		return nil, err
	}
	rangeLo := -1 // >=0: follow-up "member;range=<lo>-*" read of the group
	if req.Scope == ScopeBaseObject && DNEqual(req.BaseDN, c.groupDN) && len(req.Attributes) == 1 &&
		strings.HasPrefix(req.Attributes[0], "member;range=") {
		spec := strings.TrimSuffix(strings.TrimPrefix(req.Attributes[0], "member;range="), "-*")
		lo, err := strconv.Atoi(spec)
		if err != nil {
			return nil, err
		}
		rangeLo = lo
	} else if req.Filter != wantFilter {
		return c.directorySearch(req)
	}

	extended := hasControl(req.Controls, ldap.ControlTypeMicrosoftExtendedDN)
	values := make([]string, 0, len(c.members))
	for _, m := range c.members {
		if !extended {
			values = append(values, m.dn)
			continue
		}
		var b strings.Builder
		if m.guid != "" {
			raw, err := NewGUIDHandler().StringToGUIDBytes(m.guid)
			if err != nil {
				return nil, err
			}
			b.WriteString("<GUID=" + hex.EncodeToString(raw) + ">;")
		}
		if m.sid != "" {
			b.WriteString("<SID=" + m.sid + ">;")
		}
		b.WriteString(m.dn)
		values = append(values, b.String())
	}

	guidBytes, err := NewGUIDHandler().StringToGUIDBytes(c.groupGUID)
	if err != nil {
		return nil, err
	}
	entry := &ldap.Entry{
		DN: c.groupDN,
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", ByteValues: [][]byte{guidBytes}},
			{Name: "distinguishedName", Values: []string{c.groupDN}},
			{Name: "cn", Values: []string{"G"}},
			{Name: "sAMAccountName", Values: []string{"g"}},
		},
	}
	if len(values) > 0 {
		name := "member"
		switch {
		case rangeLo >= 0:
			hi := rangeLo + c.rangeLimit
			if c.rangeLimit <= 0 || hi >= len(values) {
				name = fmt.Sprintf("member;range=%d-*", rangeLo)
				values = values[rangeLo:]
			} else {
				name = fmt.Sprintf("member;range=%d-%d", rangeLo, hi-1)
				values = values[rangeLo:hi]
			}
		case c.rangeLimit > 0 && len(values) > c.rangeLimit:
			name = fmt.Sprintf("member;range=0-%d", c.rangeLimit-1)
			values = values[:c.rangeLimit]
		}
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: name, Values: values})
	}
	return &SearchResult{Entries: []*ldap.Entry{entry}, Total: 1}, nil
}

func (c *renameAwareMembershipClient) resolve(value string) (*raObject, error) {
	if IsAltGUIDDN(value) {
		inner := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(value), "<GUID="), ">")
		guid, err := NewGUIDHandler().NormalizeGUID(inner)
		if err != nil {
			return nil, ldap.NewError(ldap.LDAPResultInvalidDNSyntax, err)
		}
		for _, o := range c.objects {
			if o.guid == guid {
				return o, nil
			}
		}
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("no object with GUID %s", guid))
	}
	for _, o := range c.objects {
		if DNEqual(o.dn, value) {
			return o, nil
		}
	}
	return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("no object at DN %s", value))
}

func (c *renameAwareMembershipClient) Modify(_ context.Context, req *ModifyRequest) error {
	c.modifies = append(c.modifies, req)
	defer func() { c.history = append(c.history, append([]*raObject(nil), c.members...)) }()

	if !DNEqual(req.DN, c.groupDN) {
		return ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("group not found: %s", req.DN))
	}

	if vals, ok := req.ReplaceAttributes["member"]; ok {
		next := make([]*raObject, 0, len(vals))
		for _, v := range vals {
			o, err := c.resolve(v)
			if err != nil {
				return err
			}
			next = append(next, o)
		}
		c.members = next
	}
	if slices.Contains(req.DeleteAttributes, "member") {
		c.members = nil
	}
	// Value-level delete; the permissive-modify control makes absent values a no-op.
	for _, v := range req.DeleteValues["member"] {
		// Match the stored link value (by literal DN or GUID form), not the
		// directory object currently at that DN.
		c.members = slices.DeleteFunc(c.members, func(m *raObject) bool {
			if IsAltGUIDDN(v) {
				return v == "<GUID="+m.guid+">"
			}
			return DNEqual(m.dn, v)
		})
	}
	if vals, ok := req.AddAttributes["member"]; ok {
		staged := append([]*raObject(nil), c.members...)
		for _, v := range vals {
			o, err := c.resolve(v)
			if err != nil {
				return err
			}
			if slices.Contains(staged, o) {
				return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, fmt.Errorf("member already exists: %s", v))
			}
			staged = append(staged, o)
		}
		c.members = staged
	}
	return nil
}

// removalWrites counts writes that could drop members (replace / delete).
func (c *renameAwareMembershipClient) removalWrites() int {
	n := 0
	for _, m := range c.modifies {
		if _, ok := m.ReplaceAttributes["member"]; ok || slices.Contains(m.DeleteAttributes, "member") || len(m.DeleteValues["member"]) > 0 {
			n++
		}
	}
	return n
}

func (c *renameAwareMembershipClient) addedValues() []string {
	var out []string
	for _, m := range c.modifies {
		out = append(out, m.AddAttributes["member"]...)
	}
	return out
}

const (
	raGroupGUID = "12345678-1234-1234-1234-123456789012"
	raGroupDN   = "CN=G,OU=Groups,DC=example,DC=com"
	raGUIDA     = "aaaaaaaa-1111-2222-3333-444444444444"
	raGUIDB     = "bbbbbbbb-1111-2222-3333-444444444444"
	raGUIDC     = "cccccccc-1111-2222-3333-444444444444"
	raGUIDD     = "dddddddd-1111-2222-3333-444444444444"
	raDNAOld    = "CN=Alice,OU=Users,DC=example,DC=com"
	raDNANew    = "CN=Alice Renamed,OU=Users,DC=example,DC=com"
	raDNB       = "CN=Bob,OU=Users,DC=example,DC=com"
	raDNC       = "CN=Carol,OU=Users,DC=example,DC=com"
	raDND       = "CN=Dave,OU=Users,DC=example,DC=com"
)

func newRenameAwareManager(t *testing.T) (*GroupMembershipManager, *renameAwareMembershipClient) {
	t.Helper()
	c := newRenameAwareMembershipClient()
	gmm := NewGroupMembershipManager(t.Context(), c, "DC=example,DC=com", nil)
	return gmm, c
}

// A desired DN that is stale because the member was renamed (earlier in the
// same apply) while its GUID is known: the renamed member is left alone - no
// removal write, never absent, never re-added - whatever else changes.
func TestSetGroupMembers_StaleDesiredDN(t *testing.T) {
	tests := []struct {
		name              string
		members           []string // initially members: "a" (renamed), "b"
		dExists           bool     // whether D exists in the directory (else adding D fails)
		renameB           bool
		desired           []string
		guids             map[string]string
		wantErr           bool
		wantAdded         []string
		wantRemovalWrites int
		wantDNs           []string
		snapshot          bool // pass GetCurrentMembers' result: no second member read
	}{
		{
			name:    "matching GUID, unchanged: no writes",
			members: []string{"a", "b"},
			desired: []string{raDNAOld, raDNB},
			guids:   map[string]string{raDNAOld: raGUIDA, raDNB: raGUIDB},
			wantDNs: []string{raDNANew, raDNB},
		},
		{
			name:              "other member removed: renamed member untouched",
			members:           []string{"a", "b"},
			desired:           []string{raDNAOld},
			guids:             map[string]string{raDNAOld: raGUIDA},
			wantRemovalWrites: 1,
			wantDNs:           []string{raDNANew},
		},
		{
			name:              "removal uses AD's current DN even if the removed member was renamed too",
			members:           []string{"a", "b"},
			renameB:           true,
			desired:           []string{raDNAOld},
			guids:             map[string]string{raDNAOld: raGUIDA},
			wantRemovalWrites: 1,
			wantDNs:           []string{raDNANew},
		},
		{
			name:              "other member removed, decided from a current snapshot",
			members:           []string{"a", "b"},
			desired:           []string{raDNAOld},
			guids:             map[string]string{raDNAOld: raGUIDA},
			wantRemovalWrites: 1,
			wantDNs:           []string{raDNANew},
			snapshot:          true,
		},
		{
			name:      "new member: added via GUID form only",
			members:   []string{"a"},
			dExists:   true,
			desired:   []string{raDNAOld, raDND},
			guids:     map[string]string{raDNAOld: raGUIDA, raDND: raGUIDD},
			wantAdded: []string{"<GUID=" + raGUIDD + ">"},
			wantDNs:   []string{raDNANew, raDND},
		},
		{
			name:    "failing add never costs the renamed member its membership",
			members: []string{"a"},
			desired: []string{raDNAOld, raDND},
			guids:   map[string]string{raDNAOld: raGUIDA, raDND: raGUIDD},
			wantErr: true,
			// The attempted write is recorded even though D cannot be resolved.
			wantAdded: []string{"<GUID=" + raGUIDD + ">"},
			wantDNs:   []string{raDNANew},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gmm, c := newRenameAwareManager(t)
			a := c.addObject(raGUIDA, raDNAOld)
			b := c.addObject(raGUIDB, raDNB)
			if tc.dExists {
				c.addObject(raGUIDD, raDND)
			}
			byName := map[string]*raObject{"a": a, "b": b}
			var initial []*raObject
			for _, m := range tc.members {
				initial = append(initial, byName[m])
			}
			c.setMembers(initial...)
			c.rename(a, raDNANew) // renamed earlier in the same apply; caller still holds raDNAOld
			if tc.renameB {
				c.rename(b, "cn=Bob Renamed,ou=Users,dc=example,dc=com")
			}

			var current []CurrentMember
			if tc.snapshot {
				var err error
				current, err = gmm.GetCurrentMembers(raGroupGUID)
				require.NoError(t, err)
			}

			err := gmm.SetGroupMembers(raGroupGUID, tc.desired, tc.guids, current)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.True(t, c.neverAbsent(a), "renamed member must never be transiently removed")
			assert.Equal(t, tc.wantAdded, c.addedValues())
			assert.Equal(t, tc.wantRemovalWrites, c.removalWrites())
			assert.Equal(t, tc.wantDNs, c.memberDNs())
			if tc.snapshot {
				assert.Equal(t, 1, c.extendedDNSearches(), "no second member read")
			}
		})
	}
}

// --- Mixed-endian GUID conversion & extended DN parsing ---------------------

func TestExtendedDNGUIDToString(t *testing.T) {
	h := NewGUIDHandler()

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		// Vector taken verbatim from MS-ADTS 3.1.1.3.4.1.5: the same object's
		// GUID in Flag 0 (hex of raw bytes) and Flag 1 (dashed) form.
		{name: "MS-ADTS hex vector (mixed-endian raw bytes)", in: "b3d4bfbd3c45ee4298e27b4a698a61b8", want: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8"},
		{name: "MS-ADTS dashed vector", in: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8", want: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8"},
		{name: "uppercase hex", in: "B3D4BFBD3C45EE4298E27B4A698A61B8", want: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8"},
		{name: "uppercase dashed", in: "BDBFD4B3-453C-42EE-98E2-7B4A698A61B8", want: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8"},
		{name: "surrounding whitespace", in: "  b3d4bfbd3c45ee4298e27b4a698a61b8 ", want: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8"},
		{name: "hex is NOT treated as compact dashed form", in: "bdbfd4b3453c42ee98e27b4a698a61b8", want: "b3d4bfbd-3c45-ee42-98e2-7b4a698a61b8"},
		{name: "too short", in: "b3d4bfbd3c45ee4298e27b4a698a61", wantErr: true},
		{name: "too long", in: "b3d4bfbd3c45ee4298e27b4a698a61b8aa", wantErr: true},
		{name: "non-hex", in: "zzd4bfbd3c45ee4298e27b4a698a61b8", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := h.ExtendedDNGUIDToString(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("round trip with StringToGUIDBytes", func(t *testing.T) {
		for _, guid := range []string{raGUIDA, raGroupGUID, "00112233-4455-6677-8899-aabbccddeeff"} {
			got, err := h.ExtendedDNGUIDToString(rawGUIDHex(t, guid))
			require.NoError(t, err)
			assert.Equal(t, guid, got)
		}
	})
}

func TestParseExtendedDN(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    ExtendedDN
		wantErr bool
	}{
		{
			name: "MS-ADTS hex form with SID",
			in:   "<GUID=b3d4bfbd3c45ee4298e27b4a698a61b8>;<SID=01050000000000051500000061eb5b8c50ef705befda808bf4010000>;CN=Administrator,CN=Users,DC=Fabrikam,DC=com",
			want: ExtendedDN{GUID: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8", SID: "01050000000000051500000061eb5b8c50ef705befda808bf4010000", DN: "CN=Administrator,CN=Users,DC=Fabrikam,DC=com"},
		},
		{
			name: "MS-ADTS string form with SID",
			in:   "<GUID=bdbfd4b3-453c-42ee-98e2-7b4a698a61b8>;<SID=S-1-5-21-2354834273-1534127952-2340477679-500>;CN=Administrator,CN=Users,DC=Fabrikam,DC=com",
			want: ExtendedDN{GUID: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8", SID: "S-1-5-21-2354834273-1534127952-2340477679-500", DN: "CN=Administrator,CN=Users,DC=Fabrikam,DC=com"},
		},
		{
			name: "no SID (object without objectSid)",
			in:   "<GUID=b3d4bfbd3c45ee4298e27b4a698a61b8>;CN=Contact,OU=X,DC=example,DC=com",
			want: ExtendedDN{GUID: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8", DN: "CN=Contact,OU=X,DC=example,DC=com"},
		},
		{
			name: "plain DN without extended components",
			in:   "CN=S-1-5-21-1-2-3-1001,CN=ForeignSecurityPrincipals,DC=example,DC=com",
			want: ExtendedDN{DN: "CN=S-1-5-21-1-2-3-1001,CN=ForeignSecurityPrincipals,DC=example,DC=com"},
		},
		{
			name: "SID only (no GUID component)",
			in:   "<SID=S-1-5-21-1-2-3-1001>;CN=Foreign,DC=example,DC=com",
			want: ExtendedDN{SID: "S-1-5-21-1-2-3-1001", DN: "CN=Foreign,DC=example,DC=com"},
		},
		{
			name: "lowercase component key and unknown component ignored",
			in:   "<guid=b3d4bfbd3c45ee4298e27b4a698a61b8>;<WKGUID=xyz>;CN=A,DC=example,DC=com",
			want: ExtendedDN{GUID: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8", DN: "CN=A,DC=example,DC=com"},
		},
		{
			name: "DN with escaped special characters",
			in:   `<GUID=b3d4bfbd3c45ee4298e27b4a698a61b8>;CN=Smith\, John \<x\>\;y,OU=Users,DC=example,DC=com`,
			want: ExtendedDN{GUID: "bdbfd4b3-453c-42ee-98e2-7b4a698a61b8", DN: `CN=Smith\, John \<x\>\;y,OU=Users,DC=example,DC=com`},
		},
		{name: "unterminated component", in: "<GUID=b3d4bfbd3c45ee4298e27b4a698a61b8;CN=A,DC=x", wantErr: true},
		{name: "component without '='", in: "<GUID>;CN=A,DC=x", wantErr: true},
		{name: "malformed GUID", in: "<GUID=nothex>;CN=A,DC=x", wantErr: true},
		{name: "no DN part", in: "<GUID=b3d4bfbd3c45ee4298e27b4a698a61b8>;", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseExtendedDN(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, *got)
		})
	}
}

func TestNewExtendedDNControl(t *testing.T) {
	ctl := NewExtendedDNControl()
	assert.Equal(t, "1.2.840.113556.1.4.529", ctl.GetControlType())

	cs, ok := ctl.(*ldap.ControlString)
	require.True(t, ok)
	assert.True(t, cs.Criticality, "control must be critical so unsupported servers fail instead of silently degrading")
	assert.Empty(t, cs.ControlValue, "omitted controlValue == Flag 0 (hex form), supported by every AD version")

	// Encoded control: SEQUENCE { OID, BOOLEAN TRUE } with no value.
	pkt := ctl.Encode()
	require.Len(t, pkt.Children, 2)
}

// --- CalculateMembershipDeltaWithGUIDs -----------------------------------

func calcDelta(t *testing.T, gmm *GroupMembershipManager, desired []string, guids map[string]string) *MembershipDelta {
	t.Helper()
	d, err := gmm.CalculateMembershipDeltaWithGUIDs(raGroupGUID, desired, guids, nil)
	require.NoError(t, err)
	return d
}

func (c *renameAwareMembershipClient) extendedDNSearches() int {
	n := 0
	for _, ctls := range c.searchControls {
		if hasControl(ctls, ldap.ControlTypeMicrosoftExtendedDN) {
			n++
		}
	}
	return n
}

func TestCalculateMembershipDeltaWithGUIDs_LegacyEquivalence(t *testing.T) {
	cases := map[string]map[string]string{
		"nil map":                  nil,
		"empty map":                {},
		"GUIDs only for other DNs": {raDNC: raGUIDC},
		"empty GUID value":         {raDNAOld: ""},
		"malformed GUID value":     {raDNAOld: "not-a-guid"},
	}
	for name, guids := range cases {
		t.Run(name, func(t *testing.T) {
			gmm, c := newRenameAwareManager(t)
			a := c.addObject(raGUIDA, raDNAOld)
			b := c.addObject(raGUIDB, raDNB)
			c.setMembers(a, b)
			c.rename(a, raDNANew)
			desired := []string{raDNAOld, raDND}

			legacy, err := gmm.CalculateMembershipDelta(raGroupGUID, desired)
			require.NoError(t, err)
			got := calcDelta(t, gmm, desired, guids)

			assert.Equal(t, legacy, got)
			// Legacy (DN-only) semantics: stale DN is "add", renamed DN is "remove".
			assert.Equal(t, []string{raDNAOld, raDND}, got.ToAdd)
			assert.Equal(t, []string{raDNANew, raDNB}, got.ToRemove)
			assert.Zero(t, c.extendedDNSearches(), "legacy path must not issue the extended-DN search")
		})
	}
}

func TestSetGroupMembers_NilGUIDs_LegacyBehavior(t *testing.T) {
	gmm, c := newRenameAwareManager(t)
	a := c.addObject(raGUIDA, raDNAOld)
	b := c.addObject(raGUIDB, raDNB)
	d := c.addObject(raGUIDD, raDND)
	c.setMembers(a, b)

	require.NoError(t, gmm.SetGroupMembers(raGroupGUID, []string{raDNAOld, raDND}, nil, nil))

	assert.Zero(t, c.extendedDNSearches())
	assert.Equal(t, []string{raDND}, c.addedValues(), "nil memberGUIDs writes literal DNs")
	assert.True(t, c.isMember(a))
	assert.False(t, c.isMember(b))
	assert.True(t, c.isMember(d))
}

func TestCalculateMembershipDeltaWithGUIDs_Matrix(t *testing.T) {
	type member struct {
		guid, dn string
	}
	tests := []struct {
		name       string
		current    []member
		desired    []string
		guids      map[string]string
		wantAdd    []string
		wantRemove []string
	}{
		{
			name:    "stale desired DN + matching GUID => unchanged",
			current: []member{{raGUIDA, raDNANew}, {raGUIDB, raDNB}},
			desired: []string{raDNAOld, raDNB},
			guids:   map[string]string{raDNAOld: raGUIDA, raDNB: raGUIDB},
		},
		{
			name:       "stale DN + other member removed => only other removed",
			current:    []member{{raGUIDA, raDNANew}, {raGUIDB, raDNB}},
			desired:    []string{raDNAOld},
			guids:      map[string]string{raDNAOld: raGUIDA},
			wantRemove: []string{raDNB},
		},
		{
			name:    "new member with GUID => add",
			current: []member{{raGUIDA, raDNANew}},
			desired: []string{raDNAOld, raDND},
			guids:   map[string]string{raDNAOld: raGUIDA, raDND: raGUIDD},
			wantAdd: []string{raDND},
		},
		{
			name:       "desired GUID absent although DN matches a different current object => remove + add",
			current:    []member{{raGUIDB, raDNC}},
			desired:    []string{raDNC},
			guids:      map[string]string{raDNC: raGUIDC},
			wantAdd:    []string{raDNC},
			wantRemove: []string{raDNC},
		},
		{
			name:       "current member not desired => remove using AD's current DN",
			current:    []member{{raGUIDA, raDNANew}, {raGUIDB, "cn=Bob Renamed,ou=Users,dc=example,dc=com"}},
			desired:    []string{raDNAOld},
			guids:      map[string]string{raDNAOld: raGUIDA},
			wantRemove: []string{"cn=Bob Renamed,ou=Users,dc=example,dc=com"},
		},
		{
			name:       "mixed: some desired with GUID, some without",
			current:    []member{{raGUIDA, raDNANew}, {raGUIDB, raDNB}, {raGUIDC, raDNC}},
			desired:    []string{raDNAOld, raDNC, raDND},
			guids:      map[string]string{raDNAOld: raGUIDA},
			wantAdd:    []string{raDND},
			wantRemove: []string{raDNB},
		},
		{
			name:       "mixed: desired without GUID still matched by DN case-insensitively",
			current:    []member{{raGUIDA, raDNANew}, {raGUIDC, raDNC}},
			desired:    []string{raDNAOld, strings.ToLower(raDNC)},
			guids:      map[string]string{raDNAOld: raGUIDA},
			wantRemove: nil,
		},
		{
			name:    "case-insensitive GUID compare (uppercase supplied)",
			current: []member{{raGUIDA, raDNANew}},
			desired: []string{raDNAOld},
			guids:   map[string]string{raDNAOld: strings.ToUpper(raGUIDA)},
		},
		{
			name:    "malformed GUID for one DN falls back to DN comparison for that DN only",
			current: []member{{raGUIDA, raDNANew}, {raGUIDB, raDNB}},
			desired: []string{raDNAOld, raDNB},
			guids:   map[string]string{raDNAOld: raGUIDA, raDNB: "garbage"},
		},
		{
			name:    "duplicates: identical desired DN twice",
			current: []member{{raGUIDA, raDNANew}},
			desired: []string{raDNAOld, raDNAOld, raDND, raDND},
			guids:   map[string]string{raDNAOld: raGUIDA, raDND: raGUIDD},
			wantAdd: []string{raDND},
		},
		{
			name:    "duplicates: case variants of a desired DN, only one carrying a GUID",
			current: []member{},
			desired: []string{raDND, strings.ToUpper(raDND)},
			guids:   map[string]string{strings.ToUpper(raDND): raGUIDD},
			wantAdd: []string{strings.ToUpper(raDND)},
		},
		{
			name:    "duplicates: stale and fresh DN for the same GUID, present => nothing",
			current: []member{{raGUIDA, raDNANew}},
			desired: []string{raDNAOld, raDNANew},
			guids:   map[string]string{raDNAOld: raGUIDA, raDNANew: raGUIDA},
		},
		{
			name:    "duplicates: stale and fresh DN for the same GUID, absent => single add",
			current: []member{},
			desired: []string{raDNAOld, raDNANew},
			guids:   map[string]string{raDNAOld: raGUIDA, raDNANew: raGUIDA},
			// Deterministic: lexicographically first DN ("CN=Alice Renamed" < "CN=Alice,").
			wantAdd: []string{raDNANew},
		},
		{
			name:    "current member lacking GUID (FSP) matched by DN against desired with GUID",
			current: []member{{"", "CN=S-1-5-21-9-9-9-1001,CN=ForeignSecurityPrincipals,DC=example,DC=com"}, {raGUIDA, raDNANew}},
			desired: []string{"CN=S-1-5-21-9-9-9-1001,CN=ForeignSecurityPrincipals,DC=example,DC=com", raDNAOld},
			guids: map[string]string{
				"CN=S-1-5-21-9-9-9-1001,CN=ForeignSecurityPrincipals,DC=example,DC=com": raGUIDD,
				raDNAOld: raGUIDA,
			},
		},
		{
			name:       "current member lacking GUID and not desired => removed by DN",
			current:    []member{{"", "CN=S-1-5-21-9-9-9-1001,CN=ForeignSecurityPrincipals,DC=example,DC=com"}, {raGUIDA, raDNANew}},
			desired:    []string{raDNAOld},
			guids:      map[string]string{raDNAOld: raGUIDA},
			wantRemove: []string{"CN=S-1-5-21-9-9-9-1001,CN=ForeignSecurityPrincipals,DC=example,DC=com"},
		},
		{
			name:       "current member lacking GUID at a different DN => remove + add",
			current:    []member{{"", raDNC}},
			desired:    []string{raDND},
			guids:      map[string]string{raDND: raGUIDD},
			wantAdd:    []string{raDND},
			wantRemove: []string{raDNC},
		},
		{
			name:       "desired (with GUIDs) disjoint from current => remove all current",
			current:    []member{{raGUIDB, raDNB}, {raGUIDC, raDNC}},
			desired:    []string{raDND},
			guids:      map[string]string{raDND: raGUIDD},
			wantAdd:    []string{raDND},
			wantRemove: []string{raDNB, raDNC},
		},
		{
			name:    "empty current => add all desired",
			current: []member{},
			desired: []string{raDNAOld, raDNB, raDNC},
			guids:   map[string]string{raDNAOld: raGUIDA, raDNB: raGUIDB},
			wantAdd: []string{raDNAOld, raDNB, raDNC},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gmm, c := newRenameAwareManager(t)
			members := make([]*raObject, 0, len(tt.current))
			for _, m := range tt.current {
				members = append(members, c.addObject(m.guid, m.dn))
			}
			c.setMembers(members...)

			got := calcDelta(t, gmm, tt.desired, tt.guids)
			assert.Equal(t, tt.wantAdd, got.ToAdd, "ToAdd")
			assert.Equal(t, tt.wantRemove, got.ToRemove, "ToRemove")
			assert.Equal(t, 1, c.extendedDNSearches(), "GUID path must read current members in a single extended-DN search")
		})
	}
}

func TestCalculateMembershipDeltaWithGUIDs_EmptyDesiredRemovesAll(t *testing.T) {
	gmm, c := newRenameAwareManager(t)
	c.setMembers(c.addObject(raGUIDA, raDNANew), c.addObject(raGUIDB, raDNB))

	got := calcDelta(t, gmm, []string{}, map[string]string{raDNAOld: raGUIDA})
	assert.Empty(t, got.ToAdd)
	assert.Equal(t, []string{raDNANew, raDNB}, got.ToRemove)
}

func TestCalculateMembershipDeltaWithGUIDs_Errors(t *testing.T) {
	t.Run("empty group GUID", func(t *testing.T) {
		gmm, _ := newRenameAwareManager(t)
		_, err := gmm.CalculateMembershipDeltaWithGUIDs("", []string{raDNB}, map[string]string{raDNB: raGUIDB}, nil)
		assert.Error(t, err)
	})
	t.Run("invalid desired DN", func(t *testing.T) {
		gmm, _ := newRenameAwareManager(t)
		_, err := gmm.CalculateMembershipDeltaWithGUIDs(raGroupGUID, []string{"not a dn"}, map[string]string{"not a dn": raGUIDB}, nil)
		assert.Error(t, err)
	})
	t.Run("invalid group GUID", func(t *testing.T) {
		gmm, _ := newRenameAwareManager(t)
		_, err := gmm.CalculateMembershipDeltaWithGUIDs("zzz", []string{raDNB}, map[string]string{raDNB: raGUIDB}, nil)
		assert.Error(t, err)
	})
	t.Run("group not found", func(t *testing.T) {
		gmm, c := newRenameAwareManager(t)
		c.groupGUID = raGUIDC // mock now only answers for a different group
		_, err := gmm.CalculateMembershipDeltaWithGUIDs(raGroupGUID, []string{raDNB}, map[string]string{raDNB: raGUIDB}, nil)
		assert.True(t, IsNotFoundError(err), "got %v", err)
	})
}

// failingSearchClient fails or corrupts the extended-DN search.
type failingSearchClient struct {
	*renameAwareMembershipClient
	err         error
	memberValue string
}

func (f *failingSearchClient) Search(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	if !hasControl(req.Controls, ldap.ControlTypeMicrosoftExtendedDN) {
		return f.renameAwareMembershipClient.Search(ctx, req)
	}
	if f.err != nil {
		return nil, f.err
	}
	res, err := f.renameAwareMembershipClient.Search(ctx, req)
	if err != nil {
		return nil, err
	}
	res.Entries[0].Attributes = append(res.Entries[0].Attributes, &ldap.EntryAttribute{Name: "member", Values: []string{f.memberValue}})
	return res, nil
}

func TestSetGroupMembers_GUIDPathReadFailures_NoWrites(t *testing.T) {
	t.Run("search error (insufficientAccessRights)", func(t *testing.T) {
		inner := newRenameAwareMembershipClient()
		inner.setMembers(inner.addObject(raGUIDB, raDNB))
		fc := &failingSearchClient{renameAwareMembershipClient: inner, err: ldap.NewError(ldap.LDAPResultInsufficientAccessRights, fmt.Errorf("denied"))}
		gmm := NewGroupMembershipManager(t.Context(), fc, "DC=example,DC=com", nil)

		err := gmm.SetGroupMembers(raGroupGUID, []string{raDND}, map[string]string{raDND: raGUIDD}, nil)
		require.Error(t, err)
		assert.Empty(t, inner.modifies)
	})
	t.Run("malformed extended DN value", func(t *testing.T) {
		inner := newRenameAwareMembershipClient()
		fc := &failingSearchClient{renameAwareMembershipClient: inner, memberValue: "<GUID=nothex>;CN=X,DC=example,DC=com"}
		gmm := NewGroupMembershipManager(t.Context(), fc, "DC=example,DC=com", nil)

		err := gmm.SetGroupMembers(raGroupGUID, []string{raDND}, map[string]string{raDND: raGUIDD}, nil)
		require.Error(t, err)
		assert.Empty(t, inner.modifies)
	})
}

// --- SetGroupMembers end-to-end with the rename-aware AD model --------------

func TestSetGroupMembers_RecreatedObjectSameDN_ReplacedByGUID(t *testing.T) {
	gmm, c := newRenameAwareManager(t)
	old := &raObject{guid: raGUIDB, dn: raDNC} // deleted object, still a member value
	c.setMembers(old)
	fresh := c.addObject(raGUIDC, raDNC) // recreated at the same DN

	require.NoError(t, gmm.SetGroupMembers(raGroupGUID, []string{raDNC}, map[string]string{raDNC: raGUIDC}, nil))

	assert.Equal(t, []*raObject{fresh}, c.members)
	assert.Equal(t, []string{"<GUID=" + raGUIDC + ">"}, c.addedValues())
}

func TestSetGroupMembers_Mixed_EndToEnd(t *testing.T) {
	gmm, c := newRenameAwareManager(t)
	a := c.addObject(raGUIDA, raDNAOld)
	b := c.addObject(raGUIDB, raDNB)
	cc := c.addObject(raGUIDC, raDNC)
	d := c.addObject(raGUIDD, raDND)
	c.setMembers(a, b, cc)
	c.rename(a, raDNANew)

	// A: stale DN + GUID (keep). C: DN only (keep). D: DN only (add). B: drop.
	require.NoError(t, gmm.SetGroupMembers(raGroupGUID, []string{raDNAOld, raDNC, raDND}, map[string]string{raDNAOld: raGUIDA}, nil))

	assert.True(t, c.neverAbsent(a))
	assert.True(t, c.neverAbsent(cc))
	assert.False(t, c.isMember(b))
	assert.True(t, c.isMember(d))
	assert.Equal(t, []string{raDND}, c.addedValues(), "member without GUID is written as literal DN")
}

func TestSetGroupMembers_EmptyCurrentAddsAllWithGUIDForm(t *testing.T) {
	gmm, c := newRenameAwareManager(t)
	a := c.addObject(raGUIDA, raDNANew)
	b := c.addObject(raGUIDB, raDNB)

	// A's desired DN is stale; the GUID form makes the add succeed anyway.
	require.NoError(t, gmm.SetGroupMembers(raGroupGUID, []string{raDNAOld, raDNB}, map[string]string{raDNAOld: raGUIDA, raDNB: raGUIDB}, nil))

	assert.Equal(t, 0, c.removalWrites())
	assert.True(t, c.isMember(a))
	assert.True(t, c.isMember(b))
}

// Groups beyond AD's MaxValRange: the server returns "member;range=0-N" and
// the remaining values are fetched via follow-up range requests. The full
// membership is therefore seen, B is the only member dropped, and renamed A is
// recognised by GUID and never absent.
func TestSetGroupMembers_RangedMemberAttribute_FollowsRanges(t *testing.T) {
	gmm, c := newRenameAwareManager(t)
	c.rangeLimit = 2
	a := c.addObject(raGUIDA, raDNAOld)
	b := c.addObject(raGUIDB, raDNB)
	cc := c.addObject(raGUIDC, raDNC)
	c.setMembers(a, b, cc)
	c.rename(a, raDNANew)

	desired := []string{raDNAOld, raDNC}
	guids := map[string]string{raDNAOld: raGUIDA, raDNC: raGUIDC}

	got := calcDelta(t, gmm, desired, guids)
	assert.Equal(t, []string{raDNB}, got.ToRemove)
	assert.Empty(t, got.ToAdd)

	require.NoError(t, gmm.SetGroupMembers(raGroupGUID, desired, guids, nil))
	assert.True(t, c.neverAbsent(a))
	assert.False(t, c.isMember(b))
	assert.True(t, c.neverAbsent(cc))
}

// --- Graceful degradation when the extended-DN control is unsupported --------

func unavailableCriticalExtensionErr() error {
	return ldap.NewError(ldap.LDAPResultUnavailableCriticalExtension, fmt.Errorf("critical extension is unavailable"))
}

// newUnsupportedControlManager models a server rejecting the critical
// extended-DN control, with member B present and A (renamed) as desired.
func newUnsupportedControlManager(t *testing.T, searchErr error) (*GroupMembershipManager, *renameAwareMembershipClient) {
	t.Helper()
	inner := newRenameAwareMembershipClient()
	a := inner.addObject(raGUIDA, raDNAOld)
	b := inner.addObject(raGUIDB, raDNB)
	inner.addObject(raGUIDD, raDND)
	inner.setMembers(a, b)
	fc := &failingSearchClient{renameAwareMembershipClient: inner, err: searchErr}
	return NewGroupMembershipManager(t.Context(), fc, "DC=example,DC=com", nil), inner
}

func TestCalculateMembershipDeltaWithGUIDs_UnavailableCriticalExtension_FallsBackToLegacy(t *testing.T) {
	desired := []string{raDNAOld, raDND}
	guids := map[string]string{raDNAOld: raGUIDA, raDND: raGUIDD}

	for name, searchErr := range map[string]error{
		"bare":    unavailableCriticalExtensionErr(),
		"wrapped": WrapError("search", unavailableCriticalExtensionErr()),
	} {
		t.Run(name, func(t *testing.T) {
			gmm, _ := newUnsupportedControlManager(t, searchErr)

			legacy, err := gmm.CalculateMembershipDelta(raGroupGUID, desired)
			require.NoError(t, err)

			got, err := gmm.CalculateMembershipDeltaWithGUIDs(raGroupGUID, desired, guids, nil)
			require.NoError(t, err)
			assert.Equal(t, legacy, got, "fallback must equal the DN-based delta")
			assert.Equal(t, []string{raDND}, got.ToAdd)
			assert.Equal(t, []string{raDNB}, got.ToRemove)
		})
	}
}

func TestSetGroupMembers_UnavailableCriticalExtension_FallsBackAndWritesGUIDForm(t *testing.T) {
	gmm, c := newUnsupportedControlManager(t, unavailableCriticalExtensionErr())

	require.NoError(t, gmm.SetGroupMembers(raGroupGUID, []string{raDNAOld, raDND}, map[string]string{raDNAOld: raGUIDA, raDND: raGUIDD}, nil))

	assert.Equal(t, []string{"<GUID=" + raGUIDD + ">"}, c.addedValues(), "adds are still written in GUID form")
	assert.True(t, c.isMember(c.objects[2]))
	assert.False(t, c.isMember(c.objects[1]), "B removed by the DN-based delta")
}

func TestCalculateMembershipDeltaWithGUIDs_OtherReadErrors_NotMasked(t *testing.T) {
	desired := []string{raDNB}
	guids := map[string]string{raDNB: raGUIDB}

	for name, code := range map[string]uint16{
		"insufficientAccessRights": ldap.LDAPResultInsufficientAccessRights,
		"busy":                     ldap.LDAPResultBusy,
		"protocolError":            ldap.LDAPResultProtocolError,
		"unwillingToPerform":       ldap.LDAPResultUnwillingToPerform,
	} {
		t.Run(name, func(t *testing.T) {
			gmm, c := newUnsupportedControlManager(t, ldap.NewError(code, fmt.Errorf("boom")))

			_, err := gmm.CalculateMembershipDeltaWithGUIDs(raGroupGUID, desired, guids, nil)
			require.Error(t, err)
			assert.True(t, ldap.IsErrorWithCode(err, code), "got %v", err)

			require.Error(t, gmm.SetGroupMembers(raGroupGUID, desired, guids, nil))
			assert.Empty(t, c.modifies)
		})
	}

	t.Run("group not found", func(t *testing.T) {
		gmm, c := newRenameAwareManager(t)
		c.groupGUID = raGUIDC
		require.Error(t, gmm.SetGroupMembers(raGroupGUID, desired, guids, nil))
		assert.Empty(t, c.modifies)
	})
}

func TestGetCurrentMembers_UnavailableCriticalExtension_StillReturnsError(t *testing.T) {
	gmm, _ := newUnsupportedControlManager(t, unavailableCriticalExtensionErr())
	_, err := gmm.GetCurrentMembers(raGroupGUID)
	require.Error(t, err)
	assert.True(t, ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailableCriticalExtension), "got %v", err)
}

// With no usable GUIDs the extended-DN control is never sent, so a server
// lacking it is irrelevant and the legacy path is used unchanged.
func TestCalculateMembershipDeltaWithGUIDs_NoGUIDs_NeverSendsControl(t *testing.T) {
	gmm, c := newUnsupportedControlManager(t, unavailableCriticalExtensionErr())
	for _, guids := range []map[string]string{nil, {}} {
		_, err := gmm.CalculateMembershipDeltaWithGUIDs(raGroupGUID, []string{raDNB}, guids, nil)
		require.NoError(t, err)
	}
	assert.Equal(t, 0, c.extendedDNSearches())
}
