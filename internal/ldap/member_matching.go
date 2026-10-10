package ldap

import "strings"

// ResolveBatchAgainst is a drop-in replacement for ResolveBatch that first
// matches identifiers against a group's current members (as returned by
// GroupMembershipManager.GetCurrentMembers) and only resolves the remainder
// via LDAP.
//
// The return contract is ResolveBatch's: results and failures are keyed by
// the caller's verbatim identifier (whitespace preserved; matching uses the
// trimmed value), and empty or whitespace-only identifiers appear in neither
// map. Both maps are always non-nil.
//
// Per (trimmed) identifier, the type is detected with DetectIdentifierType:
//   - DN: matches a current member whose DN is equal after NormalizeDNCase,
//     compared case-insensitively (so attribute-type case, value case, RFC
//     4514 escaping style and spacing after separators are all ignored).
//   - GUID: matches a current member with the same objectGUID, in any format
//     NormalizeGUID accepts (hyphenated or compact, any case).
//   - SID: matches a current member with the same objectSid (as an "S-1-..."
//     string, canonicalised via ParseSID).
//   - UPN, SAM and unknown types never match: the extended DN carries no UPN
//     or sAMAccountName.
//
// A match yields ResolvedIdentifier{DN: the member's DN as AD currently
// reports it (CurrentMember.DN, NormalizeDNCase form), GUID: its canonical
// GUID} with no LDAP traffic and no cache access - AD's own current-member
// data is fresher than any cached entry, and writing partial entries would
// evict richer ones. For an identifier that names a current member, this is
// the same value ResolveBatch returns; additionally a member outside the
// normalizer's base DN (e.g. from another domain of the forest), which
// ResolveBatch's base-DN-scoped searches cannot find, resolves to AD's own
// identity for it.
//
// Only unambiguous matches short-circuit. A current member is not eligible
// for matching at all unless it has a GUID and a DN (so a
// matched result always carries a GUID and is guaranteed identical to what a
// lookup would produce); and a DN, GUID or SID key shared by two different
// current members (for example an FSP and a real object in another domain
// carrying the same SID) matches neither.
//
// Every identifier that does not match - UPN/SAM, new members, stale DNs of
// renamed objects, ambiguous keys, members missing from a truncated current
// view - is passed, deduplicated and in input order, to ResolveBatch in a
// single call, so its semantics (cache use, error messages, failures) are
// preserved exactly. Matching only ever resolves identity; it never decides
// membership, so a partial or empty current list is always safe. With a nil
// or empty current list this is exactly ResolveBatch(identifiers).
//
// Cost is O(len(identifiers) + len(current)): current members are indexed in
// maps once per call.
func (m *MemberNormalizer) ResolveBatchAgainst(identifiers []string, current []CurrentMember) (map[string]ResolvedIdentifier, map[string]error) {
	return m.resolveBatchAgainst(identifiers, current, m.ResolveBatch)
}

// batchResolver is the signature of ResolveBatch; a seam so tests can observe
// exactly which identifiers fall through to it and how many calls are made.
type batchResolver func(identifiers []string) (map[string]ResolvedIdentifier, map[string]error)

func (m *MemberNormalizer) resolveBatchAgainst(identifiers []string, current []CurrentMember, fallback batchResolver) (map[string]ResolvedIdentifier, map[string]error) {
	if len(current) == 0 {
		return fallback(identifiers)
	}

	index := indexCurrentMembers(current)
	results := make(map[string]ResolvedIdentifier, len(identifiers))
	failures := make(map[string]error)

	var unmatched []string
	queued := make(map[string]bool)
	for _, original := range identifiers {
		trimmed := strings.TrimSpace(original)
		if trimmed == "" {
			continue
		}
		if resolved, ok := index.lookup(m, trimmed); ok {
			results[original] = resolved
			continue
		}
		if !queued[original] {
			queued[original] = true
			unmatched = append(unmatched, original)
		}
	}

	if len(unmatched) == 0 {
		return results, failures
	}

	resolved, failed := fallback(unmatched)
	for k, v := range resolved {
		results[k] = v
	}
	for k, v := range failed {
		failures[k] = v
	}
	return results, failures
}

// ambiguousMember marks an index key shared by two different current members.
const ambiguousMember = -1

// currentMemberIndex indexes eligible current members by normalised DN,
// GUID and SID. Map values are positions in members, or ambiguousMember.
type currentMemberIndex struct {
	members []ResolvedIdentifier
	byDN    map[string]int
	byGUID  map[string]int
	bySID   map[string]int
}

// dnMatchKey is the case-insensitive comparison key for a DN already in
// NormalizeDNCase form.
func dnMatchKey(normalizedDN string) string {
	return strings.ToLower(normalizedDN)
}

func indexCurrentMembers(current []CurrentMember) *currentMemberIndex {
	index := &currentMemberIndex{
		members: make([]ResolvedIdentifier, 0, len(current)),
		byDN:    make(map[string]int, len(current)),
		byGUID:  make(map[string]int, len(current)),
		bySID:   make(map[string]int, len(current)),
	}

	// GetCurrentMembers already supplies canonical GUID, DN and SID forms.
	for _, c := range current {
		if c.GUID == "" || c.DN == "" {
			continue // ineligible: a lookup might find a GUID we cannot supply
		}

		pos := len(index.members)
		index.members = append(index.members, ResolvedIdentifier{DN: c.DN, GUID: c.GUID})

		index.put(index.byDN, dnMatchKey(c.DN), pos)
		index.put(index.byGUID, c.GUID, pos)
		if c.SID != "" {
			index.put(index.bySID, c.SID, pos)
		}
	}

	return index
}

// put records key -> pos, marking the key ambiguous if it already maps to a
// different object (different GUID or different DN).
func (x *currentMemberIndex) put(keys map[string]int, key string, pos int) {
	existing, ok := keys[key]
	if !ok {
		keys[key] = pos
		return
	}
	if existing == ambiguousMember {
		return
	}
	a, b := x.members[existing], x.members[pos]
	if a.GUID != b.GUID || dnMatchKey(a.DN) != dnMatchKey(b.DN) {
		keys[key] = ambiguousMember
	}
}

// lookup returns the current member unambiguously named by a trimmed
// DN/GUID/SID identifier.
func (x *currentMemberIndex) lookup(m *MemberNormalizer, identifier string) (ResolvedIdentifier, bool) {
	var keys map[string]int
	var key string

	switch m.DetectIdentifierType(identifier) {
	case IdentifierTypeDN:
		dn, err := NormalizeDNCase(identifier)
		if err != nil || dn == "" {
			return ResolvedIdentifier{}, false
		}
		keys, key = x.byDN, dnMatchKey(dn)
	case IdentifierTypeGUID:
		guid, err := m.guidHandler.NormalizeGUID(identifier)
		if err != nil {
			return ResolvedIdentifier{}, false
		}
		keys, key = x.byGUID, guid
	case IdentifierTypeSID:
		sid, err := ParseSID(identifier)
		if err != nil {
			return ResolvedIdentifier{}, false
		}
		keys, key = x.bySID, sid.String()
	default:
		return ResolvedIdentifier{}, false
	}

	pos, ok := keys[key]
	if !ok || pos == ambiguousMember {
		return ResolvedIdentifier{}, false
	}
	return x.members[pos], true
}
