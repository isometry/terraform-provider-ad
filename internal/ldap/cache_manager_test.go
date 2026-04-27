package ldap

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCacheEntry returns a fully-populated cache entry suitable for
// exercising every index (GUID, SID, DN, UPN, SAM).
func newTestCacheEntry(dn, guid, sid, upn, sam string) *LDAPCacheEntry {
	attrs := map[string][]string{}
	if upn != "" {
		attrs["userPrincipalName"] = []string{upn}
	}
	if sam != "" {
		attrs["sAMAccountName"] = []string{sam}
	}
	return &LDAPCacheEntry{
		DN:          dn,
		ObjectClass: []string{"top", "user"},
		Attributes:  attrs,
		ObjectGUID:  guid,
		ObjectSID:   sid,
	}
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestCacheManager_NewCacheManager(t *testing.T) {
	cm := NewCacheManager()
	require.NotNil(t, cm, "NewCacheManager should return a non-nil manager")
	require.NotNil(t, cm.guidHandler, "GUID handler should be initialised")
	require.NotNil(t, cm.sidHandler, "SID handler should be initialised")

	stats := cm.GetStats()
	assert.Equal(t, int64(0), stats.Hits)
	assert.Equal(t, int64(0), stats.Misses)
	assert.Equal(t, int64(0), stats.Entries)
	assert.True(t, stats.LastWarmed.IsZero(), "LastWarmed should be zero-valued on a fresh cache")
}

// ---------------------------------------------------------------------------
// Put validation
// ---------------------------------------------------------------------------

func TestCacheManager_Put_Validation(t *testing.T) {
	tests := []struct {
		name    string
		entry   *LDAPCacheEntry
		wantErr bool
		errSub  string
	}{
		{
			name:    "nil entry",
			entry:   nil,
			wantErr: true,
			errSub:  "nil",
		},
		{
			name:    "entry without DN",
			entry:   &LDAPCacheEntry{ObjectGUID: "12345678-1234-1234-1234-123456789012"},
			wantErr: true,
			errSub:  "DN",
		},
		{
			name: "minimal valid entry (DN only)",
			entry: &LDAPCacheEntry{
				DN:         "CN=Min,DC=example,DC=com",
				Attributes: map[string][]string{},
			},
			wantErr: false,
		},
		{
			name: "fully populated entry",
			entry: newTestCacheEntry(
				"CN=Full,DC=example,DC=com",
				"12345678-1234-1234-1234-123456789012",
				"S-1-5-21-1-2-3-1001",
				"full@example.com",
				"full",
			),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCacheManager()
			err := cm.Put(tt.entry)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSub)
				return
			}
			require.NoError(t, err)
			assert.False(t, tt.entry.LastUpdated.IsZero(), "Put should stamp LastUpdated")
		})
	}
}

func TestCacheManager_Put_ExtractsGUIDAndSIDFromAttributes(t *testing.T) {
	// When ObjectGUID / ObjectSID are empty, Put should try to populate them
	// from the Attributes map (case-insensitive match on the attribute name).
	cm := NewCacheManager()
	entry := &LDAPCacheEntry{
		DN: "CN=Attr,DC=example,DC=com",
		Attributes: map[string][]string{
			"ObjectGUID": {"12345678-1234-1234-1234-123456789012"},
			"OBJECTSID":  {"S-1-5-21-1-2-3-1042"},
		},
	}
	require.NoError(t, cm.Put(entry))
	assert.Equal(t, "12345678-1234-1234-1234-123456789012", entry.ObjectGUID)
	assert.Equal(t, "S-1-5-21-1-2-3-1042", entry.ObjectSID)
}

// ---------------------------------------------------------------------------
// Multi-key indexing
// ---------------------------------------------------------------------------

func TestCacheManager_Get_ByEveryIndex(t *testing.T) {
	cm := NewCacheManager()
	entry := newTestCacheEntry(
		"CN=Alice,OU=Users,DC=example,DC=com",
		"11111111-2222-3333-4444-555555555555",
		"S-1-5-21-1-2-3-1001",
		"alice@example.com",
		"alice",
	)
	require.NoError(t, cm.Put(entry))

	tests := []struct {
		name       string
		identifier string
	}{
		{"by DN", "CN=Alice,OU=Users,DC=example,DC=com"},
		{"by DN with prefix", "dn:CN=Alice,OU=Users,DC=example,DC=com"},
		{"by GUID (hyphenated)", "11111111-2222-3333-4444-555555555555"},
		{"by GUID with prefix", "guid:11111111-2222-3333-4444-555555555555"},
		{"by SID", "S-1-5-21-1-2-3-1001"},
		{"by SID with prefix", "sid:S-1-5-21-1-2-3-1001"},
		{"by UPN", "alice@example.com"},
		{"by UPN with prefix", "upn:alice@example.com"},
		{"by SAM with prefix", "sam:alice"},
		// DOMAIN\user NT4-style input strips the "DOMAIN\" prefix before
		// building the SAM key, so this resolves to "sam:alice" and hits.
		{"by SAM with DOMAIN\\ format", "EXAMPLE\\alice"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cm.Get(tt.identifier)
			require.True(t, ok, "expected hit for %s", tt.identifier)
			require.NotNil(t, got)
			assert.Equal(t, entry.DN, got.DN)
			assert.Equal(t, entry.ObjectGUID, got.ObjectGUID)
			assert.Equal(t, entry.ObjectSID, got.ObjectSID)
		})
	}
}

// ---------------------------------------------------------------------------
// Case normalisation
// ---------------------------------------------------------------------------

func TestCacheManager_Get_CaseInsensitive(t *testing.T) {
	cm := NewCacheManager()
	entry := newTestCacheEntry(
		"CN=Bob,OU=People,DC=Example,DC=COM",
		"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
		"S-1-5-21-1-2-3-2002",
		"Bob@Example.COM",
		"Bob",
	)
	require.NoError(t, cm.Put(entry))

	cases := []struct {
		name       string
		identifier string
	}{
		{"DN lowercased", "cn=bob,ou=people,dc=example,dc=com"},
		{"DN uppercased", "CN=BOB,OU=PEOPLE,DC=EXAMPLE,DC=COM"},
		{"DN mixed case with prefix", "dn:Cn=Bob,Ou=People,Dc=Example,Dc=Com"},
		{"GUID lowercased", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"GUID mixed case with prefix", "guid:AaAaAaAa-BbBb-CcCc-DdDd-EeEeEeEeEeEe"},
		{"UPN lowercased", "bob@example.com"},
		{"UPN uppercased", "BOB@EXAMPLE.COM"},
		{"SAM with prefix lowercase", "sam:bob"},
		{"SAM with prefix uppercase", "SAM:BOB"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := cm.Get(tc.identifier)
			require.True(t, ok, "case-insensitive lookup failed for %q", tc.identifier)
			assert.Equal(t, entry.DN, got.DN)
		})
	}
}

// ---------------------------------------------------------------------------
// Misses
// ---------------------------------------------------------------------------

func TestCacheManager_Get_Miss(t *testing.T) {
	cm := NewCacheManager()
	// Put one unrelated entry so the cache is non-empty.
	require.NoError(t, cm.Put(newTestCacheEntry(
		"CN=Carol,DC=example,DC=com",
		"cccccccc-1111-2222-3333-444444444444",
		"S-1-5-21-1-2-3-3003",
		"carol@example.com",
		"carol",
	)))

	misses := []struct {
		name       string
		identifier string
	}{
		{"empty identifier", ""},
		{"whitespace only", "   "},
		{"unknown DN", "CN=Nobody,DC=example,DC=com"},
		{"unknown GUID", "ffffffff-ffff-ffff-ffff-ffffffffffff"},
		{"unknown SID", "S-1-5-21-9-9-9-9"},
		{"unknown UPN", "ghost@example.com"},
		{"unknown SAM with prefix", "sam:ghost"},
		{"garbage (no recognisable pattern)", "###not-an-identifier###"},
	}

	before := cm.GetStats().Misses
	for _, tc := range misses {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := cm.Get(tc.identifier)
			assert.False(t, ok, "expected miss for %q", tc.identifier)
			assert.Nil(t, got)
		})
	}

	after := cm.GetStats().Misses
	assert.Equal(t, int64(len(misses)), after-before,
		"every lookup should have incremented the miss counter exactly once")
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

func TestCacheManager_GetStats_HitMissCounters(t *testing.T) {
	cm := NewCacheManager()
	require.NoError(t, cm.Put(newTestCacheEntry(
		"CN=Dan,DC=example,DC=com",
		"dddddddd-1111-2222-3333-444444444444",
		"S-1-5-21-1-2-3-4004",
		"dan@example.com",
		"dan",
	)))

	// Three hits
	for range 3 {
		_, ok := cm.Get("dan@example.com")
		require.True(t, ok)
	}
	// Two misses
	for range 2 {
		_, ok := cm.Get("ghost@example.com")
		require.False(t, ok)
	}

	stats := cm.GetStats()
	assert.Equal(t, int64(3), stats.Hits)
	assert.Equal(t, int64(2), stats.Misses)
	assert.InDelta(t, 60.0, stats.HitRate, 0.001, "hit rate should be 3/(3+2) = 60%%")
	assert.Equal(t, int64(1), stats.Entries)
	assert.Equal(t, int64(1), stats.IndexedByGUID)
	assert.Equal(t, int64(1), stats.IndexedBySID)
	assert.Equal(t, int64(1), stats.IndexedByUPN)
	assert.Equal(t, int64(1), stats.IndexedBySAM)
	assert.Equal(t, int64(1), stats.IndexedByDN)
	assert.Greater(t, stats.EstimatedMemoryBytes, int64(0))
}

func TestCacheManager_GetStats_IndexCountsReflectPopulatedAttributes(t *testing.T) {
	cm := NewCacheManager()

	// Entry with only DN and GUID.
	require.NoError(t, cm.Put(&LDAPCacheEntry{
		DN:         "CN=DnOnly,DC=example,DC=com",
		ObjectGUID: "00000000-0000-0000-0000-000000000001",
		Attributes: map[string][]string{},
	}))

	// Entry with DN, SID, UPN, SAM (no GUID).
	require.NoError(t, cm.Put(&LDAPCacheEntry{
		DN:        "CN=NoGuid,DC=example,DC=com",
		ObjectSID: "S-1-5-21-1-2-3-5005",
		Attributes: map[string][]string{
			"userPrincipalName": {"noguid@example.com"},
			"sAMAccountName":    {"noguid"},
		},
	}))

	stats := cm.GetStats()
	assert.Equal(t, int64(2), stats.Entries)
	assert.Equal(t, int64(2), stats.IndexedByDN, "every entry has a DN")
	assert.Equal(t, int64(1), stats.IndexedByGUID)
	assert.Equal(t, int64(1), stats.IndexedBySID)
	assert.Equal(t, int64(1), stats.IndexedByUPN)
	assert.Equal(t, int64(1), stats.IndexedBySAM)
}

// ---------------------------------------------------------------------------
// Clear (the public invalidation path)
// ---------------------------------------------------------------------------

func TestCacheManager_Clear_WipesAllIndexes(t *testing.T) {
	cm := NewCacheManager()
	entry := newTestCacheEntry(
		"CN=Eve,DC=example,DC=com",
		"eeeeeeee-1111-2222-3333-444444444444",
		"S-1-5-21-1-2-3-5005",
		"eve@example.com",
		"eve",
	)
	require.NoError(t, cm.Put(entry))

	// Record a hit and a miss so we can confirm historical stats are preserved.
	_, _ = cm.Get("eve@example.com")
	_, _ = cm.Get("ghost@example.com")

	before := cm.GetStats()
	require.Equal(t, int64(1), before.Hits)
	require.Equal(t, int64(1), before.Misses)
	require.Equal(t, int64(1), before.Entries)

	cm.Clear()

	after := cm.GetStats()
	assert.Equal(t, int64(0), after.Entries)
	assert.Equal(t, int64(0), after.IndexedByDN)
	assert.Equal(t, int64(0), after.IndexedByGUID)
	assert.Equal(t, int64(0), after.IndexedBySID)
	assert.Equal(t, int64(0), after.IndexedByUPN)
	assert.Equal(t, int64(0), after.IndexedBySAM)
	assert.Equal(t, before.Hits, after.Hits, "Clear should preserve historical hits")
	assert.Equal(t, before.Misses, after.Misses, "Clear should preserve historical misses")

	// After Clear, every lookup should miss.
	for _, id := range []string{
		entry.DN,
		entry.ObjectGUID,
		entry.ObjectSID,
		"eve@example.com",
		"sam:eve",
	} {
		got, ok := cm.Get(id)
		assert.False(t, ok, "post-Clear lookup %q should miss", id)
		assert.Nil(t, got)
	}
}

func TestCacheManager_Clear_OnEmptyCacheIsSafe(t *testing.T) {
	cm := NewCacheManager()
	assert.NotPanics(t, func() { cm.Clear() })
	stats := cm.GetStats()
	assert.Equal(t, int64(0), stats.Entries)
	assert.Equal(t, int64(0), stats.Hits)
	assert.Equal(t, int64(0), stats.Misses)
}

// ---------------------------------------------------------------------------
// Nil / empty input handling
// ---------------------------------------------------------------------------

func TestCacheManager_Put_SparseAttributes(t *testing.T) {
	// Entries whose optional keys are empty/missing should be accepted, and
	// should simply not show up in the corresponding index.
	cm := NewCacheManager()

	// Nil Attributes map.
	require.NoError(t, cm.Put(&LDAPCacheEntry{
		DN:         "CN=NoAttrs,DC=example,DC=com",
		Attributes: nil,
	}))

	// Empty userPrincipalName slice should not index by UPN.
	require.NoError(t, cm.Put(&LDAPCacheEntry{
		DN: "CN=EmptyUPN,DC=example,DC=com",
		Attributes: map[string][]string{
			"userPrincipalName": {}, // empty slice
			"sAMAccountName":    {"emptyupn"},
		},
	}))

	stats := cm.GetStats()
	assert.Equal(t, int64(2), stats.Entries)
	assert.Equal(t, int64(2), stats.IndexedByDN)
	assert.Equal(t, int64(0), stats.IndexedByUPN)
	assert.Equal(t, int64(1), stats.IndexedBySAM)
	assert.Equal(t, int64(0), stats.IndexedByGUID)
	assert.Equal(t, int64(0), stats.IndexedBySID)
}

func TestCacheManager_Get_EmptyAndWhitespaceReturnsMiss(t *testing.T) {
	cm := NewCacheManager()
	for _, id := range []string{"", " ", "\t\n"} {
		got, ok := cm.Get(id)
		assert.False(t, ok)
		assert.Nil(t, got)
	}
	// Each call should have incremented misses.
	assert.Equal(t, int64(3), cm.GetStats().Misses)
}

// ---------------------------------------------------------------------------
// WarmCache
// ---------------------------------------------------------------------------

func TestCacheManager_WarmCache_NilClient(t *testing.T) {
	cm := NewCacheManager()
	err := cm.WarmCache(context.Background(), nil, "DC=example,DC=com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestCacheManager_ConcurrentReadWrite(t *testing.T) {
	cm := NewCacheManager()

	const writers = 8
	const readers = 8
	const perGoroutine = 200

	var wg sync.WaitGroup
	wg.Add(writers + readers)

	// Writers: each goroutine inserts its own disjoint set of entries.
	var writeErrs atomic.Int64
	for w := range writers {
		go func() {
			defer wg.Done()
			for i := range perGoroutine {
				id := fmt.Sprintf("%d-%d", w, i)
				entry := &LDAPCacheEntry{
					DN:         fmt.Sprintf("CN=User%s,DC=example,DC=com", id),
					ObjectGUID: fmt.Sprintf("11111111-1111-1111-1111-%012d", w*10000+i),
					ObjectSID:  fmt.Sprintf("S-1-5-21-1-2-3-%d%04d", w, i),
					Attributes: map[string][]string{
						"userPrincipalName": {fmt.Sprintf("user%s@example.com", id)},
						"sAMAccountName":    {fmt.Sprintf("user%s", id)},
					},
				}
				if err := cm.Put(entry); err != nil {
					writeErrs.Add(1)
				}
			}
		}()
	}

	// Readers: probe random keys (both hits and misses). We don't assert on
	// specific results here — this test is a race-detector harness.
	for r := range readers {
		go func() {
			defer wg.Done()
			for i := range perGoroutine {
				// Mix of possible keys: some will be writes by anyone else,
				// some are guaranteed misses.
				_, _ = cm.Get(fmt.Sprintf("CN=User%d-%d,DC=example,DC=com", r%writers, i%perGoroutine))
				_, _ = cm.Get(fmt.Sprintf("missing-%d-%d@example.com", r, i))
				_ = cm.GetStats()
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(0), writeErrs.Load(), "no Put should have failed")

	stats := cm.GetStats()
	// Every writer inserted perGoroutine entries successfully.
	expected := int64(writers * perGoroutine)
	assert.Equal(t, expected, stats.Entries, "total entries should equal writers*perGoroutine")
	// DN is always present, so IndexedByDN should match Entries.
	assert.Equal(t, expected, stats.IndexedByDN)
	// Stats counters should be non-negative and internally consistent.
	assert.GreaterOrEqual(t, stats.Hits, int64(0))
	assert.GreaterOrEqual(t, stats.Misses, int64(0))
	assert.Equal(t, stats.Hits+stats.Misses, int64(readers*perGoroutine*2),
		"each reader performed 2 lookups per iteration")
}

// TestCacheManager_ConcurrentClearAndWrite is a regression guard for the
// previously-racy CacheManager.Clear() implementation that reassigned the
// sync.Map-valued struct fields wholesale without any lock. Clear() now
// drains each map in place via Range+Delete, so this test runs unconditionally
// and must pass cleanly under -race against concurrent Put/Get/GetStats.
func TestCacheManager_ConcurrentClearAndWrite(t *testing.T) {
	cm := NewCacheManager()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Go(func() {
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				_ = cm.Put(&LDAPCacheEntry{
					DN:         fmt.Sprintf("CN=Rapid%d,DC=example,DC=com", i),
					ObjectGUID: fmt.Sprintf("22222222-2222-2222-2222-%012d", i),
					Attributes: map[string][]string{},
				})
				i++
			}
		}
	})

	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				cm.Clear()
				time.Sleep(time.Microsecond)
			}
		}
	})

	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = cm.GetStats()
			}
		}
	})

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	stats := cm.GetStats()
	assert.GreaterOrEqual(t, stats.Entries, int64(0))
}

// ---------------------------------------------------------------------------
// GetMemoryStats
// ---------------------------------------------------------------------------

func TestCacheManager_GetMemoryStats(t *testing.T) {
	cm := NewCacheManager()
	require.NoError(t, cm.Put(newTestCacheEntry(
		"CN=Mem,DC=example,DC=com",
		"12121212-3434-5656-7878-909090909090",
		"S-1-5-21-1-2-3-9999",
		"mem@example.com",
		"mem",
	)))

	ms := cm.GetMemoryStats()
	require.NotNil(t, ms)

	// Shape checks: every expected key is present.
	for _, key := range []string{
		"cache_estimated_bytes",
		"cache_entries",
		"go_alloc_bytes",
		"go_sys_bytes",
		"go_heap_objects",
		"go_num_gc",
	} {
		_, ok := ms[key]
		assert.True(t, ok, "GetMemoryStats missing key %q", key)
	}

	entries, ok := ms["cache_entries"].(int64)
	require.True(t, ok, "cache_entries should be int64")
	assert.Equal(t, int64(1), entries)

	estBytes, ok := ms["cache_estimated_bytes"].(int64)
	require.True(t, ok, "cache_estimated_bytes should be int64")
	assert.Greater(t, estBytes, int64(0))
}

// ---------------------------------------------------------------------------
// Table-driven tests around overwrite semantics (documented surprise)
// ---------------------------------------------------------------------------

func TestCacheManager_Put_SameDNTwice_Dedupes(t *testing.T) {
	// Putting an entry with a DN that is already cached must replace the
	// previous primary record and all of its index pointers — not leave
	// orphaned rows behind. After the second Put, the first entry's GUID
	// and SID indexes must no longer resolve, and the entries counter
	// must reflect a single live record.
	cm := NewCacheManager()

	first := newTestCacheEntry(
		"CN=Repeat,DC=example,DC=com",
		"33333333-1111-2222-3333-444444444444",
		"S-1-5-21-1-2-3-7007",
		"repeat@example.com",
		"repeat",
	)
	require.NoError(t, cm.Put(first))

	// Second insert with the same DN but different GUID/SID. The UPN and SAM
	// are identical, so their indexes get repointed to the second entry.
	second := newTestCacheEntry(
		"CN=Repeat,DC=example,DC=com",
		"44444444-1111-2222-3333-444444444444",
		"S-1-5-21-1-2-3-7008",
		"repeat@example.com",
		"repeat",
	)
	require.NoError(t, cm.Put(second))

	// Looking up by DN / UPN / SAM should return the *second* entry.
	for _, id := range []string{
		"CN=Repeat,DC=example,DC=com",
		"repeat@example.com",
		"sam:repeat",
	} {
		got, ok := cm.Get(id)
		require.True(t, ok, "expected hit for %q after re-put", id)
		assert.Equal(t, second.ObjectGUID, got.ObjectGUID, "lookup %q should return second entry", id)
		assert.Equal(t, second.ObjectSID, got.ObjectSID, "lookup %q should return second entry", id)
	}

	// The first entry's GUID and SID must no longer resolve — they were
	// removed as part of the dedup on the second Put.
	gotByFirstGUID, ok := cm.Get(first.ObjectGUID)
	assert.False(t, ok, "first entry's GUID should no longer resolve after dedup")
	assert.Nil(t, gotByFirstGUID)

	gotByFirstSID, ok := cm.Get(first.ObjectSID)
	assert.False(t, ok, "first entry's SID should no longer resolve after dedup")
	assert.Nil(t, gotByFirstSID)

	// The second entry's GUID and SID must still resolve.
	gotBySecondGUID, ok := cm.Get(second.ObjectGUID)
	require.True(t, ok)
	assert.Equal(t, second.ObjectGUID, gotBySecondGUID.ObjectGUID)

	gotBySecondSID, ok := cm.Get(second.ObjectSID)
	require.True(t, ok)
	assert.Equal(t, second.ObjectSID, gotBySecondSID.ObjectSID)

	// Exactly one live primary record remains.
	stats := cm.GetStats()
	assert.Equal(t, int64(1), stats.Entries, "dedup should leave exactly one entry")
	assert.Equal(t, int64(1), stats.IndexedByDN)
	assert.Equal(t, int64(1), stats.IndexedByGUID)
	assert.Equal(t, int64(1), stats.IndexedBySID)
	assert.Equal(t, int64(1), stats.IndexedByUPN)
	assert.Equal(t, int64(1), stats.IndexedBySAM)
}
