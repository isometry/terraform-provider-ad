package ldap

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// LDAPCacheEntry represents a cached LDAP entry with metadata.
type LDAPCacheEntry struct {
	DN          string
	ObjectClass []string
	Attributes  map[string][]string
	LastUpdated time.Time
	ObjectGUID  string
	ObjectSID   string
}

// CacheStats provides statistics about cache usage and performance.
type CacheStats struct {
	// Basic counters
	Hits        int64
	Misses      int64
	Entries     int64
	WarmingRuns int64
	LastWarmed  time.Time

	// Performance metrics
	HitRate        float64
	AverageHitTime time.Duration

	// Memory usage
	EstimatedMemoryBytes int64

	// Index statistics
	IndexedByGUID int64
	IndexedBySID  int64
	IndexedByUPN  int64
	IndexedBySAM  int64
	IndexedByDN   int64
}

// CacheManager provides thread-safe caching for LDAP entries with multi-key indexing.
type CacheManager struct {
	// Thread-safe storage using sync.Map for concurrent access
	entries sync.Map // map[string]*LDAPCacheEntry - primary storage keyed by internal ID

	// Multi-key indexes for fast lookups
	guidIndex sync.Map // map[string]string - GUID to internal ID mapping
	sidIndex  sync.Map // map[string]string - SID to internal ID mapping
	upnIndex  sync.Map // map[string]string - UPN to internal ID mapping
	samIndex  sync.Map // map[string]string - SAM to internal ID mapping
	dnIndex   sync.Map // map[string]string - DN to internal ID mapping

	// Statistics tracking
	statsMu sync.RWMutex
	stats   CacheStats

	// Utility handlers
	guidHandler *GUIDHandler
	sidHandler  *SIDHandler

	// Internal counters for unique IDs
	idCounter int64
	counterMu sync.Mutex
}

// NewCacheManager creates a new cache manager instance.
func NewCacheManager() *CacheManager {
	return &CacheManager{
		guidHandler: NewGUIDHandler(),
		sidHandler:  NewSIDHandler(),
		stats: CacheStats{
			LastWarmed: time.Time{}, // Zero time indicates never warmed
		},
	}
}

// generateID generates a unique internal ID for cache entries.
func (cm *CacheManager) generateID() string {
	cm.counterMu.Lock()
	defer cm.counterMu.Unlock()
	cm.idCounter++
	return fmt.Sprintf("entry_%d", cm.idCounter)
}

// indexEntry creates all possible index mappings for an entry.
func (cm *CacheManager) indexEntry(internalID string, entry *LDAPCacheEntry) {
	// Index by GUID if available
	if entry.ObjectGUID != "" {
		guidKey := fmt.Sprintf("guid:%s", strings.ToLower(entry.ObjectGUID))
		cm.guidIndex.Store(guidKey, internalID)
	}

	// Index by SID if available
	if entry.ObjectSID != "" {
		sidKey := fmt.Sprintf("sid:%s", entry.ObjectSID)
		cm.sidIndex.Store(sidKey, internalID)
	}

	// Index by DN (always available)
	if entry.DN != "" {
		dnKey := fmt.Sprintf("dn:%s", strings.ToLower(entry.DN))
		cm.dnIndex.Store(dnKey, internalID)
	}

	// Index by UPN if available
	if upnValues, exists := entry.Attributes["userPrincipalName"]; exists && len(upnValues) > 0 {
		upnKey := fmt.Sprintf("upn:%s", strings.ToLower(upnValues[0]))
		cm.upnIndex.Store(upnKey, internalID)
	}

	// Index by SAM account name if available
	if samValues, exists := entry.Attributes["sAMAccountName"]; exists && len(samValues) > 0 {
		samKey := fmt.Sprintf("sam:%s", strings.ToLower(samValues[0]))
		cm.samIndex.Store(samKey, internalID)
	}
}

// removeIndexEntry removes all index mappings for an entry.
//
//nolint:unused
func (cm *CacheManager) removeIndexEntry(entry *LDAPCacheEntry) {
	// Remove GUID index
	if entry.ObjectGUID != "" {
		guidKey := fmt.Sprintf("guid:%s", strings.ToLower(entry.ObjectGUID))
		cm.guidIndex.Delete(guidKey)
	}

	// Remove SID index
	if entry.ObjectSID != "" {
		sidKey := fmt.Sprintf("sid:%s", entry.ObjectSID)
		cm.sidIndex.Delete(sidKey)
	}

	// Remove DN index
	if entry.DN != "" {
		dnKey := fmt.Sprintf("dn:%s", strings.ToLower(entry.DN))
		cm.dnIndex.Delete(dnKey)
	}

	// Remove UPN index
	if upnValues, exists := entry.Attributes["userPrincipalName"]; exists && len(upnValues) > 0 {
		upnKey := fmt.Sprintf("upn:%s", strings.ToLower(upnValues[0]))
		cm.upnIndex.Delete(upnKey)
	}

	// Remove SAM account name index
	if samValues, exists := entry.Attributes["sAMAccountName"]; exists && len(samValues) > 0 {
		samKey := fmt.Sprintf("sam:%s", strings.ToLower(samValues[0]))
		cm.samIndex.Delete(samKey)
	}
}

// lookupInternalID finds the internal ID for any supported identifier type.
func (cm *CacheManager) lookupInternalID(identifier string) (string, bool) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return "", false
	}

	lowerID := strings.ToLower(identifier)

	// Try different identifier types based on patterns

	// Check if it's a GUID (with or without prefix)
	var guidToCheck string
	if strings.HasPrefix(lowerID, "guid:") {
		guidToCheck = lowerID
	} else if cm.guidHandler.IsValidGUID(identifier) {
		guidToCheck = fmt.Sprintf("guid:%s", lowerID)
	}
	if guidToCheck != "" {
		if internalID, exists := cm.guidIndex.Load(guidToCheck); exists {
			if id, ok := internalID.(string); ok {
				return id, true
			}
		}
	}

	// Check if it's a SID (with or without prefix)
	var sidToCheck string
	if strings.HasPrefix(identifier, "sid:") {
		sidToCheck = identifier
	} else if strings.HasPrefix(identifier, "S-") {
		sidToCheck = fmt.Sprintf("sid:%s", identifier)
	}
	if sidToCheck != "" {
		if internalID, exists := cm.sidIndex.Load(sidToCheck); exists {
			if id, ok := internalID.(string); ok {
				return id, true
			}
		}
	}

	// Check if it's a UPN (with or without prefix)
	var upnToCheck string
	if strings.HasPrefix(lowerID, "upn:") {
		upnToCheck = lowerID
	} else if strings.Contains(identifier, "@") {
		upnToCheck = fmt.Sprintf("upn:%s", lowerID)
	}
	if upnToCheck != "" {
		if internalID, exists := cm.upnIndex.Load(upnToCheck); exists {
			if id, ok := internalID.(string); ok {
				return id, true
			}
		}
	}

	// Check if it's a SAM account name (with or without prefix)
	var samToCheck string
	if strings.HasPrefix(lowerID, "sam:") {
		samToCheck = lowerID
	} else if strings.Contains(identifier, "\\") {
		samToCheck = fmt.Sprintf("sam:%s", lowerID)
	}
	if samToCheck != "" {
		if internalID, exists := cm.samIndex.Load(samToCheck); exists {
			if id, ok := internalID.(string); ok {
				return id, true
			}
		}
	}

	// Check if it's a DN (with or without prefix)
	var dnToCheck string
	if strings.HasPrefix(lowerID, "dn:") {
		dnToCheck = lowerID
	} else if strings.Contains(identifier, "=") {
		dnToCheck = fmt.Sprintf("dn:%s", lowerID)
	}
	if dnToCheck != "" {
		if internalID, exists := cm.dnIndex.Load(dnToCheck); exists {
			if id, ok := internalID.(string); ok {
				return id, true
			}
		}
	}

	return "", false
}

// Get retrieves a cache entry by any supported identifier (GUID, SID, DN, UPN, SAM).
func (cm *CacheManager) Get(identifier string) (*LDAPCacheEntry, bool) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		cm.updateHitTime(duration)
	}()

	// Find the internal ID
	internalID, found := cm.lookupInternalID(identifier)
	if !found {
		cm.incrementMisses()
		return nil, false
	}

	// Get the entry from primary storage
	if entryInterface, exists := cm.entries.Load(internalID); exists {
		cm.incrementHits()
		if entry, ok := entryInterface.(*LDAPCacheEntry); ok {
			return entry, true
		}
	}

	// Entry index exists but entry is missing - clean up orphaned index
	cm.cleanupOrphanedIndex(identifier, internalID)
	cm.incrementMisses()
	return nil, false
}

// Put stores or updates a cache entry with multi-key indexing.
func (cm *CacheManager) Put(entry *LDAPCacheEntry) error {
	if entry == nil {
		return fmt.Errorf("cache entry cannot be nil")
	}

	if entry.DN == "" {
		return fmt.Errorf("cache entry must have a DN")
	}

	// Generate unique internal ID
	internalID := cm.generateID()

	// Set last updated time
	entry.LastUpdated = time.Now()

	// Extract GUID and SID for quick access
	if entry.ObjectGUID == "" && entry.Attributes != nil {
		// Try to extract GUID from attributes if not already set
		for attrName, values := range entry.Attributes {
			if strings.EqualFold(attrName, "objectGUID") && len(values) > 0 {
				entry.ObjectGUID = values[0]
				break
			}
		}
	}

	if entry.ObjectSID == "" && entry.Attributes != nil {
		// Try to extract SID from attributes if not already set
		for attrName, values := range entry.Attributes {
			if strings.EqualFold(attrName, "objectSid") && len(values) > 0 {
				entry.ObjectSID = values[0]
				break
			}
		}
	}

	// Store the entry
	cm.entries.Store(internalID, entry)

	// Create all index mappings
	cm.indexEntry(internalID, entry)

	// Update statistics
	cm.incrementEntries()

	return nil
}

// WarmCache performs bulk cache warming by fetching entries from LDAP.
func (cm *CacheManager) WarmCache(ctx context.Context, client Client, baseDN string) error {
	if client == nil {
		return fmt.Errorf("LDAP client cannot be nil")
	}

	if baseDN == "" {
		// Try to get base DN from client
		var err error
		baseDN, err = client.GetBaseDN(ctx)
		if err != nil {
			return WrapError("get_base_dn", fmt.Errorf("base DN required for cache warming: %w", err))
		}
	}

	start := time.Now()

	tflog.Info(ctx, "Starting cache warming operation", map[string]any{
		"operation": "cache_warming",
		"base_dn":   baseDN,
	})

	// Create search request for users and groups
	searchReq := &SearchRequest{
		BaseDN: baseDN,
		Scope:  ScopeWholeSubtree,
		Filter: "(|(objectClass=user)(objectClass=group))",
		Attributes: []string{
			"objectGUID",
			"objectSid",
			"distinguishedName",
			"sAMAccountName",
			"userPrincipalName",
			"objectClass",
			"cn",
			"displayName",
			"mail",
		},
		SizeLimit: 0,                // No limit
		TimeLimit: 10 * time.Minute, // Reasonable timeout for large directories
	}

	// Use paged search to handle large result sets
	result, err := client.SearchWithPaging(ctx, searchReq)
	if err != nil {
		return WrapError("cache_warm_search", fmt.Errorf("failed to search for cache warming: %w", err))
	}

	tflog.Debug(ctx, "Cache warming search completed", map[string]any{
		"entries_found":  len(result.Entries),
		"search_time_ms": time.Since(start).Milliseconds(),
	})

	// Clear existing cache before warming (atomic operation)
	cm.Clear()

	// Process each entry
	entriesProcessed := 0
	entriesWithErrors := 0

	for _, ldapEntry := range result.Entries {
		cacheEntry, err := cm.convertLDAPEntryToCacheEntry(ldapEntry)
		if err != nil {
			entriesWithErrors++
			tflog.Warn(ctx, "Failed to convert LDAP entry to cache entry", map[string]any{
				"dn":    ldapEntry.DN,
				"error": err.Error(),
			})
			continue
		}

		if err := cm.Put(cacheEntry); err != nil {
			entriesWithErrors++
			tflog.Warn(ctx, "Failed to store cache entry", map[string]any{
				"dn":    cacheEntry.DN,
				"error": err.Error(),
			})
			continue
		}

		entriesProcessed++
	}

	duration := time.Since(start)

	// Update warming statistics
	cm.statsMu.Lock()
	cm.stats.WarmingRuns++
	cm.stats.LastWarmed = time.Now()
	cm.statsMu.Unlock()

	tflog.Info(ctx, "Cache warming completed", map[string]any{
		"operation":           "cache_warming",
		"entries_processed":   entriesProcessed,
		"entries_with_errors": entriesWithErrors,
		"total_entries":       len(result.Entries),
		"duration_ms":         duration.Milliseconds(),
		"entries_per_second":  float64(entriesProcessed) / duration.Seconds(),
	})

	if entriesWithErrors > 0 && entriesProcessed == 0 {
		return fmt.Errorf("failed to process any entries during cache warming")
	}

	return nil
}

// convertLDAPEntryToCacheEntry converts an LDAP entry to a cache entry.
func (cm *CacheManager) convertLDAPEntryToCacheEntry(ldapEntry *ldap.Entry) (*LDAPCacheEntry, error) {
	if ldapEntry == nil {
		return nil, fmt.Errorf("LDAP entry cannot be nil")
	}

	cacheEntry := &LDAPCacheEntry{
		DN:         ldapEntry.DN,
		Attributes: make(map[string][]string),
	}

	// Copy all attributes
	for _, attr := range ldapEntry.Attributes {
		cacheEntry.Attributes[attr.Name] = attr.Values

		// Extract object classes
		if strings.EqualFold(attr.Name, "objectClass") {
			cacheEntry.ObjectClass = attr.Values
		}
	}

	// Extract and process GUID
	if guidBytes := ldapEntry.GetRawAttributeValue("objectGUID"); len(guidBytes) > 0 {
		if guid, err := cm.guidHandler.GUIDBytesToString(guidBytes); err == nil {
			cacheEntry.ObjectGUID = guid
		}
	} else if guidStr := ldapEntry.GetAttributeValue("objectGUID"); guidStr != "" {
		// Handle string GUID (for testing scenarios)
		if normalized, err := cm.guidHandler.NormalizeGUID(guidStr); err == nil {
			cacheEntry.ObjectGUID = normalized
		}
	}

	// Extract and process SID
	if sidBytes := ldapEntry.GetRawAttributeValue("objectSid"); len(sidBytes) > 0 {
		if sid, err := cm.sidHandler.ConvertBinarySIDToString(sidBytes); err == nil {
			cacheEntry.ObjectSID = sid
		}
	} else if sidStr := ldapEntry.GetAttributeValue("objectSid"); sidStr != "" {
		// Handle string SID (for testing scenarios)
		if err := cm.sidHandler.ValidateSIDString(sidStr); err == nil {
			cacheEntry.ObjectSID = sidStr
		}
	}

	return cacheEntry, nil
}

// GetStats returns current cache statistics.
func (cm *CacheManager) GetStats() CacheStats {
	cm.statsMu.RLock()
	defer cm.statsMu.RUnlock()

	stats := cm.stats

	// Calculate hit rate
	totalRequests := stats.Hits + stats.Misses
	if totalRequests > 0 {
		stats.HitRate = float64(stats.Hits) / float64(totalRequests) * 100
	}

	// Count current entries
	stats.Entries = cm.countEntries()

	// Count indexed entries
	stats.IndexedByGUID = cm.countIndex(&cm.guidIndex)
	stats.IndexedBySID = cm.countIndex(&cm.sidIndex)
	stats.IndexedByUPN = cm.countIndex(&cm.upnIndex)
	stats.IndexedBySAM = cm.countIndex(&cm.samIndex)
	stats.IndexedByDN = cm.countIndex(&cm.dnIndex)

	// Estimate memory usage
	stats.EstimatedMemoryBytes = cm.estimateMemoryUsage()

	return stats
}

// Clear removes all entries from the cache.
func (cm *CacheManager) Clear() {
	// Clear all storage and indexes
	cm.entries = sync.Map{}
	cm.guidIndex = sync.Map{}
	cm.sidIndex = sync.Map{}
	cm.upnIndex = sync.Map{}
	cm.samIndex = sync.Map{}
	cm.dnIndex = sync.Map{}

	// Reset entry counter
	cm.counterMu.Lock()
	cm.idCounter = 0
	cm.counterMu.Unlock()

	// Reset statistics (keep historical data like hits/misses)
	cm.statsMu.Lock()
	// Don't reset hits, misses, warming runs - keep historical data
	// Reset current state counters
	cm.stats.Entries = 0
	cm.stats.IndexedByGUID = 0
	cm.stats.IndexedBySID = 0
	cm.stats.IndexedByUPN = 0
	cm.stats.IndexedBySAM = 0
	cm.stats.IndexedByDN = 0
	cm.stats.EstimatedMemoryBytes = 0
	cm.statsMu.Unlock()
}

// Helper methods for statistics tracking

func (cm *CacheManager) incrementHits() {
	cm.statsMu.Lock()
	cm.stats.Hits++
	cm.statsMu.Unlock()
}

func (cm *CacheManager) incrementMisses() {
	cm.statsMu.Lock()
	cm.stats.Misses++
	cm.statsMu.Unlock()
}

func (cm *CacheManager) incrementEntries() {
	cm.statsMu.Lock()
	cm.stats.Entries++
	cm.statsMu.Unlock()
}

func (cm *CacheManager) updateHitTime(duration time.Duration) {
	cm.statsMu.Lock()
	// Simple moving average of hit times
	if cm.stats.AverageHitTime == 0 {
		cm.stats.AverageHitTime = duration
	} else {
		cm.stats.AverageHitTime = (cm.stats.AverageHitTime + duration) / 2
	}
	cm.statsMu.Unlock()
}

func (cm *CacheManager) countEntries() int64 {
	count := int64(0)
	cm.entries.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

func (cm *CacheManager) countIndex(index *sync.Map) int64 {
	count := int64(0)
	index.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

func (cm *CacheManager) estimateMemoryUsage() int64 {
	totalSize := int64(0)

	cm.entries.Range(func(key, value interface{}) bool {
		entry, ok := value.(*LDAPCacheEntry)
		if !ok {
			return true
		}

		// Estimate size of LDAPCacheEntry struct
		entrySize := int64(unsafe.Sizeof(*entry))

		// Add size of strings
		entrySize += int64(len(entry.DN))
		entrySize += int64(len(entry.ObjectGUID))
		entrySize += int64(len(entry.ObjectSID))

		// Add size of object classes
		for _, class := range entry.ObjectClass {
			entrySize += int64(len(class))
		}

		// Add size of attributes
		for attrName, values := range entry.Attributes {
			entrySize += int64(len(attrName))
			for _, value := range values {
				entrySize += int64(len(value))
			}
		}

		totalSize += entrySize
		return true
	})

	// Add overhead for sync.Map structures and indexes
	// This is an approximation - actual memory usage may vary
	overhead := int64(5 * 1024) // 5KB base overhead
	totalSize += overhead

	return totalSize
}

func (cm *CacheManager) cleanupOrphanedIndex(identifier, _ string) {
	// Remove orphaned index entries
	// This shouldn't happen in normal operation but provides safety
	lowerID := strings.ToLower(identifier)

	if strings.Contains(lowerID, "guid:") {
		cm.guidIndex.Delete(lowerID)
	}
	if strings.Contains(identifier, "sid:") {
		cm.sidIndex.Delete(identifier)
	}
	if strings.Contains(lowerID, "upn:") {
		cm.upnIndex.Delete(lowerID)
	}
	if strings.Contains(lowerID, "sam:") {
		cm.samIndex.Delete(lowerID)
	}
	if strings.Contains(lowerID, "dn:") {
		cm.dnIndex.Delete(lowerID)
	}
}

// GetMemoryStats returns Go runtime memory statistics along with cache stats.
func (cm *CacheManager) GetMemoryStats() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	cacheStats := cm.GetStats()

	return map[string]interface{}{
		"cache_estimated_bytes": cacheStats.EstimatedMemoryBytes,
		"cache_entries":         cacheStats.Entries,
		"go_alloc_bytes":        m.Alloc,
		"go_sys_bytes":          m.Sys,
		"go_heap_objects":       m.HeapObjects,
		"go_num_gc":             m.NumGC,
	}
}
