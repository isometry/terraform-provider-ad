package ldap

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ProviderData wraps both the LDAP client and cache manager for use by Terraform resources.
// This provides a clean interface for provider components to access both connection and cache capabilities.
type ProviderData struct {
	Client       Client        // LDAP client for directory operations
	CacheManager *CacheManager // Cache manager for performance optimization
}

// NewProviderData creates a new provider data wrapper.
func NewProviderData(client Client, cacheManager *CacheManager) *ProviderData {
	return &ProviderData{
		Client:       client,
		CacheManager: cacheManager,
	}
}

// NewProviderDataWithClient creates provider data with just a client (cache manager will be created).
func NewProviderDataWithClient(client Client) *ProviderData {
	return &ProviderData{
		Client:       client,
		CacheManager: NewCacheManager(),
	}
}

// ValidateConnection ensures both client and cache manager are available.
func (pd *ProviderData) ValidateConnection(ctx context.Context) error {
	if pd.Client == nil {
		return fmt.Errorf("LDAP client is not initialized")
	}

	if pd.CacheManager == nil {
		return fmt.Errorf("cache manager is not initialized")
	}

	// Test the LDAP client connection
	if err := pd.Client.Ping(ctx); err != nil {
		return fmt.Errorf("LDAP client connection failed: %w", err)
	}

	tflog.Debug(ctx, "Provider data validation successful", map[string]any{
		"client_available":        pd.Client != nil,
		"cache_manager_available": pd.CacheManager != nil,
	})

	return nil
}

// WarmCache is a convenience method to warm the cache using the client.
func (pd *ProviderData) WarmCache(ctx context.Context, baseDN string) error {
	if pd.Client == nil {
		return fmt.Errorf("LDAP client is not initialized")
	}

	if pd.CacheManager == nil {
		return fmt.Errorf("cache manager is not initialized")
	}

	tflog.Info(ctx, "Warming cache via provider data", map[string]any{
		"base_dn": baseDN,
	})

	start := time.Now()
	err := pd.CacheManager.WarmCache(ctx, pd.Client, baseDN)
	duration := time.Since(start)

	if err != nil {
		tflog.Error(ctx, "Cache warming failed", map[string]any{
			"base_dn":     baseDN,
			"error":       err.Error(),
			"duration_ms": duration.Milliseconds(),
		})
		return fmt.Errorf("cache warming failed: %w", err)
	}

	tflog.Info(ctx, "Cache warming completed via provider data", map[string]any{
		"base_dn":     baseDN,
		"duration_ms": duration.Milliseconds(),
	})

	return nil
}

// GetCacheStats returns cache statistics.
func (pd *ProviderData) GetCacheStats() CacheStats {
	if pd.CacheManager == nil {
		return CacheStats{}
	}

	return pd.CacheManager.GetStats()
}

// GetClientStats returns LDAP client pool statistics.
func (pd *ProviderData) GetClientStats() PoolStats {
	if pd.Client == nil {
		return PoolStats{}
	}

	return pd.Client.Stats()
}

// GetCombinedStats returns both cache and client statistics.
func (pd *ProviderData) GetCombinedStats() map[string]any {
	stats := make(map[string]any)

	// Add cache statistics
	if pd.CacheManager != nil {
		cacheStats := pd.CacheManager.GetStats()
		stats["cache"] = map[string]any{
			"hits":                   cacheStats.Hits,
			"misses":                 cacheStats.Misses,
			"entries":                cacheStats.Entries,
			"hit_rate":               cacheStats.HitRate,
			"warming_runs":           cacheStats.WarmingRuns,
			"last_warmed":            cacheStats.LastWarmed,
			"average_hit_time_ms":    cacheStats.AverageHitTime.Milliseconds(),
			"estimated_memory_bytes": cacheStats.EstimatedMemoryBytes,
			"indexed_by_guid":        cacheStats.IndexedByGUID,
			"indexed_by_sid":         cacheStats.IndexedBySID,
			"indexed_by_upn":         cacheStats.IndexedByUPN,
			"indexed_by_sam":         cacheStats.IndexedBySAM,
			"indexed_by_dn":          cacheStats.IndexedByDN,
		}

		// Add memory statistics
		memStats := pd.CacheManager.GetMemoryStats()
		stats["memory"] = memStats
	}

	// Add client pool statistics
	if pd.Client != nil {
		poolStats := pd.Client.Stats()
		stats["pool"] = map[string]any{
			"total":          poolStats.Total,
			"active":         poolStats.Active,
			"idle":           poolStats.Idle,
			"unhealthy":      poolStats.Unhealthy,
			"created":        poolStats.Created,
			"errors":         poolStats.Errors,
			"uptime_seconds": poolStats.Uptime.Seconds(),
		}
	}

	return stats
}

// Close closes both the client and clears the cache.
func (pd *ProviderData) Close() error {
	var err error

	// Clear cache first
	if pd.CacheManager != nil {
		pd.CacheManager.Clear()
	}

	// Close client connection
	if pd.Client != nil {
		if clientErr := pd.Client.Close(); clientErr != nil {
			err = fmt.Errorf("failed to close LDAP client: %w", clientErr)
		}
	}

	return err
}

// SearchWithCache performs a search operation with cache fallback.
// This method first checks the cache for the requested entries, and falls back to LDAP if needed.
func (pd *ProviderData) SearchWithCache(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	if pd.Client == nil {
		return nil, fmt.Errorf("LDAP client is not initialized")
	}

	// For now, this is a direct passthrough to the client
	// In future phases, this could implement intelligent cache lookups
	// based on the search request parameters

	tflog.Debug(ctx, "Performing search with cache support", map[string]any{
		"base_dn":    req.BaseDN,
		"filter":     req.Filter,
		"scope":      req.Scope.String(),
		"attributes": req.Attributes,
	})

	start := time.Now()
	result, err := pd.Client.Search(ctx, req)
	duration := time.Since(start)

	if err != nil {
		tflog.Error(ctx, "Search with cache failed", map[string]any{
			"base_dn":     req.BaseDN,
			"filter":      req.Filter,
			"error":       err.Error(),
			"duration_ms": duration.Milliseconds(),
		})
		return nil, err
	}

	tflog.Debug(ctx, "Search with cache completed", map[string]any{
		"base_dn":       req.BaseDN,
		"filter":        req.Filter,
		"entries_found": len(result.Entries),
		"duration_ms":   duration.Milliseconds(),
	})

	return result, nil
}

// LookupByIdentifier performs a cache lookup by any supported identifier.
// This is a convenience method for resources to quickly find cached entries.
func (pd *ProviderData) LookupByIdentifier(ctx context.Context, identifier string) (*LDAPCacheEntry, bool) {
	if pd.CacheManager == nil {
		tflog.Warn(ctx, "Cache manager not available for lookup", map[string]any{
			"identifier": identifier,
		})
		return nil, false
	}

	tflog.Trace(ctx, "Performing cache lookup by identifier", map[string]any{
		"identifier": identifier,
	})

	start := time.Now()
	entry, found := pd.CacheManager.Get(identifier)
	duration := time.Since(start)

	tflog.Trace(ctx, "Cache lookup completed", map[string]any{
		"identifier":  identifier,
		"found":       found,
		"duration_ms": duration.Milliseconds(),
	})

	return entry, found
}

// UpdateCache adds or updates an entry in the cache.
// This is useful when resources perform LDAP operations and want to keep the cache current.
func (pd *ProviderData) UpdateCache(ctx context.Context, entry *LDAPCacheEntry) error {
	if pd.CacheManager == nil {
		tflog.Warn(ctx, "Cache manager not available for update", map[string]any{
			"entry_dn": entry.DN,
		})
		return fmt.Errorf("cache manager is not initialized")
	}

	tflog.Trace(ctx, "Updating cache entry", map[string]any{
		"entry_dn":   entry.DN,
		"entry_guid": entry.ObjectGUID,
	})

	err := pd.CacheManager.Put(entry)
	if err != nil {
		tflog.Error(ctx, "Failed to update cache entry", map[string]any{
			"entry_dn": entry.DN,
			"error":    err.Error(),
		})
		return fmt.Errorf("failed to update cache entry: %w", err)
	}

	tflog.Trace(ctx, "Cache entry updated successfully", map[string]any{
		"entry_dn":   entry.DN,
		"entry_guid": entry.ObjectGUID,
	})

	return nil
}

// IsConnected checks if the provider has a working connection.
func (pd *ProviderData) IsConnected(ctx context.Context) bool {
	if pd.Client == nil {
		return false
	}

	if err := pd.Client.Ping(ctx); err != nil {
		tflog.Debug(ctx, "Connection check failed", map[string]any{
			"error": err.Error(),
		})
		return false
	}

	return true
}

// GetBaseDN is a convenience method to get the base DN from the client.
func (pd *ProviderData) GetBaseDN(ctx context.Context) (string, error) {
	if pd.Client == nil {
		return "", fmt.Errorf("LDAP client is not initialized")
	}

	return pd.Client.GetBaseDN(ctx)
}
