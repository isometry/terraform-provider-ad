package ldap

// ProviderData wraps both the LDAP client and cache manager for use by Terraform resources.
// This provides a clean interface for provider components to access both connection and cache capabilities.
type ProviderData struct {
	Client               Client        // LDAP client for directory operations
	CacheManager         *CacheManager // Cache manager for performance optimization
	IgnoreMissingMembers bool          // When true, unresolvable members emit warnings instead of errors
}

// NewProviderData creates a new provider data wrapper.
func NewProviderData(client Client, cacheManager *CacheManager, ignoreMissingMembers bool) *ProviderData {
	return &ProviderData{
		Client:               client,
		CacheManager:         cacheManager,
		IgnoreMissingMembers: ignoreMissingMembers,
	}
}
