package ldap

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SRVDiscovery handles DNS SRV record discovery for domain controllers.
type SRVDiscovery struct {
	resolver *net.Resolver
}

// NewSRVDiscovery creates a new SRV discovery instance.
func NewSRVDiscovery() *SRVDiscovery {
	return &SRVDiscovery{
		resolver: net.DefaultResolver,
	}
}

// DiscoverServers discovers LDAP servers for a domain using SRV records
// Implements the discovery priority:
// 1. _ldaps._tcp.<domain> (LDAPS - preferred)
// 2. _ldap._tcp.<domain> (LDAP+StartTLS - fallback)
// 3. _gc._tcp.<domain> (Global Catalog - last resort).
func (d *SRVDiscovery) DiscoverServers(ctx context.Context, domain string) ([]*ServerInfo, error) {
	start := time.Now()
	fmt.Printf("[DEBUG] Starting server discovery for domain: %s\n", domain)

	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	var allServers []*ServerInfo

	// Discovery order based on security and functionality
	srvRecords := []struct {
		service string
		useTLS  bool
		source  string
	}{
		{"_ldaps._tcp." + domain, true, "srv"},
		{"_ldap._tcp." + domain, false, "srv"},
		{"_gc._tcp." + domain, false, "srv"},
	}

	fmt.Printf("[DEBUG] Will attempt SRV lookups for %d service types\n", len(srvRecords))

	for i, record := range srvRecords {
		fmt.Printf("[DEBUG] Attempting SRV lookup %d/%d: %s\n", i+1, len(srvRecords), record.service)
		servers, err := d.lookupSRV(ctx, record.service, record.useTLS, record.source)
		if err != nil {
			fmt.Printf("[DEBUG] SRV lookup failed for %s, continuing to next service\n", record.service)
			continue
		}
		allServers = append(allServers, servers...)
		fmt.Printf("[DEBUG] Added %d servers from %s (total: %d)\n", len(servers), record.service, len(allServers))

		// If we found LDAPS servers, prefer them and don't look further
		if record.useTLS && len(servers) > 0 {
			break
		}
	}

	if len(allServers) == 0 {
		// Fallback to standard ports if SRV discovery fails
		fallbackServers := d.createFallbackServers(domain)
		fmt.Printf("[DEBUG] No SRV records found, using fallback servers. Total discovery time: %v\n", time.Since(start))
		return fallbackServers, nil
	}

	// Sort servers by priority (lower priority = higher preference)
	// Within same priority, randomize by weight
	d.sortServersByPriority(allServers)

	fmt.Printf("[DEBUG] Server discovery completed in %v, returning %d servers\n", time.Since(start), len(allServers))
	return allServers, nil
}

// lookupSRV performs SRV record lookup for a specific service.
func (d *SRVDiscovery) lookupSRV(ctx context.Context, service string, useTLS bool, source string) ([]*ServerInfo, error) {
	start := time.Now()
	fmt.Printf("[DEBUG] Looking up SRV records for service: %s\n", service)

	_, srvRecords, err := d.resolver.LookupSRV(ctx, "", "", service)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("[DEBUG] SRV lookup for %s failed after %v: %v\n", service, duration, err)
		return nil, fmt.Errorf("SRV lookup failed for %s: %w", service, err)
	}

	fmt.Printf("[DEBUG] SRV lookup for %s completed in %v, found %d records\n", service, duration, len(srvRecords))

	if len(srvRecords) == 0 {
		return nil, fmt.Errorf("no SRV records found for %s", service)
	}

	var servers []*ServerInfo
	for _, srv := range srvRecords {
		// Remove trailing dot from hostname if present
		host := strings.TrimSuffix(srv.Target, ".")

		server := &ServerInfo{
			Host:     host,
			Port:     int(srv.Port),
			UseTLS:   useTLS,
			Priority: int(srv.Priority),
			Weight:   int(srv.Weight),
			Source:   source,
		}
		servers = append(servers, server)
	}

	return servers, nil
}

// createFallbackServers creates fallback servers when SRV discovery fails.
func (d *SRVDiscovery) createFallbackServers(domain string) []*ServerInfo {
	// Standard Active Directory LDAP ports
	fallbackServers := []*ServerInfo{
		{
			Host:     domain,
			Port:     636, // LDAPS
			UseTLS:   true,
			Priority: 0,
			Weight:   100,
			Source:   "fallback",
		},
		{
			Host:     domain,
			Port:     389, // LDAP
			UseTLS:   false,
			Priority: 1,
			Weight:   100,
			Source:   "fallback",
		},
	}

	return fallbackServers
}

// sortServersByPriority sorts servers by priority and weight according to RFC 2782.
func (d *SRVDiscovery) sortServersByPriority(servers []*ServerInfo) {
	// First sort by priority (ascending)
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Priority != servers[j].Priority {
			return servers[i].Priority < servers[j].Priority
		}
		// Within same priority, sort by weight (descending for weighted random selection)
		return servers[i].Weight > servers[j].Weight
	})
}

// ValidateServerInfo validates server information.
func ValidateServerInfo(server *ServerInfo) error {
	if server == nil {
		return fmt.Errorf("server info cannot be nil")
	}

	if server.Host == "" {
		return fmt.Errorf("server host cannot be empty")
	}

	if server.Port <= 0 || server.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", server.Port)
	}

	if server.Priority < 0 {
		return fmt.Errorf("priority cannot be negative: %d", server.Priority)
	}

	if server.Weight < 0 {
		return fmt.Errorf("weight cannot be negative: %d", server.Weight)
	}

	return nil
}

// ServerInfoToURL converts ServerInfo to LDAP URL.
func ServerInfoToURL(server *ServerInfo) string {
	scheme := "ldap"
	if server.UseTLS {
		scheme = "ldaps"
	}

	return fmt.Sprintf("%s://%s:%d", scheme, server.Host, server.Port)
}

// ParseLDAPURL parses an LDAP URL into ServerInfo.
func ParseLDAPURL(url string) (*ServerInfo, error) {
	if url == "" {
		return nil, fmt.Errorf("URL cannot be empty")
	}

	// Basic URL parsing for LDAP URLs
	var host string
	var port int
	var useTLS bool

	if strings.HasPrefix(url, "ldaps://") {
		useTLS = true
		url = strings.TrimPrefix(url, "ldaps://")
	} else if strings.HasPrefix(url, "ldap://") {
		useTLS = false
		url = strings.TrimPrefix(url, "ldap://")
	} else {
		return nil, fmt.Errorf("unsupported scheme, must be ldap:// or ldaps://")
	}

	// Extract host and port
	if strings.Contains(url, ":") {
		parts := strings.Split(url, ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid URL format")
		}
		host = parts[0]

		// Parse port, handling potential path after port
		portStr := parts[1]
		if strings.Contains(portStr, "/") {
			portStr = strings.Split(portStr, "/")[0]
		}

		var err error
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port number: %s", portStr)
		}
	} else {
		// Default ports
		host = url
		if strings.Contains(host, "/") {
			host = strings.Split(host, "/")[0]
		}

		if useTLS {
			port = 636 // LDAPS default
		} else {
			port = 389 // LDAP default
		}
	}

	server := &ServerInfo{
		Host:     host,
		Port:     port,
		UseTLS:   useTLS,
		Priority: 0, // Explicitly configured URLs get highest priority
		Weight:   100,
		Source:   "config",
	}

	return server, ValidateServerInfo(server)
}
