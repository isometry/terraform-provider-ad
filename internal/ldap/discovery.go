package ldap

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// SRVDiscovery handles DNS SRV record discovery for domain controllers.
type SRVDiscovery struct {
	ctx      context.Context // Logging context with LDAP subsystem
	resolver *net.Resolver
}

// NewSRVDiscovery creates a new SRV discovery instance.
func NewSRVDiscovery(ctx context.Context) *SRVDiscovery {
	return &SRVDiscovery{
		ctx:      ctx,
		resolver: net.DefaultResolver,
	}
}

// DiscoverServers discovers LDAP servers for a domain using SRV records.
// Queries the standard Active Directory SRV record: _ldap._tcp.<domain>
// Returns error if no SRV records found. Use ldap_url provider configuration
// to specify servers directly when SRV records are not available.
func (d *SRVDiscovery) DiscoverServers(ctx context.Context, domain string) ([]*ServerInfo, error) {
	start := time.Now()
	tflog.SubsystemDebug(d.ctx, "ldap", "Starting server discovery for domain", map[string]any{
		"domain": domain,
	})

	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	// Query standard Active Directory SRV record
	service := "_ldap._tcp." + domain

	tflog.SubsystemDebug(d.ctx, "ldap", "Attempting SRV lookup", map[string]any{
		"service": service,
	})

	servers, err := d.lookupSRV(ctx, service)
	if err != nil {
		tflog.SubsystemError(d.ctx, "ldap", "SRV lookup failed", map[string]any{
			"service": service,
			"error":   err.Error(),
		})

		return nil, fmt.Errorf(
			"no LDAP servers discovered via DNS SRV records for domain %s. "+
				"Verify DNS configuration with 'nslookup -type=SRV %s' or "+
				"use 'ldap_url' provider configuration to specify server directly: %w",
			domain, service, err,
		)
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf(
			"no LDAP servers found in SRV record %s for domain %s. "+
				"Verify DNS configuration or use 'ldap_url' provider configuration",
			service, domain,
		)
	}

	// Sort servers by priority (lower priority = higher preference)
	d.sortServersByPriority(servers)

	tflog.SubsystemInfo(d.ctx, "ldap", "Server discovery completed", map[string]any{
		"duration":     time.Since(start).String(),
		"server_count": len(servers),
	})

	return servers, nil
}

// lookupSRV performs SRV record lookup for a specific service.
// Discovered servers are always configured for plain LDAP (UseTLS=false)
// as AD SRV records point to port 389. TLS is applied via StartTLS based
// on ConnectionConfig.UseTLS, not per-server configuration.
func (d *SRVDiscovery) lookupSRV(ctx context.Context, service string) ([]*ServerInfo, error) {
	start := time.Now()
	tflog.SubsystemDebug(d.ctx, "ldap", "Looking up SRV records for service", map[string]any{
		"service": service,
	})

	_, srvRecords, err := d.resolver.LookupSRV(ctx, "", "", service)
	duration := time.Since(start)

	if err != nil {
		tflog.SubsystemDebug(d.ctx, "ldap", "SRV lookup failed", map[string]any{
			"service":  service,
			"duration": duration.String(),
			"error":    err.Error(),
		})
		return nil, fmt.Errorf("SRV lookup failed for %s: %w", service, err)
	}

	tflog.SubsystemDebug(d.ctx, "ldap", "SRV lookup completed", map[string]any{
		"service":      service,
		"duration":     duration.String(),
		"record_count": len(srvRecords),
	})

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
			UseTLS:   false, // SRV records always point to plain LDAP (port 389)
			Priority: int(srv.Priority),
			Weight:   int(srv.Weight),
			Source:   "srv", // This function is specifically for SRV discovery
		}
		servers = append(servers, server)
	}

	return servers, nil
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
