package ldap

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// MockGroupMembershipClient implements Client interface for membership testing.
type MockGroupMembershipClient struct {
	groups       map[string]*MockGroup
	groupsByDN   map[string]*MockGroup
	objects      map[string]*MockObject // For member resolution
	operationLog []string               // Track operations for testing
}

// MockGroup represents a group with membership.
type MockGroup struct {
	ObjectGUID        string
	DistinguishedName string
	Name              string
	SAMAccountName    string
	Members           []string // Member DNs
}

// MockObject represents any AD object for member resolution.
type MockObject struct {
	DN                string
	ObjectGUID        string
	ObjectSid         string
	UserPrincipalName string
	SAMAccountName    string
}

func NewMockGroupMembershipClient() *MockGroupMembershipClient {
	return &MockGroupMembershipClient{
		groups:       make(map[string]*MockGroup),
		groupsByDN:   make(map[string]*MockGroup),
		objects:      make(map[string]*MockObject),
		operationLog: make([]string, 0),
	}
}

func (m *MockGroupMembershipClient) AddMockGroup(guid, dn, name, sam string) {
	group := &MockGroup{
		ObjectGUID:        guid,
		DistinguishedName: dn,
		Name:              name,
		SAMAccountName:    sam,
		Members:           make([]string, 0),
	}
	m.groups[guid] = group
	m.groupsByDN[dn] = group
}

func (m *MockGroupMembershipClient) AddMockObject(dn, guid, sid, upn, sam string) {
	obj := &MockObject{
		DN:                dn,
		ObjectGUID:        guid,
		ObjectSid:         sid,
		UserPrincipalName: upn,
		SAMAccountName:    sam,
	}
	m.objects[dn] = obj
	if guid != "" {
		m.objects[guid] = obj
	}
	if sid != "" {
		m.objects[sid] = obj
	}
	if upn != "" {
		m.objects[upn] = obj
	}
	if sam != "" {
		m.objects[sam] = obj
	}
}

// Implement Client interface methods.
func (m *MockGroupMembershipClient) Connect(ctx context.Context) error {
	return nil
}

func (m *MockGroupMembershipClient) Close() error {
	return nil
}

func (m *MockGroupMembershipClient) Bind(ctx context.Context, username, password string) error {
	return nil
}

func (m *MockGroupMembershipClient) BindWithConfig(ctx context.Context) error {
	return nil
}

func (m *MockGroupMembershipClient) Add(ctx context.Context, req *AddRequest) error {
	m.operationLog = append(m.operationLog, fmt.Sprintf("Add: %s", req.DN))
	return nil
}

func (m *MockGroupMembershipClient) Delete(ctx context.Context, dn string) error {
	m.operationLog = append(m.operationLog, fmt.Sprintf("Delete: %s", dn))
	return nil
}

func (m *MockGroupMembershipClient) Ping(ctx context.Context) error {
	return nil
}

func (m *MockGroupMembershipClient) Stats() PoolStats {
	return PoolStats{}
}

func (m *MockGroupMembershipClient) SearchWithPaging(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	return m.Search(ctx, req)
}

func (m *MockGroupMembershipClient) GetBaseDN(ctx context.Context) (string, error) {
	return "DC=example,DC=com", nil
}

func (m *MockGroupMembershipClient) Search(ctx context.Context, req *SearchRequest) (*SearchResult, error) {
	m.operationLog = append(m.operationLog, fmt.Sprintf("Search: %s", req.Filter))

	// Handle group searches by GUID
	if strings.Contains(req.Filter, "objectGUID") {
		return m.handleGroupGUIDSearch(req)
	}

	// Handle group searches by DN (base object)
	if req.Scope == ScopeBaseObject && req.BaseDN != "" {
		return m.handleBaseObjectSearch(req)
	}

	// Handle member resolution searches
	if strings.Contains(req.Filter, "objectSid") ||
		strings.Contains(req.Filter, "userPrincipalName") ||
		strings.Contains(req.Filter, "sAMAccountName") {
		return m.handleMemberResolutionSearch(req)
	}

	return &SearchResult{Entries: []*ldap.Entry{}, Total: 0}, nil
}

func (m *MockGroupMembershipClient) Modify(ctx context.Context, req *ModifyRequest) error {
	operation := fmt.Sprintf("Modify: %s", req.DN)
	if len(req.AddAttributes) > 0 {
		operation += fmt.Sprintf(" ADD(%v)", req.AddAttributes)
	}
	if len(req.ReplaceAttributes) > 0 {
		operation += fmt.Sprintf(" REPLACE(%v)", req.ReplaceAttributes)
	}
	if len(req.DeleteAttributes) > 0 {
		operation += fmt.Sprintf(" DELETE(%v)", req.DeleteAttributes)
	}
	m.operationLog = append(m.operationLog, operation)

	// Find the group being modified
	group, exists := m.groupsByDN[req.DN]
	if !exists {
		return fmt.Errorf("group not found: %s", req.DN)
	}

	// Handle member additions
	if addMembers, exists := req.AddAttributes["member"]; exists {
		for _, memberDN := range addMembers {
			// Check if member already exists (simulate AD conflict)
			for _, existing := range group.Members {
				if strings.EqualFold(existing, memberDN) {
					return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, fmt.Errorf("member already exists: %s", memberDN))
				}
			}
			group.Members = append(group.Members, memberDN)
		}
	}

	// Handle member replacement
	if replaceMembers, exists := req.ReplaceAttributes["member"]; exists {
		group.Members = make([]string, len(replaceMembers))
		copy(group.Members, replaceMembers)
	}

	// Handle member deletion
	for _, attr := range req.DeleteAttributes {
		if attr == "member" {
			group.Members = make([]string, 0)
		}
	}

	return nil
}

func (m *MockGroupMembershipClient) ModifyDN(ctx context.Context, req *ModifyDNRequest) error {
	operation := fmt.Sprintf("ModifyDN: %s -> %s (superior: %s)", req.DN, req.NewRDN, req.NewSuperior)
	m.operationLog = append(m.operationLog, operation)

	// This is a mock - just simulate success for now
	// In a real implementation this would move the group in AD
	return nil
}

func (m *MockGroupMembershipClient) WhoAmI(ctx context.Context) (*WhoAmIResult, error) {
	// Return a default result for testing
	return &WhoAmIResult{
		AuthzID: "u:CN=Test User,CN=Users,DC=example,DC=com",
	}, nil
}

func (m *MockGroupMembershipClient) handleGroupGUIDSearch(req *SearchRequest) (*SearchResult, error) {
	// Extract GUID from filter (simplified)
	if strings.Contains(req.Filter, "objectGUID") {
		// This is a simplified GUID extraction - in real tests this would be more robust
		for _, group := range m.groups {
			entry := m.createGroupEntry(group)
			return &SearchResult{Entries: []*ldap.Entry{entry}, Total: 1}, nil
		}
	}
	return &SearchResult{Entries: []*ldap.Entry{}, Total: 0}, nil
}

func (m *MockGroupMembershipClient) handleBaseObjectSearch(req *SearchRequest) (*SearchResult, error) {
	// Check if it's a group
	if group, exists := m.groupsByDN[req.BaseDN]; exists {
		entry := m.createGroupEntry(group)
		return &SearchResult{Entries: []*ldap.Entry{entry}, Total: 1}, nil
	}

	// Check if it's a member object
	if obj, exists := m.objects[req.BaseDN]; exists {
		entry := m.createObjectEntry(obj)
		return &SearchResult{Entries: []*ldap.Entry{entry}, Total: 1}, nil
	}

	return &SearchResult{Entries: []*ldap.Entry{}, Total: 0}, nil
}

func (m *MockGroupMembershipClient) handleMemberResolutionSearch(req *SearchRequest) (*SearchResult, error) {
	// Extract search value from filter
	filter := req.Filter

	for _, obj := range m.objects {
		found := false

		if strings.Contains(filter, "objectSid") && obj.ObjectSid != "" && strings.Contains(filter, obj.ObjectSid) {
			found = true
		} else if strings.Contains(filter, "userPrincipalName") && obj.UserPrincipalName != "" && strings.Contains(filter, obj.UserPrincipalName) {
			found = true
		} else if strings.Contains(filter, "sAMAccountName") && obj.SAMAccountName != "" && strings.Contains(filter, obj.SAMAccountName) {
			found = true
		}

		if found {
			entry := m.createObjectEntry(obj)
			return &SearchResult{Entries: []*ldap.Entry{entry}, Total: 1}, nil
		}
	}

	return &SearchResult{Entries: []*ldap.Entry{}, Total: 0}, nil
}

func (m *MockGroupMembershipClient) createGroupEntry(group *MockGroup) *ldap.Entry {
	// Convert GUID string to binary format for objectGUID
	guidHandler := NewGUIDHandler()
	guidBytes, _ := guidHandler.StringToGUIDBytes(group.ObjectGUID)

	entry := &ldap.Entry{
		DN: group.DistinguishedName,
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", ByteValues: [][]byte{guidBytes}},
			{Name: "distinguishedName", Values: []string{group.DistinguishedName}},
			{Name: "cn", Values: []string{group.Name}},
			{Name: "sAMAccountName", Values: []string{group.SAMAccountName}},
			{Name: "objectClass", Values: []string{"group"}},
		},
	}

	// Add members if any
	if len(group.Members) > 0 {
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
			Name:   "member",
			Values: group.Members,
		})
	}

	return entry
}

func (m *MockGroupMembershipClient) createObjectEntry(obj *MockObject) *ldap.Entry {
	attributes := []*ldap.EntryAttribute{
		{Name: "distinguishedName", Values: []string{obj.DN}},
	}

	if obj.ObjectGUID != "" {
		guidHandler := NewGUIDHandler()
		if guidBytes, err := guidHandler.StringToGUIDBytes(obj.ObjectGUID); err == nil {
			attributes = append(attributes, &ldap.EntryAttribute{Name: "objectGUID", ByteValues: [][]byte{guidBytes}})
		}
	}
	if obj.ObjectSid != "" {
		attributes = append(attributes, &ldap.EntryAttribute{Name: "objectSid", Values: []string{obj.ObjectSid}})
	}
	if obj.UserPrincipalName != "" {
		attributes = append(attributes, &ldap.EntryAttribute{Name: "userPrincipalName", Values: []string{obj.UserPrincipalName}})
	}
	if obj.SAMAccountName != "" {
		attributes = append(attributes, &ldap.EntryAttribute{Name: "sAMAccountName", Values: []string{obj.SAMAccountName}})
	}

	return &ldap.Entry{
		DN:         obj.DN,
		Attributes: attributes,
	}
}

func (m *MockGroupMembershipClient) GetOperationLog() []string {
	return m.operationLog
}

func (m *MockGroupMembershipClient) ClearOperationLog() {
	m.operationLog = make([]string, 0)
}

// Test helper to create a test membership manager.
func createTestMembershipManager(t *testing.T) (*GroupMembershipManager, *MockGroupMembershipClient) {
	client := NewMockGroupMembershipClient()
	baseDN := "DC=example,DC=com"

	gmm := NewGroupMembershipManager(t.Context(), client, baseDN)
	gmm.SetTimeout(5 * time.Second)

	return gmm, client
}

func TestNewGroupMembershipManager(t *testing.T) {
	client := NewMockGroupMembershipClient()
	baseDN := "DC=example,DC=com"

	gmm := NewGroupMembershipManager(t.Context(), client, baseDN)

	if gmm.client != client {
		t.Error("Client not set correctly")
	}

	if gmm.timeout != 30*time.Second {
		t.Errorf("Expected default timeout 30s, got %v", gmm.timeout)
	}
}

func TestMembershipSetTimeout(t *testing.T) {
	gmm, _ := createTestMembershipManager(t)

	newTimeout := 45 * time.Second
	gmm.SetTimeout(newTimeout)

	if gmm.timeout != newTimeout {
		t.Errorf("Expected timeout %v, got %v", newTimeout, gmm.timeout)
	}
}

func TestGetGroupMembers(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup test group
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Add some members
	member1DN := "CN=User1,OU=Users,DC=example,DC=com"
	member2DN := "CN=User2,OU=Users,DC=example,DC=com"

	group := client.groups[groupGUID]
	group.Members = []string{member2DN, member1DN} // Unsorted to test sorting

	members, err := gmm.GetGroupMembers(groupGUID)

	if err != nil {
		t.Fatalf("GetGroupMembers failed: %v", err)
	}

	expected := []string{member1DN, member2DN} // Should be sorted
	if !reflect.DeepEqual(members, expected) {
		t.Errorf("Expected members %v, got %v", expected, members)
	}
}

func TestGetGroupMembersEmptyGroup(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup empty test group
	groupGUID := "87654321-4321-4321-4321-210987654321"
	groupDN := "CN=EmptyGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "EmptyGroup", "emptygroup")

	members, err := gmm.GetGroupMembers(groupGUID)

	if err != nil {
		t.Fatalf("GetGroupMembers failed: %v", err)
	}

	if len(members) != 0 {
		t.Errorf("Expected empty members list, got %v", members)
	}
}

func TestAddGroupMembers(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Add mock objects for normalization
	user1DN := "CN=User1,OU=Users,DC=example,DC=com"
	user1GUID := "11111111-1111-1111-1111-111111111111"
	user1UPN := "user1@example.com"
	client.AddMockObject(user1DN, user1GUID, "", user1UPN, "user1")

	user2DN := "CN=User2,OU=Users,DC=example,DC=com"
	user2SAM := "EXAMPLE\\user2"
	client.AddMockObject(user2DN, "", "", "", "user2")

	// Test adding members using different identifier formats
	membersToAdd := []string{
		user1DN,  // DN format
		user1UPN, // UPN format
		user2SAM, // SAM format
	}

	err := gmm.AddGroupMembers(groupGUID, membersToAdd)

	if err != nil {
		t.Fatalf("AddGroupMembers failed: %v", err)
	}

	// Verify members were added
	group := client.groups[groupGUID]
	expectedMembers := []string{user1DN, user2DN} // Should be normalized to DNs
	sort.Strings(group.Members)
	sort.Strings(expectedMembers)

	if !reflect.DeepEqual(group.Members, expectedMembers) {
		t.Errorf("Expected members %v, got %v", expectedMembers, group.Members)
	}
}

func TestAddGroupMembersWithConflicts(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Add mock objects
	user1DN := "CN=User1,OU=Users,DC=example,DC=com"
	user2DN := "CN=User2,OU=Users,DC=example,DC=com"
	client.AddMockObject(user1DN, "", "", "", "user1")
	client.AddMockObject(user2DN, "", "", "", "user2")

	// Pre-populate group with user1
	group := client.groups[groupGUID]
	group.Members = []string{user1DN}

	// Try to add both users (user1 should conflict, user2 should succeed)
	membersToAdd := []string{user1DN, user2DN}

	err := gmm.AddGroupMembers(groupGUID, membersToAdd)

	// Should succeed despite conflict (graceful handling)
	if err != nil {
		t.Fatalf("AddGroupMembers should handle conflicts gracefully, got error: %v", err)
	}

	// Verify both members are present
	expectedMembers := []string{user1DN, user2DN}
	sort.Strings(group.Members)
	sort.Strings(expectedMembers)

	if !reflect.DeepEqual(group.Members, expectedMembers) {
		t.Errorf("Expected members %v, got %v", expectedMembers, group.Members)
	}
}

func TestRemoveGroupMembers(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Add mock objects
	user1DN := "CN=User1,OU=Users,DC=example,DC=com"
	user2DN := "CN=User2,OU=Users,DC=example,DC=com"
	user3DN := "CN=User3,OU=Users,DC=example,DC=com"
	client.AddMockObject(user1DN, "", "", "user1@example.com", "user1")
	client.AddMockObject(user2DN, "", "", "", "user2")
	client.AddMockObject(user3DN, "", "", "", "user3")

	// Pre-populate group with all users
	group := client.groups[groupGUID]
	group.Members = []string{user1DN, user2DN, user3DN}

	// Remove user1 and user2 using different identifier formats
	membersToRemove := []string{
		"user1@example.com", // UPN format for user1
		user2DN,             // DN format for user2
	}

	err := gmm.RemoveGroupMembers(groupGUID, membersToRemove)

	if err != nil {
		t.Fatalf("RemoveGroupMembers failed: %v", err)
	}

	// Verify only user3 remains
	expectedMembers := []string{user3DN}
	if !reflect.DeepEqual(group.Members, expectedMembers) {
		t.Errorf("Expected members %v, got %v", expectedMembers, group.Members)
	}
}

func TestRemoveAllGroupMembers(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Add mock objects
	user1DN := "CN=User1,OU=Users,DC=example,DC=com"
	user2DN := "CN=User2,OU=Users,DC=example,DC=com"
	client.AddMockObject(user1DN, "", "", "", "user1")
	client.AddMockObject(user2DN, "", "", "", "user2")

	// Pre-populate group
	group := client.groups[groupGUID]
	group.Members = []string{user1DN, user2DN}

	// Remove all members
	membersToRemove := []string{user1DN, user2DN}

	err := gmm.RemoveGroupMembers(groupGUID, membersToRemove)

	if err != nil {
		t.Fatalf("RemoveGroupMembers failed: %v", err)
	}

	// Verify group is empty
	if len(group.Members) != 0 {
		t.Errorf("Expected empty group, got members: %v", group.Members)
	}
}

func TestCalculateMembershipDelta(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Add mock objects
	user1DN := "CN=User1,OU=Users,DC=example,DC=com"
	user2DN := "CN=User2,OU=Users,DC=example,DC=com"
	user3DN := "CN=User3,OU=Users,DC=example,DC=com"
	user4DN := "CN=User4,OU=Users,DC=example,DC=com"

	client.AddMockObject(user1DN, "", "", "", "user1")
	client.AddMockObject(user2DN, "", "", "user2@example.com", "user2")
	client.AddMockObject(user3DN, "", "", "", "user3")
	client.AddMockObject(user4DN, "", "", "", "user4")

	// Current group has user1 and user2
	group := client.groups[groupGUID]
	group.Members = []string{user1DN, user2DN}

	// Desired state: user2, user3, user4 (using mixed identifier formats)
	desiredMembers := []string{
		"user2@example.com", // UPN format (existing member)
		user3DN,             // DN format (new member)
		user4DN,             // DN format (new member)
	}

	delta, err := gmm.CalculateMembershipDelta(groupGUID, desiredMembers)

	if err != nil {
		t.Fatalf("CalculateMembershipDelta failed: %v", err)
	}

	// Expected: add user3 and user4, remove user1
	expectedToAdd := []string{user3DN, user4DN}
	expectedToRemove := []string{user1DN}

	sort.Strings(delta.ToAdd)
	sort.Strings(delta.ToRemove)
	sort.Strings(expectedToAdd)
	sort.Strings(expectedToRemove)

	if !reflect.DeepEqual(delta.ToAdd, expectedToAdd) {
		t.Errorf("Expected ToAdd %v, got %v", expectedToAdd, delta.ToAdd)
	}

	if !reflect.DeepEqual(delta.ToRemove, expectedToRemove) {
		t.Errorf("Expected ToRemove %v, got %v", expectedToRemove, delta.ToRemove)
	}
}

func TestCalculateMembershipDeltaNoChanges(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Add mock objects
	user1DN := "CN=User1,OU=Users,DC=example,DC=com"
	user2DN := "CN=User2,OU=Users,DC=example,DC=com"

	client.AddMockObject(user1DN, "", "", "user1@example.com", "user1")
	client.AddMockObject(user2DN, "", "", "", "user2")

	// Current group has user1 and user2
	group := client.groups[groupGUID]
	group.Members = []string{user1DN, user2DN}

	// Desired state: same members but in different identifier formats
	desiredMembers := []string{
		"user1@example.com", // UPN format for user1
		user2DN,             // DN format for user2
	}

	delta, err := gmm.CalculateMembershipDelta(groupGUID, desiredMembers)

	if err != nil {
		t.Fatalf("CalculateMembershipDelta failed: %v", err)
	}

	// Should detect no changes needed
	if len(delta.ToAdd) != 0 {
		t.Errorf("Expected no additions, got %v", delta.ToAdd)
	}

	if len(delta.ToRemove) != 0 {
		t.Errorf("Expected no removals, got %v", delta.ToRemove)
	}
}

func TestSetGroupMembers(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Add mock objects
	user1DN := "CN=User1,OU=Users,DC=example,DC=com"
	user2DN := "CN=User2,OU=Users,DC=example,DC=com"
	user3DN := "CN=User3,OU=Users,DC=example,DC=com"

	client.AddMockObject(user1DN, "", "", "user1@example.com", "user1")
	client.AddMockObject(user2DN, "", "", "", "user2")
	client.AddMockObject(user3DN, "", "", "", "user3")

	// Start with user1 in the group
	group := client.groups[groupGUID]
	group.Members = []string{user1DN}

	// Set membership to user2 and user3
	desiredMembers := []string{
		user2DN,             // DN format
		"user1@example.com", // UPN format for user1
	}

	err := gmm.SetGroupMembers(groupGUID, desiredMembers)

	if err != nil {
		t.Fatalf("SetGroupMembers failed: %v", err)
	}

	// Verify final membership
	expectedMembers := []string{user1DN, user2DN} // Normalized to DNs
	sort.Strings(group.Members)
	sort.Strings(expectedMembers)

	if !reflect.DeepEqual(group.Members, expectedMembers) {
		t.Errorf("Expected final members %v, got %v", expectedMembers, group.Members)
	}
}

func TestSetGroupMembersEmptyDesiredList(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Add mock objects
	user1DN := "CN=User1,OU=Users,DC=example,DC=com"
	user2DN := "CN=User2,OU=Users,DC=example,DC=com"
	client.AddMockObject(user1DN, "", "", "", "user1")
	client.AddMockObject(user2DN, "", "", "", "user2")

	// Start with members in the group
	group := client.groups[groupGUID]
	group.Members = []string{user1DN, user2DN}

	// Set empty membership
	desiredMembers := []string{}

	err := gmm.SetGroupMembers(groupGUID, desiredMembers)

	if err != nil {
		t.Fatalf("SetGroupMembers failed: %v", err)
	}

	// Verify group is now empty
	if len(group.Members) != 0 {
		t.Errorf("Expected empty group, got members: %v", group.Members)
	}
}

func TestValidateMembers(t *testing.T) {
	gmm, _ := createTestMembershipManager(t)

	tests := []struct {
		name        string
		members     []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid DN",
			members:     []string{"CN=User,OU=Users,DC=example,DC=com"},
			expectError: false,
		},
		{
			name:        "Valid UPN",
			members:     []string{"user@example.com"},
			expectError: false,
		},
		{
			name:        "Valid SAM",
			members:     []string{"DOMAIN\\user"},
			expectError: false,
		},
		{
			name:        "Mixed valid formats",
			members:     []string{"CN=User1,OU=Users,DC=example,DC=com", "user2@example.com", "DOMAIN\\user3"},
			expectError: false,
		},
		{
			name:        "Invalid identifier",
			members:     []string{"@invalid@format@"},
			expectError: true,
			errorMsg:    "unknown identifier format",
		},
		{
			name:        "Empty string",
			members:     []string{""},
			expectError: true,
			errorMsg:    "identifier cannot be empty",
		},
		{
			name:        "Empty list",
			members:     []string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := gmm.ValidateMembers(tt.members)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestGetMembershipStats(t *testing.T) {
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	groupName := "TestGroup"
	client.AddMockGroup(groupGUID, groupDN, groupName, "testgroup")

	// Add some members
	user1DN := "CN=User1,OU=Users,DC=example,DC=com"
	user2DN := "CN=User2,OU=Users,DC=example,DC=com"

	group := client.groups[groupGUID]
	group.Members = []string{user1DN, user2DN}

	stats, err := gmm.GetMembershipStats(groupGUID)

	if err != nil {
		t.Fatalf("GetMembershipStats failed: %v", err)
	}

	// Verify stats content
	if stats["group_dn"] != groupDN {
		t.Errorf("Expected group_dn %s, got %s", groupDN, stats["group_dn"])
	}

	if stats["group_name"] != groupName {
		t.Errorf("Expected group_name %s, got %s", groupName, stats["group_name"])
	}

	if stats["member_count"] != 2 {
		t.Errorf("Expected member_count 2, got %v", stats["member_count"])
	}

	memberDNs, ok := stats["member_dns"].([]string)
	if !ok {
		t.Errorf("Expected member_dns to be []string, got %T", stats["member_dns"])
	} else if len(memberDNs) != 2 {
		t.Errorf("Expected 2 member DNs, got %d", len(memberDNs))
	}

	// Should include cache stats
	if _, exists := stats["cache_stats"]; !exists {
		t.Error("Expected cache_stats in response")
	}
}

func TestAntiDriftScenario(t *testing.T) {
	// This test simulates a real anti-drift scenario where the same user
	// is specified in different identifier formats but should be treated as one user
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Add mock user with multiple identifiers
	userDN := "CN=John Doe,OU=Users,DC=example,DC=com"
	userGUID := "22222222-2222-2222-2222-222222222222"
	userSID := "S-1-5-21-123456789-123456789-123456789-1001"
	userUPN := "john.doe@example.com"

	client.AddMockObject(userDN, userGUID, userSID, userUPN, "john.doe")

	// Initial state: group has the user by DN
	group := client.groups[groupGUID]
	group.Members = []string{userDN}

	// Terraform config specifies the same user by UPN
	// This should NOT result in any membership changes
	desiredMembers := []string{userUPN}

	// Test 1: Calculate delta - should show no changes needed
	delta, err := gmm.CalculateMembershipDelta(groupGUID, desiredMembers)
	if err != nil {
		t.Fatalf("CalculateMembershipDelta failed: %v", err)
	}

	if len(delta.ToAdd) != 0 || len(delta.ToRemove) != 0 {
		t.Errorf("Anti-drift failed: expected no changes, got ToAdd=%v, ToRemove=%v", delta.ToAdd, delta.ToRemove)
	}

	// Test 2: SetGroupMembers should be a no-op
	client.ClearOperationLog()

	err = gmm.SetGroupMembers(groupGUID, desiredMembers)
	if err != nil {
		t.Fatalf("SetGroupMembers failed: %v", err)
	}

	// Should have only performed search operations, no modifications
	log := client.GetOperationLog()
	for _, operation := range log {
		if strings.Contains(operation, "Modify:") {
			t.Errorf("Unexpected modify operation in anti-drift scenario: %s", operation)
		}
	}

	// Final membership should still be the original DN
	finalMembers := group.Members
	if len(finalMembers) != 1 || finalMembers[0] != userDN {
		t.Errorf("Anti-drift failed: expected final members [%s], got %v", userDN, finalMembers)
	}
}

func TestBatchOperationsLargeSet(t *testing.T) {
	// Test that large member sets are handled in batches
	gmm, client := createTestMembershipManager(t)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Create 2500 mock users (more than the 1000 batch limit)
	largeUserSet := make([]string, 2500)
	for i := range 2500 {
		userDN := fmt.Sprintf("CN=User%d,OU=Users,DC=example,DC=com", i)
		largeUserSet[i] = userDN
		client.AddMockObject(userDN, "", "", "", fmt.Sprintf("user%d", i))
	}

	client.ClearOperationLog()

	// Add all users - should be done in batches
	err := gmm.AddGroupMembers(groupGUID, largeUserSet)

	if err != nil {
		t.Fatalf("AddGroupMembers with large set failed: %v", err)
	}

	// Verify that multiple modify operations were performed (indicating batching)
	log := client.GetOperationLog()
	modifyCount := 0
	for _, operation := range log {
		if strings.Contains(operation, "Modify:") && strings.Contains(operation, "ADD") {
			modifyCount++
		}
	}

	// Should have at least 3 batches (2500 members / 1000 batch size = 2.5, rounded up to 3)
	if modifyCount < 3 {
		t.Errorf("Expected at least 3 batch operations for 2500 members, got %d", modifyCount)
	}

	// Verify all members were added
	group := client.groups[groupGUID]
	if len(group.Members) != 2500 {
		t.Errorf("Expected 2500 members added, got %d", len(group.Members))
	}
}

func TestClearNormalizationCache(t *testing.T) {
	gmm, _ := createTestMembershipManager(t)

	// This is mostly a smoke test to ensure the method exists and doesn't panic
	gmm.ClearNormalizationCache()

	// Verify cache is cleared by checking stats
	stats := gmm.normalizer.CacheStats()
	totalEntries, ok := stats["total_entries"].(int)
	if !ok {
		t.Fatalf("Expected total_entries to be an int, got %T", stats["total_entries"])
	}

	if totalEntries != 0 {
		t.Errorf("Expected cache to be empty after clear, got %d entries", totalEntries)
	}
}

func TestGetSupportedIdentifierFormats(t *testing.T) {
	gmm, _ := createTestMembershipManager(t)

	formats := gmm.GetSupportedIdentifierFormats()

	if len(formats) == 0 {
		t.Error("Expected non-empty list of supported formats")
	}

	// Check that expected formats are included
	expectedFormats := []string{"DN", "GUID", "SID", "UPN", "SAM"}

	formatStr := strings.Join(formats, " ")
	for _, expected := range expectedFormats {
		if !strings.Contains(formatStr, expected) {
			t.Errorf("Expected format '%s' not found in supported formats: %v", expected, formats)
		}
	}
}

func TestSetBaseDN(t *testing.T) {
	gmm, _ := createTestMembershipManager(t)

	newBaseDN := "DC=newdomain,DC=com"
	gmm.SetBaseDN(newBaseDN)

	// Verify both the group manager and normalizer were updated
	if gmm.groupManager.baseDN != newBaseDN {
		t.Errorf("Expected group manager baseDN %s, got %s", newBaseDN, gmm.groupManager.baseDN)
	}

	if gmm.normalizer.GetBaseDN() != newBaseDN {
		t.Errorf("Expected normalizer baseDN %s, got %s", newBaseDN, gmm.normalizer.GetBaseDN())
	}
}

// Benchmark tests for performance validation.
func BenchmarkNormalizeLargeSet(b *testing.B) {
	client := NewMockGroupMembershipClient()
	baseDN := "DC=example,DC=com"
	gmm := NewGroupMembershipManager(context.Background(), client, baseDN)

	// Setup test data
	testMembers := make([]string, 100)
	for i := range 100 {
		userDN := fmt.Sprintf("CN=User%d,OU=Users,DC=example,DC=com", i)
		testMembers[i] = userDN
		client.AddMockObject(userDN, "", "", "", fmt.Sprintf("user%d", i))
	}

	for b.Loop() {
		_, err := gmm.normalizer.NormalizeToDNBatch(testMembers)
		if err != nil {
			b.Fatalf("Normalization failed: %v", err)
		}
	}
}

func BenchmarkCalculateMembershipDelta(b *testing.B) {
	client := NewMockGroupMembershipClient()
	baseDN := "DC=example,DC=com"
	gmm := NewGroupMembershipManager(context.Background(), client, baseDN)

	// Setup test data
	groupGUID := "12345678-1234-1234-1234-123456789012"
	groupDN := "CN=TestGroup,OU=Groups,DC=example,DC=com"
	client.AddMockGroup(groupGUID, groupDN, "TestGroup", "testgroup")

	// Create test members
	testMembers := make([]string, 100)
	for i := range 100 {
		userDN := fmt.Sprintf("CN=User%d,OU=Users,DC=example,DC=com", i)
		testMembers[i] = userDN
		client.AddMockObject(userDN, "", "", "", fmt.Sprintf("user%d", i))
	}

	// Set initial group membership (first 50 users)
	group := client.groups[groupGUID]
	group.Members = testMembers[:50]

	// Desired membership (last 50 users)
	desiredMembers := testMembers[50:]

	for b.Loop() {
		_, err := gmm.CalculateMembershipDelta(groupGUID, desiredMembers)
		if err != nil {
			b.Fatalf("Delta calculation failed: %v", err)
		}
	}
}
