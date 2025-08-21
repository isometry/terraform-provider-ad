package provider

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/isometry/terraform-provider-ad/internal/ldap"
)

// Test environment configuration constants.
const (
	// Environment variables for test configuration.
	EnvTestDomain    = "AD_TEST_DOMAIN"
	EnvTestLDAPURL   = "AD_TEST_LDAP_URL"
	EnvTestUsername  = "AD_TEST_USERNAME"
	EnvTestPassword  = "AD_TEST_PASSWORD"
	EnvTestBaseDN    = "AD_TEST_BASE_DN"
	EnvTestContainer = "AD_TEST_CONTAINER"
	EnvTestKeytab    = "AD_TEST_KEYTAB"
	EnvTestRealm     = "AD_TEST_REALM"

	// Default values for testing.
	DefaultTestContainer = "CN=Users"
	DefaultTestDomain    = "example.com"
	DefaultTestBaseDN    = "DC=example,DC=com"

	// Test object name prefixes to avoid conflicts.
	TestGroupPrefix = "tf-test-group-"
	TestOUPrefix    = "tf-test-ou-"
	TestUserPrefix  = "tf-test-user-"
)

// TestConfig holds common test configuration.
type TestConfig struct {
	Domain      string
	LDAPURL     string
	Username    string
	Password    string
	BaseDN      string
	Container   string
	Keytab      string
	Realm       string
	UseKerberos bool
}

// GetTestConfig returns the test configuration from environment variables.
func GetTestConfig() *TestConfig {
	config := &TestConfig{
		Domain:    getEnvWithDefault(EnvTestDomain, DefaultTestDomain),
		LDAPURL:   os.Getenv(EnvTestLDAPURL),
		Username:  os.Getenv(EnvTestUsername),
		Password:  os.Getenv(EnvTestPassword),
		BaseDN:    getEnvWithDefault(EnvTestBaseDN, DefaultTestBaseDN),
		Container: getEnvWithDefault(EnvTestContainer, DefaultTestContainer),
		Keytab:    os.Getenv(EnvTestKeytab),
		Realm:     os.Getenv(EnvTestRealm),
	}

	// Determine if we should use Kerberos authentication
	config.UseKerberos = config.Keytab != "" && config.Realm != ""

	return config
}

// IsAccTest returns true if acceptance tests should run.
func IsAccTest() bool {
	return os.Getenv("TF_ACC") != ""
}

// SkipIfNotAccTest skips the test if TF_ACC is not set.
func SkipIfNotAccTest(t *testing.T) {
	if !IsAccTest() {
		t.Skip("Skipping acceptance test - set TF_ACC=1 to run")
	}
}

// testAccPreCheckWithConfig is an enhanced pre-check function that validates test environment.
func testAccPreCheckWithConfig(t *testing.T) *TestConfig {
	SkipIfNotAccTest(t)

	config := GetTestConfig()

	// Validate required configuration
	if config.Username == "" {
		t.Skipf("Skipping test: %s must be set", EnvTestUsername)
	}

	if config.Password == "" && !config.UseKerberos {
		t.Skipf("Skipping test: %s must be set (or configure Kerberos)", EnvTestPassword)
	}

	if config.UseKerberos && (config.Keytab == "" || config.Realm == "") {
		t.Skipf("Skipping test: Both %s and %s must be set for Kerberos auth", EnvTestKeytab, EnvTestRealm)
	}

	if config.LDAPURL == "" && config.Domain == DefaultTestDomain {
		t.Skipf("Skipping test: Either %s or %s must be set to a real AD environment", EnvTestLDAPURL, EnvTestDomain)
	}

	return config
}

// TestProviderConfig generates provider configuration for tests.
func TestProviderConfig() string {
	config := GetTestConfig()

	var providerConfig strings.Builder
	providerConfig.WriteString("provider \"ad\" {\n")

	if config.LDAPURL != "" {
		providerConfig.WriteString(fmt.Sprintf("  ldap_url = %q\n", config.LDAPURL))
	} else {
		providerConfig.WriteString(fmt.Sprintf("  domain = %q\n", config.Domain))
	}

	providerConfig.WriteString(fmt.Sprintf("  username = %q\n", config.Username))

	if config.UseKerberos {
		providerConfig.WriteString(fmt.Sprintf("  realm = %q\n", config.Realm))
		providerConfig.WriteString(fmt.Sprintf("  keytab = %q\n", config.Keytab))
	} else {
		providerConfig.WriteString(fmt.Sprintf("  password = %q\n", config.Password))
	}

	providerConfig.WriteString("}\n")
	return providerConfig.String()
}

// TestDomainDataSource generates a data source for getting domain info.
func TestDomainDataSource() string {
	return "data \"ad_domain\" \"test\" {}"
}

// GenerateTestName generates a unique test name with timestamp.
func GenerateTestName(prefix string) string {
	timestamp := time.Now().Format("20060102-150405")
	shortUUID := uuid.New().String()[:8]
	return fmt.Sprintf("%s%s-%s", prefix, timestamp, shortUUID)
}

// GenerateTestSAMName generates a valid SAM account name (max 20 chars).
func GenerateTestSAMName(prefix string) string {
	timestamp := time.Now().Format("0102-1504")
	shortUUID := uuid.New().String()[:4]
	samName := fmt.Sprintf("%s%s%s", prefix, timestamp, shortUUID)

	// Ensure SAM name is within AD limits (20 characters)
	if len(samName) > 20 {
		samName = samName[:20]
	}

	return samName
}

// TestDataGenerator provides test data generation utilities.
type TestDataGenerator struct {
	config *TestConfig
}

// NewTestDataGenerator creates a new test data generator.
func NewTestDataGenerator() *TestDataGenerator {
	return &TestDataGenerator{
		config: GetTestConfig(),
	}
}

// GenerateGroupConfig generates a test group configuration.
func (g *TestDataGenerator) GenerateGroupConfig(name, samName string) string {
	return fmt.Sprintf(`
resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[3]s,${data.ad_domain.test.distinguished_name}"
  scope            = "Global"
  category         = "Security"
}`, name, samName, g.config.Container)
}

// GenerateGroupConfigWithDescription generates a test group configuration with description.
func (g *TestDataGenerator) GenerateGroupConfigWithDescription(name, samName, description string) string {
	return fmt.Sprintf(`
resource "ad_group" "test" {
  name             = %[1]q
  sam_account_name = %[2]q
  container        = "%[3]s,${data.ad_domain.test.distinguished_name}"
  scope            = "Global"
  category         = "Security"
  description      = %[4]q
}`, name, samName, g.config.Container, description)
}

// GenerateOUConfig generates a test OU configuration.
func (g *TestDataGenerator) GenerateOUConfig(name string) string {
	return fmt.Sprintf(`
resource "ad_ou" "test" {
  name      = %[1]q
  container = "${data.ad_domain.test.distinguished_name}"
}`, name)
}

// GenerateOUConfigWithDescription generates a test OU configuration with description.
func (g *TestDataGenerator) GenerateOUConfigWithDescription(name, description string) string {
	return fmt.Sprintf(`
resource "ad_ou" "test" {
  name        = %[1]q
  container   = "${data.ad_domain.test.distinguished_name}"
  description = %[2]q
}`, name, description)
}

// TestFixture manages test fixtures for cleanup.
type TestFixture struct {
	client    ldap.Client
	resources []string
	t         *testing.T
}

// NewTestFixture creates a new test fixture manager.
func NewTestFixture(t *testing.T) *TestFixture {
	config := testAccPreCheckWithConfig(t)

	// Create LDAP client for cleanup operations
	ldapConfig := &ldap.ConnectionConfig{
		Domain:         config.Domain,
		LDAPURLs:       []string{config.LDAPURL},
		Username:       config.Username,
		Password:       config.Password,
		KerberosKeytab: config.Keytab,
		KerberosRealm:  config.Realm,
	}

	client, err := ldap.NewClient(ldapConfig)
	if err != nil {
		t.Fatalf("Failed to create LDAP client for test fixture: %v", err)
	}

	return &TestFixture{
		client:    client,
		resources: make([]string, 0),
		t:         t,
	}
}

// RegisterResource registers a resource for cleanup.
func (f *TestFixture) RegisterResource(dn string) {
	f.resources = append(f.resources, dn)
}

// Cleanup removes all registered test resources.
func (f *TestFixture) Cleanup() {
	ctx := context.Background()

	for _, dn := range f.resources {
		if err := f.client.Delete(ctx, dn); err != nil {
			// Log but don't fail the test if cleanup fails
			log.Printf("Failed to cleanup test resource %s: %v", dn, err)
		}
	}

	if err := f.client.Close(); err != nil {
		log.Printf("Failed to close LDAP client during cleanup: %v", err)
	}
}

// Test check functions for acceptance tests

// TestCheckGroupExists verifies that a group exists in AD.
func TestCheckGroupExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("resource ID not set")
		}

		config := GetTestConfig()
		ldapURLs := []string{}
		if config.LDAPURL != "" {
			ldapURLs = []string{config.LDAPURL}
		}
		ldapConfig := &ldap.ConnectionConfig{
			Domain:         config.Domain,
			LDAPURLs:       ldapURLs,
			Username:       config.Username,
			Password:       config.Password,
			KerberosKeytab: config.Keytab,
			KerberosRealm:  config.Realm,
		}

		client, err := ldap.NewClient(ldapConfig)
		if err != nil {
			return fmt.Errorf("failed to create LDAP client: %v", err)
		}
		defer client.Close()

		ctx := context.Background()
		groupManager := ldap.NewGroupManager(client, config.BaseDN)

		// Try to read the group by GUID (stored in ID)
		_, err = groupManager.GetGroup(ctx, rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("group %s does not exist: %v", rs.Primary.ID, err)
		}

		return nil
	}
}

// TestCheckGroupDestroy verifies that all test groups are destroyed.
func TestCheckGroupDestroy(s *terraform.State) error {
	config := GetTestConfig()
	ldapURLs := []string{}
	if config.LDAPURL != "" {
		ldapURLs = []string{config.LDAPURL}
	}
	ldapConfig := &ldap.ConnectionConfig{
		Domain:         config.Domain,
		LDAPURLs:       ldapURLs,
		Username:       config.Username,
		Password:       config.Password,
		KerberosKeytab: config.Keytab,
		KerberosRealm:  config.Realm,
	}

	client, err := ldap.NewClient(ldapConfig)
	if err != nil {
		return fmt.Errorf("failed to create LDAP client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	groupManager := ldap.NewGroupManager(client, config.BaseDN)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "ad_group" {
			continue
		}

		// Try to read the group - it should not exist
		_, err := groupManager.GetGroup(ctx, rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("group %s still exists", rs.Primary.ID)
		}

		// Verify it's a "not found" error, not some other error
		if !ldap.IsNotFoundError(err) {
			return fmt.Errorf("unexpected error checking group %s: %v", rs.Primary.ID, err)
		}
	}

	return nil
}

// TestCheckGroupDisappears manually deletes a group outside of Terraform.
func TestCheckGroupDisappears(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		config := GetTestConfig()
		ldapURLs := []string{}
		if config.LDAPURL != "" {
			ldapURLs = []string{config.LDAPURL}
		}
		ldapConfig := &ldap.ConnectionConfig{
			Domain:         config.Domain,
			LDAPURLs:       ldapURLs,
			Username:       config.Username,
			Password:       config.Password,
			KerberosKeytab: config.Keytab,
			KerberosRealm:  config.Realm,
		}

		client, err := ldap.NewClient(ldapConfig)
		if err != nil {
			return fmt.Errorf("failed to create LDAP client: %v", err)
		}
		defer client.Close()

		ctx := context.Background()
		groupManager := ldap.NewGroupManager(client, config.BaseDN)

		// Delete the group manually using its GUID
		err = groupManager.DeleteGroup(ctx, rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("failed to manually delete group: %v", err)
		}

		return nil
	}
}

// TestCheckOUExists verifies that an OU exists in AD.
func TestCheckOUExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("resource ID not set")
		}

		config := GetTestConfig()
		ldapURLs := []string{}
		if config.LDAPURL != "" {
			ldapURLs = []string{config.LDAPURL}
		}
		ldapConfig := &ldap.ConnectionConfig{
			Domain:         config.Domain,
			LDAPURLs:       ldapURLs,
			Username:       config.Username,
			Password:       config.Password,
			KerberosKeytab: config.Keytab,
			KerberosRealm:  config.Realm,
		}

		client, err := ldap.NewClient(ldapConfig)
		if err != nil {
			return fmt.Errorf("failed to create LDAP client: %v", err)
		}
		defer client.Close()

		ctx := context.Background()

		// Try to read the OU by searching for its GUID
		guidHandler := ldap.NewGUIDHandler()
		guidFilter, err := guidHandler.GUIDToSearchFilter(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("invalid GUID format %s: %v", rs.Primary.ID, err)
		}

		req := &ldap.SearchRequest{
			BaseDN:     config.BaseDN,
			Scope:      ldap.ScopeWholeSubtree,
			Filter:     guidFilter,
			Attributes: []string{"objectGUID", "distinguishedName", "name", "description"},
			SizeLimit:  1,
		}

		result, err := client.Search(ctx, req)
		if err != nil {
			return fmt.Errorf("OU %s does not exist: %v", rs.Primary.ID, err)
		}

		if len(result.Entries) == 0 {
			return fmt.Errorf("OU %s not found", rs.Primary.ID)
		}

		return nil
	}
}

// TestCheckOUDestroy verifies that all test OUs are destroyed.
func TestCheckOUDestroy(s *terraform.State) error {
	config := GetTestConfig()
	ldapURLs := []string{}
	if config.LDAPURL != "" {
		ldapURLs = []string{config.LDAPURL}
	}
	ldapConfig := &ldap.ConnectionConfig{
		Domain:         config.Domain,
		LDAPURLs:       ldapURLs,
		Username:       config.Username,
		Password:       config.Password,
		KerberosKeytab: config.Keytab,
		KerberosRealm:  config.Realm,
	}

	client, err := ldap.NewClient(ldapConfig)
	if err != nil {
		return fmt.Errorf("failed to create LDAP client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "ad_ou" {
			continue
		}

		// Try to read the OU - it should not exist
		guidHandler := ldap.NewGUIDHandler()
		guidFilter, err := guidHandler.GUIDToSearchFilter(rs.Primary.ID)
		if err != nil {
			// If GUID format is invalid, skip this check
			continue
		}

		req := &ldap.SearchRequest{
			BaseDN:     config.BaseDN,
			Scope:      ldap.ScopeWholeSubtree,
			Filter:     guidFilter,
			Attributes: []string{"objectGUID"},
			SizeLimit:  1,
		}

		result, err := client.Search(ctx, req)
		if err == nil && len(result.Entries) > 0 {
			return fmt.Errorf("OU %s still exists", rs.Primary.ID)
		}

		// Verify it's a "not found" error, not some other error
		if err != nil && !ldap.IsNotFoundError(err) {
			return fmt.Errorf("unexpected error checking OU %s: %v", rs.Primary.ID, err)
		}
	}

	return nil
}

// TestCheckGroupMembershipExists verifies that group membership exists.
func TestCheckGroupMembershipExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		groupID := rs.Primary.Attributes["group_id"]
		if groupID == "" {
			return fmt.Errorf("group_id not set in resource %s", resourceName)
		}

		membersStr := rs.Primary.Attributes["members.#"]
		if membersStr == "" {
			return fmt.Errorf("members count not set in resource %s", resourceName)
		}

		memberCount, err := strconv.Atoi(membersStr)
		if err != nil {
			return fmt.Errorf("invalid members count: %v", err)
		}

		if memberCount == 0 {
			return fmt.Errorf("no members found in group membership %s", resourceName)
		}

		config := GetTestConfig()
		ldapURLs := []string{}
		if config.LDAPURL != "" {
			ldapURLs = []string{config.LDAPURL}
		}
		ldapConfig := &ldap.ConnectionConfig{
			Domain:         config.Domain,
			LDAPURLs:       ldapURLs,
			Username:       config.Username,
			Password:       config.Password,
			KerberosKeytab: config.Keytab,
			KerberosRealm:  config.Realm,
		}

		client, err := ldap.NewClient(ldapConfig)
		if err != nil {
			return fmt.Errorf("failed to create LDAP client: %v", err)
		}
		defer client.Close()

		ctx := context.Background()
		membershipManager := ldap.NewGroupMembershipManager(client, config.BaseDN)

		// Verify the group has the expected members
		members, err := membershipManager.GetGroupMembers(ctx, groupID)
		if err != nil {
			return fmt.Errorf("failed to get group members: %v", err)
		}

		if len(members) != memberCount {
			return fmt.Errorf("expected %d members, found %d", memberCount, len(members))
		}

		return nil
	}
}

// Performance test utilities

// BenchmarkHelper provides utilities for benchmarking operations.
type BenchmarkHelper struct {
	client ldap.Client
	config *TestConfig
}

// NewBenchmarkHelper creates a new benchmark helper.
func NewBenchmarkHelper(b *testing.B) *BenchmarkHelper {
	SkipIfNotAccTest(&testing.T{})

	config := GetTestConfig()
	ldapURLs := []string{}
	if config.LDAPURL != "" {
		ldapURLs = []string{config.LDAPURL}
	}
	ldapConfig := &ldap.ConnectionConfig{
		Domain:         config.Domain,
		LDAPURLs:       ldapURLs,
		Username:       config.Username,
		Password:       config.Password,
		KerberosKeytab: config.Keytab,
		KerberosRealm:  config.Realm,
	}

	client, err := ldap.NewClient(ldapConfig)
	if err != nil {
		b.Fatalf("Failed to create LDAP client: %v", err)
	}

	return &BenchmarkHelper{
		client: client,
		config: config,
	}
}

// Close closes the benchmark helper.
func (h *BenchmarkHelper) Close() error {
	return h.client.Close()
}

// CreateTestGroups creates test groups for benchmarking.
func (h *BenchmarkHelper) CreateTestGroups(ctx context.Context, count int) ([]string, error) {
	groupManager := ldap.NewGroupManager(h.client, h.config.BaseDN)
	groups := make([]string, 0, count)

	for i := range count {
		name := fmt.Sprintf("bench-group-%d", i)
		samName := fmt.Sprintf("BenchGroup%d", i)
		container := fmt.Sprintf("%s,%s", h.config.Container, h.config.BaseDN)

		req := &ldap.CreateGroupRequest{
			Name:           name,
			SAMAccountName: samName,
			Container:      container,
			Description:    "",
			Scope:          ldap.GroupScopeGlobal,
			Category:       ldap.GroupCategorySecurity,
		}

		group, err := groupManager.CreateGroup(ctx, req)
		if err != nil {
			// Cleanup created groups on error
			h.CleanupTestGroups(ctx, groups)
			return nil, fmt.Errorf("failed to create test group %d: %v", i, err)
		}

		groups = append(groups, group.ObjectGUID)
	}

	return groups, nil
}

// CleanupTestGroups removes test groups.
func (h *BenchmarkHelper) CleanupTestGroups(ctx context.Context, groupIDs []string) {
	groupManager := ldap.NewGroupManager(h.client, h.config.BaseDN)

	for _, groupID := range groupIDs {
		if err := groupManager.DeleteGroup(ctx, groupID); err != nil {
			log.Printf("Failed to cleanup benchmark group %s: %v", groupID, err)
		}
	}
}

// Utility functions

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// MockLDAPClient provides a mock LDAP client for unit testing.
type MockLDAPClient struct {
	groups map[string]*ldap.Group
	users  map[string]*ldap.User
	ous    map[string]*ldap.OU
	err    error
}

// NewMockLDAPClient creates a new mock LDAP client.
func NewMockLDAPClient() *MockLDAPClient {
	return &MockLDAPClient{
		groups: make(map[string]*ldap.Group),
		users:  make(map[string]*ldap.User),
		ous:    make(map[string]*ldap.OU),
	}
}

// SetError sets an error to be returned by mock operations.
func (m *MockLDAPClient) SetError(err error) {
	m.err = err
}

// AddMockGroup adds a mock group.
func (m *MockLDAPClient) AddMockGroup(group *ldap.Group) {
	m.groups[group.ObjectGUID] = group
}

// AddMockUser adds a mock user.
func (m *MockLDAPClient) AddMockUser(user *ldap.User) {
	m.users[user.ObjectGUID] = user
}

// AddMockOU adds a mock organizational unit.
func (m *MockLDAPClient) AddMockOU(ou *ldap.OU) {
	m.ous[ou.ObjectGUID] = ou
}

// GetMockGroup retrieves a mock group by ID.
func (m *MockLDAPClient) GetMockGroup(id string) (*ldap.Group, error) {
	if m.err != nil {
		return nil, m.err
	}

	group, exists := m.groups[id]
	if !exists {
		return nil, fmt.Errorf("group not found")
	}

	return group, nil
}

// GetMockUser retrieves a mock user by ID.
func (m *MockLDAPClient) GetMockUser(id string) (*ldap.User, error) {
	if m.err != nil {
		return nil, m.err
	}

	user, exists := m.users[id]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

// GetMockOU retrieves a mock OU by ID.
func (m *MockLDAPClient) GetMockOU(id string) (*ldap.OU, error) {
	if m.err != nil {
		return nil, m.err
	}

	ou, exists := m.ous[id]
	if !exists {
		return nil, fmt.Errorf("OU not found")
	}

	return ou, nil
}
