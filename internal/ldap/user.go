package ldap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// UserAccountControl represents the userAccountControl attribute flags.
// These flags control various account properties and restrictions.
const (
	// User Account Control flags (from Microsoft documentation).
	UACAccountDisabled         int32 = 0x00000002 // Account is disabled
	UACHomeDirRequired         int32 = 0x00000008 // Home directory required
	UACPasswordNotRequired     int32 = 0x00000020 // No password required
	UACPasswordCantChange      int32 = 0x00000040 // User cannot change password
	UACEncryptedTextPwdAllowed int32 = 0x00000080 // Encrypted text password allowed
	UACTempDuplicateAccount    int32 = 0x00000100 // Local user account (temporary)
	UACNormalAccount           int32 = 0x00000200 // Normal user account
	UACInterdomainTrustAccount int32 = 0x00000800 // Interdomain trust account
	UACWorkstationTrustAccount int32 = 0x00001000 // Workstation trust account
	UACServerTrustAccount      int32 = 0x00002000 // Server trust account
	UACPasswordNeverExpires    int32 = 0x00010000 // Password never expires
	UACMNSLogonAccount         int32 = 0x00020000 // MNS logon account
	UACSmartCardRequired       int32 = 0x00040000 // Smart card required for logon
	UACTrustedForDelegation    int32 = 0x00080000 // Account trusted for delegation
	UACNotDelegated            int32 = 0x00100000 // Account not delegated
	UACUseDesKeyOnly           int32 = 0x00200000 // Use DES key only
	UACDontRequirePreauth      int32 = 0x00400000 // Don't require Kerberos preauth
	UACPasswordExpired         int32 = 0x00800000 // Password expired
	UACTrustedToAuthForDeleg   int32 = 0x01000000 // Trusted to authenticate for delegation
)

// UserSearchFilter represents user-friendly filter options for searching users.
type UserSearchFilter struct {
	// Name filters
	NamePrefix   string `json:"namePrefix,omitempty"`   // Users whose common name starts with this string
	NameSuffix   string `json:"nameSuffix,omitempty"`   // Users whose common name ends with this string
	NameContains string `json:"nameContains,omitempty"` // Users whose common name contains this string

	// Organizational filters
	Department string `json:"department,omitempty"` // Department name
	Title      string `json:"title,omitempty"`      // Job title
	Company    string `json:"company,omitempty"`    // Company name (exact match)
	Office     string `json:"office,omitempty"`     // Office location (exact match)
	Manager    string `json:"manager,omitempty"`    // Manager DN, GUID, UPN, or SAM

	// Status filters
	Enabled *bool `json:"enabled,omitempty"` // true=enabled accounts, false=disabled accounts, nil=all

	// Email filters
	HasEmail    *bool  `json:"hasEmail,omitempty"`    // true=users with email, false=users without email, nil=all
	EmailDomain string `json:"emailDomain,omitempty"` // Email domain (e.g., "example.com")

	// Location filter
	Container string `json:"container,omitempty"` // Specific OU to search, empty for base DN

	// Group membership filters (supports nested groups via LDAP_MATCHING_RULE_IN_CHAIN)
	MemberOf    string `json:"memberOf,omitempty"`    // Filter users who are members of specified group (DN)
	NotMemberOf string `json:"notMemberOf,omitempty"` // Filter users who are NOT members of specified group (DN)
}

// User represents an Active Directory user with comprehensive attributes.
type User struct {
	// Core identification
	ObjectGUID        string `json:"objectGUID"`
	DistinguishedName string `json:"distinguishedName"`
	ObjectSid         string `json:"objectSid,omitempty"`

	// Identity attributes
	SAMAccountName    string `json:"sAMAccountName"`        // Pre-Windows 2000 name
	UserPrincipalName string `json:"userPrincipalName"`     // UPN (user@domain.com)
	CommonName        string `json:"commonName"`            // Common name (cn)
	DisplayName       string `json:"displayName"`           // Display name
	GivenName         string `json:"givenName,omitempty"`   // First name
	Surname           string `json:"surname,omitempty"`     // Last name
	Initials          string `json:"initials,omitempty"`    // Middle initials
	Description       string `json:"description,omitempty"` // User description

	// Contact information
	EmailAddress string `json:"emailAddress,omitempty"` // Primary email (mail attribute)
	HomePhone    string `json:"homePhone,omitempty"`    // Home telephone number
	MobilePhone  string `json:"mobilePhone,omitempty"`  // Mobile telephone number
	OfficePhone  string `json:"officePhone,omitempty"`  // Office telephone number
	Fax          string `json:"fax,omitempty"`          // Fax number
	HomePage     string `json:"homePage,omitempty"`     // Web page URL

	// Address information
	StreetAddress string `json:"streetAddress,omitempty"` // Street address
	City          string `json:"city,omitempty"`          // City/locality
	State         string `json:"state,omitempty"`         // State/province
	PostalCode    string `json:"postalCode,omitempty"`    // ZIP/postal code
	Country       string `json:"country,omitempty"`       // Country
	POBox         string `json:"poBox,omitempty"`         // P.O. Box

	// Organizational information
	Title          string `json:"title,omitempty"`          // Job title
	Department     string `json:"department,omitempty"`     // Department
	Company        string `json:"company,omitempty"`        // Company name
	Manager        string `json:"manager,omitempty"`        // Manager DN
	EmployeeID     string `json:"employeeID,omitempty"`     // Employee ID
	EmployeeNumber string `json:"employeeNumber,omitempty"` // Employee number
	Office         string `json:"office,omitempty"`         // Physical office location
	Division       string `json:"division,omitempty"`       // Division
	Organization   string `json:"organization,omitempty"`   // Organization

	// System information
	HomeDirectory string `json:"homeDirectory,omitempty"` // Home directory path
	HomeDrive     string `json:"homeDrive,omitempty"`     // Home drive letter
	ProfilePath   string `json:"profilePath,omitempty"`   // Profile path
	LogonScript   string `json:"logonScript,omitempty"`   // Logon script path

	// Account status and security
	AccountEnabled         bool  `json:"accountEnabled"`         // Account is enabled
	PasswordNeverExpires   bool  `json:"passwordNeverExpires"`   // Password never expires
	PasswordNotRequired    bool  `json:"passwordNotRequired"`    // No password required
	ChangePasswordAtLogon  bool  `json:"changePasswordAtLogon"`  // Must change password at next logon
	CannotChangePassword   bool  `json:"cannotChangePassword"`   // Cannot change password
	SmartCardLogonRequired bool  `json:"smartCardLogonRequired"` // Smart card required
	TrustedForDelegation   bool  `json:"trustedForDelegation"`   // Trusted for delegation
	AccountLockedOut       bool  `json:"accountLockedOut"`       // Account is locked out
	UserAccountControl     int32 `json:"userAccountControl"`     // Raw UAC value

	// Group memberships
	MemberOf     []string `json:"memberOf,omitempty"`     // Groups this user is a member of (DNs)
	PrimaryGroup string   `json:"primaryGroup,omitempty"` // Primary group DN

	// Timestamps
	WhenCreated     time.Time  `json:"whenCreated"`               // When user was created
	WhenChanged     time.Time  `json:"whenChanged"`               // When user was last modified
	LastLogon       *time.Time `json:"lastLogon,omitempty"`       // Last logon timestamp
	PasswordLastSet *time.Time `json:"passwordLastSet,omitempty"` // Password last set timestamp
	AccountExpires  *time.Time `json:"accountExpires,omitempty"`  // Account expiration timestamp
}

// UserReader handles read-only Active Directory user operations.
// This provides comprehensive user data retrieval without modification capabilities.
type UserReader struct {
	client      Client
	guidHandler *GUIDHandler
	sidHandler  *SIDHandler
	normalizer  *MemberNormalizer
	baseDN      string
	timeout     time.Duration
}

// NewUserReader creates a new user reader instance.
func NewUserReader(client Client, baseDN string) *UserReader {
	return &UserReader{
		client:      client,
		guidHandler: NewGUIDHandler(),
		sidHandler:  NewSIDHandler(),
		normalizer:  NewMemberNormalizer(client, baseDN),
		baseDN:      baseDN,
		timeout:     30 * time.Second,
	}
}

// SetTimeout sets the LDAP operation timeout.
func (ur *UserReader) SetTimeout(timeout time.Duration) {
	ur.timeout = timeout
	ur.normalizer.SetTimeout(timeout)
}

// GetUser retrieves a user by various identifier types.
// Supports lookup by DN, GUID, SID, UPN, or SAM account name.
func (ur *UserReader) GetUser(ctx context.Context, identifier string) (*User, error) {
	if identifier == "" {
		return nil, fmt.Errorf("user identifier cannot be empty")
	}

	// Detect identifier type and route to appropriate method
	idType := ur.normalizer.DetectIdentifierType(identifier)

	switch idType {
	case IdentifierTypeDN:
		return ur.getUserByDN(ctx, identifier)
	case IdentifierTypeGUID:
		return ur.getUserByGUID(ctx, identifier)
	case IdentifierTypeSID:
		return ur.getUserBySID(ctx, identifier)
	case IdentifierTypeUPN:
		return ur.getUserByUPN(ctx, identifier)
	case IdentifierTypeSAM:
		return ur.getUserBySAM(ctx, identifier)
	default:
		return nil, fmt.Errorf("unable to determine identifier type for: %s", identifier)
	}
}

// GetUserByDN retrieves a user by distinguished name.
func (ur *UserReader) GetUserByDN(ctx context.Context, dn string) (*User, error) {
	if dn == "" {
		return nil, fmt.Errorf("user DN cannot be empty")
	}

	return ur.getUserByDN(ctx, dn)
}

// GetUserByGUID retrieves a user by objectGUID.
func (ur *UserReader) GetUserByGUID(ctx context.Context, guid string) (*User, error) {
	if guid == "" {
		return nil, fmt.Errorf("user GUID cannot be empty")
	}

	// Validate GUID format
	if !ur.guidHandler.IsValidGUID(guid) {
		return nil, fmt.Errorf("invalid GUID format: %s", guid)
	}

	return ur.getUserByGUID(ctx, guid)
}

// GetUserBySID retrieves a user by security identifier (SID).
func (ur *UserReader) GetUserBySID(ctx context.Context, sid string) (*User, error) {
	if sid == "" {
		return nil, fmt.Errorf("user SID cannot be empty")
	}

	return ur.getUserBySID(ctx, sid)
}

// GetUserByUPN retrieves a user by User Principal Name.
func (ur *UserReader) GetUserByUPN(ctx context.Context, upn string) (*User, error) {
	if upn == "" {
		return nil, fmt.Errorf("user UPN cannot be empty")
	}

	return ur.getUserByUPN(ctx, upn)
}

// GetUserBySAM retrieves a user by SAM account name.
func (ur *UserReader) GetUserBySAM(ctx context.Context, samAccountName string) (*User, error) {
	if samAccountName == "" {
		return nil, fmt.Errorf("SAM account name cannot be empty")
	}

	return ur.getUserBySAM(ctx, samAccountName)
}

// SearchUsers searches for users using LDAP filter with pagination support.
func (ur *UserReader) SearchUsers(ctx context.Context, filter string, attributes []string) ([]*User, error) {
	if filter == "" {
		filter = "(&(objectClass=user)(!(objectClass=computer)))"
	} else {
		// Ensure we're only searching for user objects (not computers)
		filter = fmt.Sprintf("(&(objectClass=user)(!(objectClass=computer))%s)", filter)
	}

	if len(attributes) == 0 {
		attributes = ur.getAllUserAttributes()
	}

	searchReq := &SearchRequest{
		BaseDN:     ur.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: attributes,
		TimeLimit:  ur.timeout,
	}

	result, err := ur.client.SearchWithPaging(ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_users", err)
	}

	users := make([]*User, 0, len(result.Entries))
	for _, entry := range result.Entries {
		user, err := ur.entryToUser(entry)
		if err != nil {
			// Log error but continue with other entries
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

// SearchUsersWithFilter searches for users using user-friendly filter criteria.
func (ur *UserReader) SearchUsersWithFilter(ctx context.Context, filter *UserSearchFilter) ([]*User, error) {
	if filter == nil {
		return ur.SearchUsers(ctx, "", nil)
	}

	// Validate filter values
	if err := ur.validateSearchFilter(filter); err != nil {
		return nil, WrapError("validate_search_filter", err)
	}

	// Convert user-friendly filter to LDAP filter
	ldapFilter, err := ur.buildLDAPFilter(filter)
	if err != nil {
		return nil, WrapError("build_ldap_filter", err)
	}

	// Determine search base DN (container or baseDN)
	searchBaseDN := ur.baseDN
	if filter.Container != "" {
		searchBaseDN = filter.Container
	}

	// Perform search using existing SearchUsers method with custom base DN
	return ur.searchUsersInContainer(ctx, searchBaseDN, ldapFilter, nil)
}

// getUserByDN is the internal implementation for DN-based user retrieval.
func (ur *UserReader) getUserByDN(ctx context.Context, dn string) (*User, error) {
	searchReq := &SearchRequest{
		BaseDN:     dn,
		Scope:      ScopeBaseObject,
		Filter:     "(&(objectClass=user)(!(objectClass=computer)))",
		Attributes: ur.getAllUserAttributes(),
		SizeLimit:  1,
		TimeLimit:  ur.timeout,
	}

	result, err := ur.client.Search(ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_user_by_dn", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewLDAPError("get_user_by_dn", fmt.Errorf("user not found at DN: %s", dn))
	}

	user, err := ur.entryToUser(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_user_entry", err)
	}

	return user, nil
}

// getUserByGUID is the internal implementation for GUID-based user retrieval.
func (ur *UserReader) getUserByGUID(ctx context.Context, guid string) (*User, error) {
	// Create GUID search request
	searchReq, err := ur.guidHandler.GenerateGUIDSearchRequest(ur.baseDN, guid)
	if err != nil {
		return nil, WrapError("generate_guid_search", err)
	}

	// Expand filter to ensure it's a user object
	searchReq.Filter = fmt.Sprintf("(&%s(objectClass=user)(!(objectClass=computer)))", searchReq.Filter)
	searchReq.Attributes = ur.getAllUserAttributes()
	searchReq.TimeLimit = ur.timeout

	result, err := ur.client.Search(ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_user_by_guid", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewLDAPError("get_user_by_guid", fmt.Errorf("user with GUID %s not found", guid))
	}

	user, err := ur.entryToUser(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_user_entry", err)
	}

	return user, nil
}

// getUserBySID is the internal implementation for SID-based user retrieval.
func (ur *UserReader) getUserBySID(ctx context.Context, sid string) (*User, error) {
	searchReq := &SearchRequest{
		BaseDN:     ur.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     fmt.Sprintf("(&(objectClass=user)(!(objectClass=computer))(objectSid=%s))", ldap.EscapeFilter(sid)),
		Attributes: ur.getAllUserAttributes(),
		SizeLimit:  1,
		TimeLimit:  ur.timeout,
	}

	result, err := ur.client.Search(ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_user_by_sid", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewLDAPError("get_user_by_sid", fmt.Errorf("user with SID %s not found", sid))
	}

	user, err := ur.entryToUser(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_user_entry", err)
	}

	return user, nil
}

// getUserByUPN is the internal implementation for UPN-based user retrieval.
func (ur *UserReader) getUserByUPN(ctx context.Context, upn string) (*User, error) {
	searchReq := &SearchRequest{
		BaseDN:     ur.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     fmt.Sprintf("(&(objectClass=user)(!(objectClass=computer))(userPrincipalName=%s))", ldap.EscapeFilter(upn)),
		Attributes: ur.getAllUserAttributes(),
		SizeLimit:  1,
		TimeLimit:  ur.timeout,
	}

	result, err := ur.client.Search(ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_user_by_upn", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewLDAPError("get_user_by_upn", fmt.Errorf("user with UPN %s not found", upn))
	}

	user, err := ur.entryToUser(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_user_entry", err)
	}

	return user, nil
}

// getUserBySAM is the internal implementation for SAM-based user retrieval.
func (ur *UserReader) getUserBySAM(ctx context.Context, samAccountName string) (*User, error) {
	// Handle DOMAIN\username format
	if strings.Contains(samAccountName, "\\") {
		parts := strings.SplitN(samAccountName, "\\", 2)
		if len(parts) == 2 {
			samAccountName = parts[1] // Use only the username part
		}
	}

	searchReq := &SearchRequest{
		BaseDN:     ur.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     fmt.Sprintf("(&(objectClass=user)(!(objectClass=computer))(sAMAccountName=%s))", ldap.EscapeFilter(samAccountName)),
		Attributes: ur.getAllUserAttributes(),
		SizeLimit:  1,
		TimeLimit:  ur.timeout,
	}

	result, err := ur.client.Search(ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_user_by_sam", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewLDAPError("get_user_by_sam", fmt.Errorf("user with SAM account name %s not found", samAccountName))
	}

	user, err := ur.entryToUser(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_user_entry", err)
	}

	return user, nil
}

// searchUsersInContainer searches for users in a specific container using LDAP filter.
func (ur *UserReader) searchUsersInContainer(ctx context.Context, baseDN, filter string, attributes []string) ([]*User, error) {
	if filter == "" {
		filter = "(&(objectClass=user)(!(objectClass=computer)))"
	} else {
		// Ensure we're only searching for user objects (not computers)
		filter = fmt.Sprintf("(&(objectClass=user)(!(objectClass=computer))%s)", filter)
	}

	if len(attributes) == 0 {
		attributes = ur.getAllUserAttributes()
	}

	searchReq := &SearchRequest{
		BaseDN:     baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: attributes,
		TimeLimit:  ur.timeout,
	}

	result, err := ur.client.SearchWithPaging(ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_users_in_container", err)
	}

	users := make([]*User, 0, len(result.Entries))
	for _, entry := range result.Entries {
		user, err := ur.entryToUser(entry)
		if err != nil {
			// Log error but continue with other entries
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

// entryToUser converts an LDAP entry to a User struct.
func (ur *UserReader) entryToUser(entry *ldap.Entry) (*User, error) {
	if entry == nil {
		return nil, fmt.Errorf("LDAP entry cannot be nil")
	}

	user := &User{}

	// Extract GUID
	guid, err := ur.guidHandler.ExtractGUID(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to extract GUID: %w", err)
	}
	user.ObjectGUID = guid

	// Core identification
	user.DistinguishedName = entry.DN
	user.ObjectSid = ur.sidHandler.ExtractSIDSafe(entry)
	user.SAMAccountName = entry.GetAttributeValue("sAMAccountName")
	user.UserPrincipalName = entry.GetAttributeValue("userPrincipalName")
	user.CommonName = entry.GetAttributeValue("cn")

	// Personal information
	user.DisplayName = entry.GetAttributeValue("displayName")
	user.GivenName = entry.GetAttributeValue("givenName")
	user.Surname = entry.GetAttributeValue("sn")
	user.Initials = entry.GetAttributeValue("initials")
	user.Description = entry.GetAttributeValue("description")

	// Contact information
	user.EmailAddress = entry.GetAttributeValue("mail")
	user.HomePhone = entry.GetAttributeValue("homePhone")
	user.MobilePhone = entry.GetAttributeValue("mobile")
	user.OfficePhone = entry.GetAttributeValue("telephoneNumber")
	user.Fax = entry.GetAttributeValue("facsimileTelephoneNumber")
	user.HomePage = entry.GetAttributeValue("wWWHomePage")

	// Address information
	user.StreetAddress = entry.GetAttributeValue("streetAddress")
	user.City = entry.GetAttributeValue("l")
	user.State = entry.GetAttributeValue("st")
	user.PostalCode = entry.GetAttributeValue("postalCode")
	user.Country = entry.GetAttributeValue("co")
	user.POBox = entry.GetAttributeValue("postOfficeBox")

	// Organizational information
	user.Title = entry.GetAttributeValue("title")
	user.Department = entry.GetAttributeValue("department")
	user.Company = entry.GetAttributeValue("company")
	user.Manager = entry.GetAttributeValue("manager")
	user.EmployeeID = entry.GetAttributeValue("employeeID")
	user.EmployeeNumber = entry.GetAttributeValue("employeeNumber")
	user.Office = entry.GetAttributeValue("physicalDeliveryOfficeName")
	user.Division = entry.GetAttributeValue("division")
	user.Organization = entry.GetAttributeValue("o")

	// System information
	user.HomeDirectory = entry.GetAttributeValue("homeDirectory")
	user.HomeDrive = entry.GetAttributeValue("homeDrive")
	user.ProfilePath = entry.GetAttributeValue("profilePath")
	user.LogonScript = entry.GetAttributeValue("scriptPath")

	// Parse userAccountControl flags
	uacStr := entry.GetAttributeValue("userAccountControl")
	if uacStr != "" {
		if uacValue, err := strconv.ParseInt(uacStr, 10, 32); err == nil {
			user.UserAccountControl = int32(uacValue)
			ur.parseUserAccountControl(user, int32(uacValue))
		}
	}

	// Group memberships
	user.MemberOf = entry.GetAttributeValues("memberOf")

	// Parse primary group (primaryGroupID + domain SID)
	if primaryGroupID := entry.GetAttributeValue("primaryGroupID"); primaryGroupID != "" && user.ObjectSid != "" {
		if pgid, err := strconv.ParseInt(primaryGroupID, 10, 32); err == nil {
			// Extract domain SID from object SID and append primary group ID
			sidParts := strings.Split(user.ObjectSid, "-")
			if len(sidParts) >= 4 {
				domainSID := strings.Join(sidParts[:len(sidParts)-1], "-")
				primaryGroupSID := fmt.Sprintf("%s-%d", domainSID, pgid)
				// Note: We could resolve this SID to DN, but that requires an additional search
				// For now, we'll store the SID and let the caller resolve it if needed
				user.PrimaryGroup = primaryGroupSID
			}
		}
	}

	// Parse timestamps
	if whenCreated := entry.GetAttributeValue("whenCreated"); whenCreated != "" {
		if t, err := time.Parse("20060102150405.0Z", whenCreated); err == nil {
			user.WhenCreated = t
		}
	}

	if whenChanged := entry.GetAttributeValue("whenChanged"); whenChanged != "" {
		if t, err := time.Parse("20060102150405.0Z", whenChanged); err == nil {
			user.WhenChanged = t
		}
	}

	// Parse optional timestamps (may not be present)
	if lastLogon := entry.GetAttributeValue("lastLogon"); lastLogon != "" {
		if t, err := ur.parseADTimestamp(lastLogon); err == nil {
			user.LastLogon = &t
		}
	}

	if pwdLastSet := entry.GetAttributeValue("pwdLastSet"); pwdLastSet != "" {
		if t, err := ur.parseADTimestamp(pwdLastSet); err == nil {
			user.PasswordLastSet = &t
		}
	}

	if accountExpires := entry.GetAttributeValue("accountExpires"); accountExpires != "" && accountExpires != "0" && accountExpires != "9223372036854775807" {
		if t, err := ur.parseADTimestamp(accountExpires); err == nil {
			user.AccountExpires = &t
		}
	}

	return user, nil
}

// parseUserAccountControl extracts boolean flags from the userAccountControl value.
func (ur *UserReader) parseUserAccountControl(user *User, uac int32) {
	user.AccountEnabled = (uac & UACAccountDisabled) == 0
	user.PasswordNeverExpires = (uac & UACPasswordNeverExpires) != 0
	user.PasswordNotRequired = (uac & UACPasswordNotRequired) != 0
	user.ChangePasswordAtLogon = (uac & UACPasswordExpired) != 0
	user.CannotChangePassword = (uac & UACPasswordCantChange) != 0
	user.SmartCardLogonRequired = (uac & UACSmartCardRequired) != 0
	user.TrustedForDelegation = (uac & UACTrustedForDelegation) != 0
	// Note: Account lockout is typically determined by lockoutTime attribute, not UAC
	user.AccountLockedOut = false // This would require checking lockoutTime attribute
}

// parseADTimestamp parses Active Directory timestamp format (100-nanosecond intervals since Jan 1, 1601).
func (ur *UserReader) parseADTimestamp(timestamp string) (time.Time, error) {
	if timestamp == "" || timestamp == "0" {
		return time.Time{}, fmt.Errorf("empty or zero timestamp")
	}

	// Parse as int64
	ticks, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	// AD timestamps are 100-nanosecond intervals since January 1, 1601 (UTC)
	// Convert to Unix timestamp (nanoseconds since January 1, 1970)
	const adEpoch = 116444736000000000 // 100-nanosecond intervals between 1601 and 1970

	if ticks <= adEpoch {
		return time.Time{}, fmt.Errorf("timestamp before Unix epoch")
	}

	unixNanos := (ticks - adEpoch) * 100
	return time.Unix(0, unixNanos).UTC(), nil
}

// getAllUserAttributes returns the complete list of user attributes to retrieve.
func (ur *UserReader) getAllUserAttributes() []string {
	return []string{
		// Core identification
		"objectGUID", "distinguishedName", "objectSid",
		"sAMAccountName", "userPrincipalName", "cn",

		// Personal information
		"displayName", "givenName", "sn", "initials", "description",

		// Contact information
		"mail", "homePhone", "mobile", "telephoneNumber",
		"facsimileTelephoneNumber", "wWWHomePage",

		// Address information
		"streetAddress", "l", "st", "postalCode", "co", "postOfficeBox",

		// Organizational information
		"title", "department", "company", "manager",
		"employeeID", "employeeNumber", "physicalDeliveryOfficeName",
		"division", "o",

		// System information
		"homeDirectory", "homeDrive", "profilePath", "scriptPath",

		// Account control and membership
		"userAccountControl", "memberOf", "primaryGroupID",

		// Timestamps
		"whenCreated", "whenChanged", "lastLogon", "pwdLastSet", "accountExpires",
	}
}

// validateSearchFilter validates the user-provided search filter.
func (ur *UserReader) validateSearchFilter(filter *UserSearchFilter) error {
	if filter == nil {
		return nil
	}

	// Validate container DN format if provided
	if filter.Container != "" {
		if _, err := ldap.ParseDN(filter.Container); err != nil {
			return fmt.Errorf("invalid container DN '%s': %w", filter.Container, err)
		}
	}

	// Validate email domain format if provided
	if filter.EmailDomain != "" {
		if !strings.Contains(filter.EmailDomain, ".") {
			return fmt.Errorf("invalid email domain format: %s", filter.EmailDomain)
		}
	}

	return nil
}

// buildLDAPFilter converts a user-friendly filter to an LDAP filter string.
func (ur *UserReader) buildLDAPFilter(filter *UserSearchFilter) (string, error) {
	if filter == nil {
		return "", nil
	}

	var filterParts []string

	// Name filters
	if filter.NamePrefix != "" {
		filterParts = append(filterParts, fmt.Sprintf("(cn=%s*)", ldap.EscapeFilter(filter.NamePrefix)))
	}
	if filter.NameSuffix != "" {
		filterParts = append(filterParts, fmt.Sprintf("(cn=*%s)", ldap.EscapeFilter(filter.NameSuffix)))
	}
	if filter.NameContains != "" {
		filterParts = append(filterParts, fmt.Sprintf("(cn=*%s*)", ldap.EscapeFilter(filter.NameContains)))
	}

	// Organizational filters
	if filter.Department != "" {
		filterParts = append(filterParts, fmt.Sprintf("(department=%s)", ldap.EscapeFilter(filter.Department)))
	}
	if filter.Title != "" {
		filterParts = append(filterParts, fmt.Sprintf("(title=%s)", ldap.EscapeFilter(filter.Title)))
	}
	if filter.Manager != "" {
		// Normalize manager identifier to DN
		managerDN, err := ur.normalizer.NormalizeToDN(filter.Manager)
		if err != nil {
			return "", fmt.Errorf("failed to normalize manager identifier: %w", err)
		}
		filterParts = append(filterParts, fmt.Sprintf("(manager=%s)", ldap.EscapeFilter(managerDN)))
	}
	if filter.Company != "" {
		filterParts = append(filterParts, fmt.Sprintf("(company=%s)", ldap.EscapeFilter(filter.Company)))
	}
	if filter.Office != "" {
		filterParts = append(filterParts, fmt.Sprintf("(physicalDeliveryOfficeName=%s)", ldap.EscapeFilter(filter.Office)))
	}

	// Status filters
	if filter.Enabled != nil {
		if *filter.Enabled {
			// Enabled accounts (UAC bit 1 is NOT set)
			filterParts = append(filterParts, "(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
		} else {
			// Disabled accounts (UAC bit 1 is set)
			filterParts = append(filterParts, "(userAccountControl:1.2.840.113556.1.4.803:=2)")
		}
	}

	// Email filters
	if filter.HasEmail != nil {
		if *filter.HasEmail {
			// Users with email addresses
			filterParts = append(filterParts, "(mail=*)")
		} else {
			// Users without email addresses
			filterParts = append(filterParts, "(!(mail=*))")
		}
	}
	if filter.EmailDomain != "" {
		// Users with email addresses in specific domain
		filterParts = append(filterParts, fmt.Sprintf("(mail=*@%s)", ldap.EscapeFilter(filter.EmailDomain)))
	}

	// Group membership filters (supports nested groups via LDAP_MATCHING_RULE_IN_CHAIN)
	if filter.MemberOf != "" {
		// Users who are members of the specified group (including nested)
		filterParts = append(filterParts, fmt.Sprintf("(memberOf:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(filter.MemberOf)))
	}
	if filter.NotMemberOf != "" {
		// Users who are NOT members of the specified group (including nested)
		filterParts = append(filterParts, fmt.Sprintf("(!(memberOf:1.2.840.113556.1.4.1941:=%s))", ldap.EscapeFilter(filter.NotMemberOf)))
	}

	// Combine all filter parts
	if len(filterParts) == 0 {
		return "", nil
	} else if len(filterParts) == 1 {
		return filterParts[0], nil
	} else {
		return fmt.Sprintf("(&%s)", strings.Join(filterParts, "")), nil
	}
}

// GetUserStats returns statistics about users in the directory.
func (ur *UserReader) GetUserStats(ctx context.Context) (map[string]int, error) {
	stats := make(map[string]int)

	// Count total users
	allUsers, err := ur.SearchUsers(ctx, "", []string{"userAccountControl"})
	if err != nil {
		return nil, WrapError("get_user_stats", err)
	}

	stats["total"] = len(allUsers)

	// Count by status
	enabledCount := 0
	disabledCount := 0
	for _, user := range allUsers {
		if user.AccountEnabled {
			enabledCount++
		} else {
			disabledCount++
		}
	}
	stats["enabled"] = enabledCount
	stats["disabled"] = disabledCount

	return stats, nil
}
