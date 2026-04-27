package ldap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// UserAccountControl represents the userAccountControl attribute flags.
// These flags control various account properties and restrictions.
const (
	// User Account Control flags (from Microsoft documentation).
	UACAccountDisabled         int32 = 0x00000002 // Account is disabled
	UACHomeDirRequired         int32 = 0x00000008 // Home directory required
	UACPasswordNotRequired     int32 = 0x00000020 // No password required
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
	Department       string `json:"department,omitempty"`       // Department name
	NegateDepartment bool   `json:"negateDepartment,omitempty"` // Whether to negate the Department filter
	Title            string `json:"title,omitempty"`            // Job title
	NegateTitle      bool   `json:"negateTitle,omitempty"`      // Whether to negate the Title filter
	Company          string `json:"company,omitempty"`          // Company name (exact match)
	NegateCompany    bool   `json:"negateCompany,omitempty"`    // Whether to negate the Company filter
	Office           string `json:"office,omitempty"`           // Office location (exact match)
	NegateOffice     bool   `json:"negateOffice,omitempty"`     // Whether to negate the Office filter
	Manager          string `json:"manager,omitempty"`          // Manager DN, GUID, UPN, or SAM

	// Status filters
	Enabled *bool `json:"enabled,omitempty"` // true=enabled accounts, false=disabled accounts, nil=all

	// Email filters
	HasEmail    *bool  `json:"hasEmail,omitempty"`    // true=users with email, false=users without email, nil=all
	EmailDomain string `json:"emailDomain,omitempty"` // Email domain (e.g., "example.com")

	// Location filter
	Container string `json:"container,omitempty"` // Specific OU to search, empty for base DN

	// Group membership filters (supports nested groups via LDAP_MATCHING_RULE_IN_CHAIN)
	MemberOf       string `json:"memberOf,omitempty"`       // Filter users who are members of specified group (DN)
	NegateMemberOf bool   `json:"negateMemberOf,omitempty"` // Whether to negate the MemberOf filter

	// LDAP search scope. A nil pointer is treated as ScopeWholeSubtree by
	// SearchUsersWithFilter to preserve the historical default for callers
	// that don't explicitly set this field. A pointer is required because
	// the zero value of SearchScope (ScopeBaseObject) is itself a legal and
	// distinct scope.
	SearchScope *SearchScope `json:"searchScope,omitempty"`

	// Attributes restricts the LDAP attributes returned for each user. Empty
	// means "use the full user attribute list". A narrow list speeds up bulk
	// searches (data sources) by trimming wire payload and skipping per-user
	// derivations like primary-group SID resolution.
	Attributes []string `json:"-"`
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

// CreateUserRequest represents a request to create a new user.
type CreateUserRequest struct {
	// Required fields
	Name              string // cn - Common Name
	UserPrincipalName string // userPrincipalName (UPN - user@domain.com)
	SAMAccountName    string // sAMAccountName (pre-Windows 2000 name, max 20 chars)
	Container         string // Parent container DN

	// Password (write-only, optional)
	InitialPassword string

	// Security flags (pointers for optional with defaults)
	Enabled                *bool // Default: true
	PasswordNeverExpires   *bool // Default: false
	SmartCardLogonRequired *bool // Default: false
	TrustedForDelegation   *bool // Default: false
	ChangePasswordAtLogon  *bool // Default: false

	// Personal information
	DisplayName string // displayName
	Description string // description
	GivenName   string // givenName (first name)
	Surname     string // sn (last name)
	Initials    string // initials (middle initials)

	// Contact information
	EmailAddress string // mail
	HomePhone    string // homePhone
	MobilePhone  string // mobile
	OfficePhone  string // telephoneNumber
	Fax          string // facsimileTelephoneNumber
	HomePage     string // wWWHomePage

	// Address information
	StreetAddress string // streetAddress
	City          string // l (locality)
	State         string // st (state/province)
	PostalCode    string // postalCode
	Country       string // co (country)
	POBox         string // postOfficeBox

	// Organizational information
	Title          string // title
	Department     string // department
	Company        string // company
	Manager        string // manager (DN)
	EmployeeID     string // employeeID
	EmployeeNumber string // employeeNumber
	Office         string // physicalDeliveryOfficeName
	Division       string // division
	Organization   string // o (organization)

	// System information
	HomeDirectory string // homeDirectory
	HomeDrive     string // homeDrive
	ProfilePath   string // profilePath
	LogonScript   string // scriptPath
}

// UpdateUserRequest represents a request to update an existing user.
// All fields are pointers - nil means no change, empty string means clear.
type UpdateUserRequest struct {
	// Name change (requires ModifyDN)
	Name *string // cn - triggers rename

	// Container change (requires ModifyDN)
	Container *string // triggers move

	// Account name changes
	UserPrincipalName *string // userPrincipalName
	SAMAccountName    *string // sAMAccountName

	// Security flags
	Enabled                *bool
	PasswordNeverExpires   *bool
	SmartCardLogonRequired *bool
	TrustedForDelegation   *bool
	ChangePasswordAtLogon  *bool

	// Personal information
	DisplayName *string
	Description *string
	GivenName   *string
	Surname     *string
	Initials    *string

	// Contact information
	EmailAddress *string
	HomePhone    *string
	MobilePhone  *string
	OfficePhone  *string
	Fax          *string
	HomePage     *string

	// Address information
	StreetAddress *string
	City          *string
	State         *string
	PostalCode    *string
	Country       *string
	POBox         *string

	// Organizational information
	Title          *string
	Department     *string
	Company        *string
	Manager        *string // DN
	EmployeeID     *string
	EmployeeNumber *string
	Office         *string
	Division       *string
	Organization   *string

	// System information
	HomeDirectory *string
	HomeDrive     *string
	ProfilePath   *string
	LogonScript   *string
}

// UserManager handles Active Directory user operations (both read and write).
type UserManager struct {
	ctx          context.Context
	client       Client
	guidHandler  *GUIDHandler
	sidHandler   *SIDHandler
	normalizer   *MemberNormalizer
	baseDN       string
	timeout      time.Duration
	cacheManager *CacheManager
}

// NewUserManager creates a new user manager instance.
func NewUserManager(ctx context.Context, client Client, baseDN string, cacheManager *CacheManager) *UserManager {
	return &UserManager{
		ctx:          ctx,
		client:       client,
		guidHandler:  NewGUIDHandler(),
		sidHandler:   NewSIDHandler(),
		normalizer:   NewMemberNormalizer(client, baseDN, cacheManager),
		baseDN:       baseDN,
		timeout:      30 * time.Second,
		cacheManager: cacheManager,
	}
}

// SetTimeout sets the LDAP operation timeout.
func (um *UserManager) SetTimeout(timeout time.Duration) {
	um.timeout = timeout
	um.normalizer.SetTimeout(timeout)
}

// -----------------------------------------------------------------------------
// Read Operations
// -----------------------------------------------------------------------------

// GetUser retrieves a user by various identifier types.
// Supports lookup by DN, GUID, SID, UPN, or SAM account name.
func (um *UserManager) GetUser(identifier string) (*User, error) {
	if identifier == "" {
		return nil, fmt.Errorf("user identifier cannot be empty")
	}

	// Detect identifier type and route to appropriate method
	idType := um.normalizer.DetectIdentifierType(identifier)

	switch idType {
	case IdentifierTypeDN:
		return um.getUserByDN(identifier)
	case IdentifierTypeGUID:
		return um.getUserByGUID(identifier)
	case IdentifierTypeSID:
		return um.getUserBySID(identifier)
	case IdentifierTypeUPN:
		return um.getUserByUPN(identifier)
	case IdentifierTypeSAM:
		return um.getUserBySAM(identifier)
	default:
		return nil, fmt.Errorf("unable to determine identifier type for: %s", identifier)
	}
}

// GetUserByDN retrieves a user by distinguished name.
func (um *UserManager) GetUserByDN(dn string) (*User, error) {
	if dn == "" {
		return nil, fmt.Errorf("user DN cannot be empty")
	}

	return um.getUserByDN(dn)
}

// GetUserByGUID retrieves a user by objectGUID.
func (um *UserManager) GetUserByGUID(guid string) (*User, error) {
	if guid == "" {
		return nil, fmt.Errorf("user GUID cannot be empty")
	}

	// Validate GUID format
	if !um.guidHandler.IsValidGUID(guid) {
		return nil, fmt.Errorf("invalid GUID format: %s", guid)
	}

	return um.getUserByGUID(guid)
}

// GetUserBySID retrieves a user by security identifier (SID).
func (um *UserManager) GetUserBySID(sid string) (*User, error) {
	if sid == "" {
		return nil, fmt.Errorf("user SID cannot be empty")
	}

	return um.getUserBySID(sid)
}

// GetUserByUPN retrieves a user by User Principal Name.
func (um *UserManager) GetUserByUPN(upn string) (*User, error) {
	if upn == "" {
		return nil, fmt.Errorf("user UPN cannot be empty")
	}

	return um.getUserByUPN(upn)
}

// GetUserBySAM retrieves a user by SAM account name.
func (um *UserManager) GetUserBySAM(samAccountName string) (*User, error) {
	if samAccountName == "" {
		return nil, fmt.Errorf("SAM account name cannot be empty")
	}

	return um.getUserBySAM(samAccountName)
}

// SearchUsers searches for users using LDAP filter with pagination support.
func (um *UserManager) SearchUsers(filter string, attributes []string) ([]*User, error) {
	if filter == "" {
		filter = "(&(objectClass=user)(!(objectClass=computer)))"
	} else {
		// Ensure we're only searching for user objects (not computers)
		filter = fmt.Sprintf("(&(objectClass=user)(!(objectClass=computer))%s)", filter)
	}

	if len(attributes) == 0 {
		attributes = um.getAllUserAttributes()
	}

	searchReq := &SearchRequest{
		BaseDN:     um.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     filter,
		Attributes: attributes,
		TimeLimit:  um.timeout,
	}

	result, err := um.client.SearchWithPaging(um.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_users", err)
	}

	users := make([]*User, 0, len(result.Entries))
	for i, entry := range result.Entries {
		user, err := um.entryToUser(entry)
		if err != nil {
			tflog.SubsystemWarn(um.ctx, "ldap", "Failed to convert LDAP entry to user, skipping", map[string]any{
				"operation":   "entry_to_user",
				"entry_index": i,
				"entry_dn":    entry.DN,
				"error":       err.Error(),
			})
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

// SearchUsersWithFilter searches for users using user-friendly filter criteria.
func (um *UserManager) SearchUsersWithFilter(filter *UserSearchFilter) ([]*User, error) {
	if filter == nil {
		return um.SearchUsers("", nil)
	}

	// Validate filter values
	if err := um.validateSearchFilter(filter); err != nil {
		return nil, WrapError("validate_search_filter", err)
	}

	// Convert user-friendly filter to LDAP filter
	ldapFilter, err := um.buildLDAPFilter(filter)
	if err != nil {
		return nil, WrapError("build_ldap_filter", err)
	}

	// Determine search base DN (container or baseDN)
	searchBaseDN := um.baseDN
	if filter.Container != "" {
		searchBaseDN = filter.Container
	}

	// Resolve the LDAP search scope: preserve the historical subtree behaviour
	// when the caller has not explicitly set a scope (nil pointer). All
	// existing (pre-wiring) callers rely on subtree semantics.
	searchScope := ScopeWholeSubtree
	if filter.SearchScope != nil {
		searchScope = *filter.SearchScope
	}

	return um.searchUsersInContainer(searchBaseDN, ldapFilter, filter.Attributes, searchScope)
}

// -----------------------------------------------------------------------------
// Write Operations
// -----------------------------------------------------------------------------

// ValidateCreateUserRequest validates a user creation request.
func (um *UserManager) ValidateCreateUserRequest(req *CreateUserRequest) error {
	if req == nil {
		return fmt.Errorf("create user request cannot be nil")
	}

	if req.Name == "" {
		return fmt.Errorf("user name (cn) is required")
	}

	if req.UserPrincipalName == "" {
		return fmt.Errorf("user principal name (UPN) is required")
	}

	if req.SAMAccountName == "" {
		return fmt.Errorf("SAM account name is required")
	}

	// SAM account name max length for users is 20 characters
	if len(req.SAMAccountName) > 20 {
		return fmt.Errorf("SAM account name cannot exceed 20 characters for users: %s (%d chars)", req.SAMAccountName, len(req.SAMAccountName))
	}

	if req.Container == "" {
		return fmt.Errorf("container DN is required")
	}

	// Validate UPN format
	if !strings.Contains(req.UserPrincipalName, "@") {
		return fmt.Errorf("user principal name must be in UPN format (user@domain): %s", req.UserPrincipalName)
	}

	// Validate SAM account name format per Microsoft documentation.
	// Prohibited: " / \ [ ] : ; | = , + * ? < > @, plus whitespace.
	if strings.ContainsAny(req.SAMAccountName, " \t\n\r\"@/\\[]:;|=,+*?<>") {
		return fmt.Errorf("SAM account name contains invalid characters: %s", req.SAMAccountName)
	}

	// Validate manager DN format if provided
	if req.Manager != "" {
		if _, err := ldap.ParseDN(req.Manager); err != nil {
			return fmt.Errorf("invalid manager DN '%s': %w", req.Manager, err)
		}
	}

	return nil
}

// CreateUser creates a new Active Directory user.
func (um *UserManager) CreateUser(req *CreateUserRequest) (*User, error) {
	if err := um.ValidateCreateUserRequest(req); err != nil {
		return nil, WrapError("create_user_validation", err)
	}

	// Build the user DN
	userDN := fmt.Sprintf("CN=%s,%s", ldap.EscapeDN(req.Name), req.Container)

	tflog.SubsystemDebug(um.ctx, "ldap", "Creating user", map[string]any{
		"user_dn":   userDN,
		"name":      req.Name,
		"upn":       req.UserPrincipalName,
		"sam":       req.SAMAccountName,
		"container": req.Container,
	})

	// Calculate initial UAC value
	// Start with account disabled - we'll enable after setting password
	initialUAC := UACNormalAccount | UACAccountDisabled

	// Build attributes for user creation
	attributes := map[string][]string{
		"objectClass":        {"top", "person", "organizationalPerson", "user"},
		"cn":                 {req.Name},
		"sAMAccountName":     {req.SAMAccountName},
		"userPrincipalName":  {req.UserPrincipalName},
		"userAccountControl": {strconv.FormatInt(int64(initialUAC), 10)},
	}

	// Add optional string attributes
	um.addOptionalAttribute(attributes, "displayName", req.DisplayName)
	um.addOptionalAttribute(attributes, "description", req.Description)
	um.addOptionalAttribute(attributes, "givenName", req.GivenName)
	um.addOptionalAttribute(attributes, "sn", req.Surname)
	um.addOptionalAttribute(attributes, "initials", req.Initials)
	um.addOptionalAttribute(attributes, "mail", req.EmailAddress)
	um.addOptionalAttribute(attributes, "homePhone", req.HomePhone)
	um.addOptionalAttribute(attributes, "mobile", req.MobilePhone)
	um.addOptionalAttribute(attributes, "telephoneNumber", req.OfficePhone)
	um.addOptionalAttribute(attributes, "facsimileTelephoneNumber", req.Fax)
	um.addOptionalAttribute(attributes, "wWWHomePage", req.HomePage)
	um.addOptionalAttribute(attributes, "streetAddress", req.StreetAddress)
	um.addOptionalAttribute(attributes, "l", req.City)
	um.addOptionalAttribute(attributes, "st", req.State)
	um.addOptionalAttribute(attributes, "postalCode", req.PostalCode)
	um.addOptionalAttribute(attributes, "co", req.Country)
	um.addOptionalAttribute(attributes, "postOfficeBox", req.POBox)
	um.addOptionalAttribute(attributes, "title", req.Title)
	um.addOptionalAttribute(attributes, "department", req.Department)
	um.addOptionalAttribute(attributes, "company", req.Company)
	um.addOptionalAttribute(attributes, "manager", req.Manager)
	um.addOptionalAttribute(attributes, "employeeID", req.EmployeeID)
	um.addOptionalAttribute(attributes, "employeeNumber", req.EmployeeNumber)
	um.addOptionalAttribute(attributes, "physicalDeliveryOfficeName", req.Office)
	um.addOptionalAttribute(attributes, "division", req.Division)
	um.addOptionalAttribute(attributes, "o", req.Organization)
	um.addOptionalAttribute(attributes, "homeDirectory", req.HomeDirectory)
	um.addOptionalAttribute(attributes, "homeDrive", req.HomeDrive)
	um.addOptionalAttribute(attributes, "profilePath", req.ProfilePath)
	um.addOptionalAttribute(attributes, "scriptPath", req.LogonScript)

	// Create the user
	addReq := &AddRequest{
		DN:         userDN,
		Attributes: attributes,
	}

	if err := um.client.Add(um.ctx, addReq); err != nil {
		return nil, WrapError("create_user", err)
	}

	tflog.SubsystemDebug(um.ctx, "ldap", "User object created, configuring account", map[string]any{
		"user_dn": userDN,
	})

	// Set password if provided (must be done after user creation)
	if req.InitialPassword != "" {
		if err := um.setPasswordByDN(userDN, req.InitialPassword); err != nil {
			// Try to clean up the partially created user
			_ = um.client.Delete(um.ctx, userDN)
			return nil, WrapError("set_initial_password", err)
		}
		tflog.SubsystemDebug(um.ctx, "ldap", "Initial password set", map[string]any{
			"user_dn": userDN,
		})
	}

	// Calculate and apply final UAC flags
	finalUAC := um.calculateUserAccountControl(req)

	// Active Directory requires a password before an account can be enabled.
	// Force the account to stay disabled if no initial password was provided.
	if req.InitialPassword == "" {
		finalUAC |= UACAccountDisabled
	}

	// Apply final UAC flags (enable account if requested, apply other flags)
	modReq := &ModifyRequest{
		DN:                userDN,
		ReplaceAttributes: make(map[string][]string),
	}
	modReq.ReplaceAttributes["userAccountControl"] = []string{strconv.FormatInt(int64(finalUAC), 10)}

	// Handle "change password at logon" via pwdLastSet.
	// AD auto-updates pwdLastSet to the current timestamp when unicodePwd is
	// modified, so the false-with-password case needs no explicit write. The
	// provider-side validator rejects false-without-password configurations,
	// so when ChangePasswordAtLogon is false here, a password has been set
	// earlier in this Create flow and AD has already cleared the must-change flag.
	if req.ChangePasswordAtLogon != nil && *req.ChangePasswordAtLogon {
		modReq.ReplaceAttributes["pwdLastSet"] = []string{"0"}
	}

	if err := um.client.Modify(um.ctx, modReq); err != nil {
		return nil, WrapError("apply_user_flags", err)
	}

	tflog.SubsystemDebug(um.ctx, "ldap", "User flags applied", map[string]any{
		"user_dn":   userDN,
		"final_uac": finalUAC,
	})

	// Retrieve the created user to get its GUID and other computed attributes
	user, err := um.getUserByDN(userDN)
	if err != nil {
		return nil, WrapError("retrieve_created_user", err)
	}

	tflog.SubsystemInfo(um.ctx, "ldap", "User created successfully", map[string]any{
		"user_guid": user.ObjectGUID,
		"user_dn":   user.DistinguishedName,
		"user_upn":  user.UserPrincipalName,
	})

	return user, nil
}

// UpdateUser updates an existing user.
func (um *UserManager) UpdateUser(guid string, req *UpdateUserRequest) (*User, error) {
	if guid == "" {
		return nil, fmt.Errorf("user GUID cannot be empty")
	}

	if req == nil {
		return nil, fmt.Errorf("update user request cannot be nil")
	}

	// Get current user to determine DN and validate changes
	currentUser, err := um.GetUserByGUID(guid)
	if err != nil {
		return nil, WrapError("get_current_user", err)
	}

	tflog.SubsystemDebug(um.ctx, "ldap", "Updating user", map[string]any{
		"user_guid": guid,
		"user_dn":   currentUser.DistinguishedName,
	})

	// Handle name and/or container changes (both require ModifyDN)
	needsRename := req.Name != nil && *req.Name != currentUser.CommonName
	currentContainer, _ := GetDNParent(currentUser.DistinguishedName)
	needsMove := req.Container != nil && !strings.EqualFold(*req.Container, currentContainer)

	if needsRename || needsMove {
		newName := currentUser.CommonName
		if needsRename {
			newName = *req.Name
		}

		newContainer := currentContainer
		if needsMove {
			newContainer = *req.Container
		}

		if err := um.renameAndMoveUser(currentUser, newName, newContainer); err != nil {
			return nil, WrapError("rename_or_move_user", err)
		}

		// Refresh user to get new DN
		currentUser, err = um.GetUserByGUID(guid)
		if err != nil {
			return nil, WrapError("refresh_user_after_move", err)
		}
	}

	// Build modification request for attribute changes
	modReq := &ModifyRequest{
		DN:                currentUser.DistinguishedName,
		ReplaceAttributes: make(map[string][]string),
	}
	hasChanges := false

	// Handle account name changes
	if req.UserPrincipalName != nil && *req.UserPrincipalName != currentUser.UserPrincipalName {
		modReq.ReplaceAttributes["userPrincipalName"] = []string{*req.UserPrincipalName}
		hasChanges = true
	}

	if req.SAMAccountName != nil && *req.SAMAccountName != currentUser.SAMAccountName {
		modReq.ReplaceAttributes["sAMAccountName"] = []string{*req.SAMAccountName}
		hasChanges = true
	}

	// Handle optional string attribute changes
	hasChanges = um.addModifyAttribute(modReq, "displayName", req.DisplayName, currentUser.DisplayName) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "description", req.Description, currentUser.Description) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "givenName", req.GivenName, currentUser.GivenName) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "sn", req.Surname, currentUser.Surname) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "initials", req.Initials, currentUser.Initials) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "mail", req.EmailAddress, currentUser.EmailAddress) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "homePhone", req.HomePhone, currentUser.HomePhone) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "mobile", req.MobilePhone, currentUser.MobilePhone) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "telephoneNumber", req.OfficePhone, currentUser.OfficePhone) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "facsimileTelephoneNumber", req.Fax, currentUser.Fax) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "wWWHomePage", req.HomePage, currentUser.HomePage) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "streetAddress", req.StreetAddress, currentUser.StreetAddress) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "l", req.City, currentUser.City) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "st", req.State, currentUser.State) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "postalCode", req.PostalCode, currentUser.PostalCode) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "co", req.Country, currentUser.Country) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "postOfficeBox", req.POBox, currentUser.POBox) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "title", req.Title, currentUser.Title) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "department", req.Department, currentUser.Department) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "company", req.Company, currentUser.Company) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "manager", req.Manager, currentUser.Manager) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "employeeID", req.EmployeeID, currentUser.EmployeeID) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "employeeNumber", req.EmployeeNumber, currentUser.EmployeeNumber) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "physicalDeliveryOfficeName", req.Office, currentUser.Office) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "division", req.Division, currentUser.Division) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "o", req.Organization, currentUser.Organization) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "homeDirectory", req.HomeDirectory, currentUser.HomeDirectory) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "homeDrive", req.HomeDrive, currentUser.HomeDrive) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "profilePath", req.ProfilePath, currentUser.ProfilePath) || hasChanges
	hasChanges = um.addModifyAttribute(modReq, "scriptPath", req.LogonScript, currentUser.LogonScript) || hasChanges

	// Handle UAC flag changes
	uacChanged, newUAC := um.calculateUACChanges(req, currentUser)
	if uacChanged {
		modReq.ReplaceAttributes["userAccountControl"] = []string{strconv.FormatInt(int64(newUAC), 10)}
		hasChanges = true
	}

	// Handle "change password at logon" separately (uses pwdLastSet)
	if req.ChangePasswordAtLogon != nil {
		if *req.ChangePasswordAtLogon && !currentUser.ChangePasswordAtLogon {
			// Force password change at next logon
			modReq.ReplaceAttributes["pwdLastSet"] = []string{"0"}
			hasChanges = true
		} else if !*req.ChangePasswordAtLogon && currentUser.ChangePasswordAtLogon {
			// Clear "must change password" by setting pwdLastSet to -1 (current time)
			modReq.ReplaceAttributes["pwdLastSet"] = []string{"-1"}
			hasChanges = true
		}
	}

	// Apply modifications if any
	if hasChanges {
		if err := um.client.Modify(um.ctx, modReq); err != nil {
			return nil, WrapError("modify_user", err)
		}
	}

	// Retrieve final updated user
	updatedUser, err := um.GetUserByGUID(guid)
	if err != nil {
		return nil, WrapError("retrieve_updated_user", err)
	}

	tflog.SubsystemInfo(um.ctx, "ldap", "User updated successfully", map[string]any{
		"user_guid": updatedUser.ObjectGUID,
		"user_dn":   updatedUser.DistinguishedName,
	})

	return updatedUser, nil
}

// DeleteUser deletes a user by its objectGUID.
func (um *UserManager) DeleteUser(guid string) error {
	if guid == "" {
		return fmt.Errorf("user GUID cannot be empty")
	}

	dn, err := um.resolveGUIDToDN(guid)
	if err != nil {
		if IsNotFoundError(err) {
			// User already doesn't exist
			return nil
		}
		return WrapError("get_user_for_deletion", err)
	}

	tflog.SubsystemDebug(um.ctx, "ldap", "Deleting user", map[string]any{
		"user_guid": guid,
		"user_dn":   dn,
	})

	if err := um.client.Delete(um.ctx, dn); err != nil {
		return WrapError("delete_user", err)
	}

	tflog.SubsystemInfo(um.ctx, "ldap", "User deleted successfully", map[string]any{
		"user_guid": guid,
	})

	return nil
}

// SetPassword sets the password for a user.
func (um *UserManager) SetPassword(guid string, password string) error {
	if guid == "" {
		return fmt.Errorf("user GUID cannot be empty")
	}

	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	dn, err := um.resolveGUIDToDN(guid)
	if err != nil {
		return WrapError("get_user_for_password", err)
	}

	return um.setPasswordByDN(dn, password)
}

// -----------------------------------------------------------------------------
// Internal Read Helpers
// -----------------------------------------------------------------------------

// getUserByDN is the internal implementation for DN-based user retrieval.
func (um *UserManager) getUserByDN(dn string) (*User, error) {
	searchReq := &SearchRequest{
		BaseDN:     dn,
		Scope:      ScopeBaseObject,
		Filter:     "(&(objectClass=user)(!(objectClass=computer)))",
		Attributes: um.getAllUserAttributes(),
		SizeLimit:  1,
		TimeLimit:  um.timeout,
	}

	result, err := um.client.Search(um.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_user_by_dn", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewNotFoundError("get_user_by_dn", "user not found at DN: %s", dn)
	}

	user, err := um.entryToUser(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_user_entry", err)
	}

	return user, nil
}

// resolveGUIDToDN performs a narrow LDAP search to obtain only the DN of a
// user identified by GUID. Cheaper than GetUserByGUID when callers (delete,
// set-password) only need the DN to issue follow-up operations.
func (um *UserManager) resolveGUIDToDN(guid string) (string, error) {
	searchReq, err := um.guidHandler.GenerateGUIDSearchRequest(um.baseDN, guid)
	if err != nil {
		return "", WrapError("generate_guid_search", err)
	}
	searchReq.Filter = fmt.Sprintf("(&%s(objectClass=user)(!(objectClass=computer)))", searchReq.Filter)
	searchReq.Attributes = []string{"distinguishedName"}
	searchReq.SizeLimit = 1
	searchReq.TimeLimit = um.timeout

	result, err := um.client.Search(um.ctx, searchReq)
	if err != nil {
		return "", WrapError("search_user_by_guid", err)
	}
	if len(result.Entries) == 0 {
		return "", NewNotFoundError("resolve_guid_to_dn", "user with GUID %s not found", guid)
	}
	return result.Entries[0].DN, nil
}

// getUserByGUID is the internal implementation for GUID-based user retrieval.
func (um *UserManager) getUserByGUID(guid string) (*User, error) {
	// Create GUID search request
	searchReq, err := um.guidHandler.GenerateGUIDSearchRequest(um.baseDN, guid)
	if err != nil {
		return nil, WrapError("generate_guid_search", err)
	}

	// Expand filter to ensure it's a user object
	searchReq.Filter = fmt.Sprintf("(&%s(objectClass=user)(!(objectClass=computer)))", searchReq.Filter)
	searchReq.Attributes = um.getAllUserAttributes()
	searchReq.TimeLimit = um.timeout

	result, err := um.client.Search(um.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_user_by_guid", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewNotFoundError("get_user_by_guid", "user with GUID %s not found", guid)
	}

	user, err := um.entryToUser(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_user_entry", err)
	}

	return user, nil
}

// getUserBySID is the internal implementation for SID-based user retrieval.
func (um *UserManager) getUserBySID(sid string) (*User, error) {
	sidFilter, err := um.sidHandler.SIDToSearchFilter(sid)
	if err != nil {
		return nil, WrapError("sid_to_search_filter", err)
	}

	searchReq := &SearchRequest{
		BaseDN:     um.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     fmt.Sprintf("(&(objectClass=user)(!(objectClass=computer))%s)", sidFilter),
		Attributes: um.getAllUserAttributes(),
		SizeLimit:  1,
		TimeLimit:  um.timeout,
	}

	result, err := um.client.Search(um.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_user_by_sid", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewNotFoundError("get_user_by_sid", "user with SID %s not found", sid)
	}

	user, err := um.entryToUser(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_user_entry", err)
	}

	return user, nil
}

// getUserByUPN is the internal implementation for UPN-based user retrieval.
func (um *UserManager) getUserByUPN(upn string) (*User, error) {
	searchReq := &SearchRequest{
		BaseDN:     um.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     fmt.Sprintf("(&(objectClass=user)(!(objectClass=computer))(userPrincipalName=%s))", ldap.EscapeFilter(upn)),
		Attributes: um.getAllUserAttributes(),
		SizeLimit:  1,
		TimeLimit:  um.timeout,
	}

	result, err := um.client.Search(um.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_user_by_upn", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewNotFoundError("get_user_by_upn", "user with UPN %s not found", upn)
	}

	user, err := um.entryToUser(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_user_entry", err)
	}

	return user, nil
}

// getUserBySAM is the internal implementation for SAM-based user retrieval.
func (um *UserManager) getUserBySAM(samAccountName string) (*User, error) {
	// Handle DOMAIN\username format
	if strings.Contains(samAccountName, "\\") {
		parts := strings.SplitN(samAccountName, "\\", 2)
		if len(parts) == 2 {
			samAccountName = parts[1] // Use only the username part
		}
	}

	searchReq := &SearchRequest{
		BaseDN:     um.baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     fmt.Sprintf("(&(objectClass=user)(!(objectClass=computer))(sAMAccountName=%s))", ldap.EscapeFilter(samAccountName)),
		Attributes: um.getAllUserAttributes(),
		SizeLimit:  1,
		TimeLimit:  um.timeout,
	}

	result, err := um.client.Search(um.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_user_by_sam", err)
	}

	if len(result.Entries) == 0 {
		return nil, NewNotFoundError("get_user_by_sam", "user with SAM account name %s not found", samAccountName)
	}

	user, err := um.entryToUser(result.Entries[0])
	if err != nil {
		return nil, WrapError("parse_user_entry", err)
	}

	return user, nil
}

// searchUsersInContainer searches for users in a specific container using LDAP filter.
// The searchScope argument is passed verbatim; callers are responsible for
// defaulting an unset scope before calling this helper.
func (um *UserManager) searchUsersInContainer(baseDN, filter string, attributes []string, searchScope SearchScope) ([]*User, error) {
	if filter == "" {
		filter = "(&(objectClass=user)(!(objectClass=computer)))"
	} else {
		// Ensure we're only searching for user objects (not computers)
		filter = fmt.Sprintf("(&(objectClass=user)(!(objectClass=computer))%s)", filter)
	}

	if len(attributes) == 0 {
		attributes = um.getAllUserAttributes()
	}

	searchReq := &SearchRequest{
		BaseDN:     baseDN,
		Scope:      searchScope,
		Filter:     filter,
		Attributes: attributes,
		TimeLimit:  um.timeout,
	}

	result, err := um.client.SearchWithPaging(um.ctx, searchReq)
	if err != nil {
		return nil, WrapError("search_users_in_container", err)
	}

	users := make([]*User, 0, len(result.Entries))
	for i, entry := range result.Entries {
		user, err := um.entryToUser(entry)
		if err != nil {
			tflog.SubsystemWarn(um.ctx, "ldap", "Failed to convert LDAP entry to user, skipping", map[string]any{
				"operation":   "entry_to_user",
				"entry_index": i,
				"entry_dn":    entry.DN,
				"error":       err.Error(),
			})
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

// entryToUser converts an LDAP entry to a User struct.
func (um *UserManager) entryToUser(entry *ldap.Entry) (*User, error) {
	if entry == nil {
		return nil, fmt.Errorf("LDAP entry cannot be nil")
	}

	user := &User{}

	// Extract GUID
	guid, err := um.guidHandler.ExtractGUID(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to extract GUID: %w", err)
	}
	user.ObjectGUID = guid

	// Core identification
	user.DistinguishedName = entry.DN
	user.ObjectSid = um.sidHandler.ExtractSIDSafe(entry)
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
			um.parseUserAccountControl(user, int32(uacValue))
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
				if dn, err := um.normalizer.ResolveSIDToDN(primaryGroupSID); err == nil {
					user.PrimaryGroup = dn
				} else {
					tflog.SubsystemWarn(um.ctx, "ldap", "Could not resolve primary group SID to DN, using SID", map[string]any{
						"sid":   primaryGroupSID,
						"error": err.Error(),
					})
					user.PrimaryGroup = primaryGroupSID
				}
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
		if t, err := um.parseADTimestamp(lastLogon); err == nil {
			user.LastLogon = &t
		}
	}

	if pwdLastSet := entry.GetAttributeValue("pwdLastSet"); pwdLastSet != "" {
		// ChangePasswordAtLogon is determined by pwdLastSet == 0, not a UAC bit.
		user.ChangePasswordAtLogon = pwdLastSet == "0"
		if t, err := um.parseADTimestamp(pwdLastSet); err == nil {
			user.PasswordLastSet = &t
		}
	}

	if accountExpires := entry.GetAttributeValue("accountExpires"); accountExpires != "" && accountExpires != "0" && accountExpires != "9223372036854775807" {
		if t, err := um.parseADTimestamp(accountExpires); err == nil {
			user.AccountExpires = &t
		}
	}

	// AD sets lockoutTime to a non-zero filetime when the account is locked.
	// Note: AD does not clear lockoutTime on auto-unlock; a non-zero value
	// older than the domain lockoutDuration may represent a stale lock.
	if lockoutTime := entry.GetAttributeValue("lockoutTime"); lockoutTime != "" && lockoutTime != "0" {
		user.AccountLockedOut = true
	}

	return user, nil
}

// parseUserAccountControl extracts boolean flags from the userAccountControl value.
func (um *UserManager) parseUserAccountControl(user *User, uac int32) {
	user.AccountEnabled = (uac & UACAccountDisabled) == 0
	user.PasswordNeverExpires = (uac & UACPasswordNeverExpires) != 0
	user.PasswordNotRequired = (uac & UACPasswordNotRequired) != 0
	user.SmartCardLogonRequired = (uac & UACSmartCardRequired) != 0
	user.TrustedForDelegation = (uac & UACTrustedForDelegation) != 0
}

// parseADTimestamp parses Active Directory timestamp format (100-nanosecond intervals since Jan 1, 1601).
func (um *UserManager) parseADTimestamp(timestamp string) (time.Time, error) {
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

// DataSourceUsersAttributes is the narrow attribute set the ad_users data
// source projects. Omitting attributes that the data source doesn't expose
// (notably primaryGroupID, memberOf, address fields) keeps paged searches
// over thousands of users cheap and lets entryToUser skip primary-group
// SID resolution because primaryGroupID is absent from the entry.
func DataSourceUsersAttributes() []string {
	return []string{
		"objectGUID", "distinguishedName",
		"sAMAccountName", "userPrincipalName", "cn",
		"displayName", "givenName", "sn", "mail",
		"title", "department", "company", "manager", "physicalDeliveryOfficeName",
		"userAccountControl",
		"whenCreated", "lastLogon",
	}
}

// getAllUserAttributes returns the complete list of user attributes to retrieve.
func (um *UserManager) getAllUserAttributes() []string {
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

		// Timestamps and lockout
		"whenCreated", "whenChanged", "lastLogon", "pwdLastSet", "accountExpires", "lockoutTime",
	}
}

// validateSearchFilter validates the user-provided search filter.
func (um *UserManager) validateSearchFilter(filter *UserSearchFilter) error {
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
func (um *UserManager) buildLDAPFilter(filter *UserSearchFilter) (string, error) {
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
		departmentFilter := fmt.Sprintf("(department=%s)", ldap.EscapeFilter(filter.Department))
		if filter.NegateDepartment {
			departmentFilter = fmt.Sprintf("(!%s)", departmentFilter)
		}
		filterParts = append(filterParts, departmentFilter)
	}
	if filter.Title != "" {
		titleFilter := fmt.Sprintf("(title=%s)", ldap.EscapeFilter(filter.Title))
		if filter.NegateTitle {
			titleFilter = fmt.Sprintf("(!%s)", titleFilter)
		}
		filterParts = append(filterParts, titleFilter)
	}
	if filter.Manager != "" {
		// Normalize manager identifier to DN
		managerDN, err := um.normalizer.NormalizeToDN(filter.Manager)
		if err != nil {
			return "", fmt.Errorf("failed to normalize manager identifier: %w", err)
		}
		filterParts = append(filterParts, fmt.Sprintf("(manager=%s)", ldap.EscapeFilter(managerDN)))
	}
	if filter.Company != "" {
		companyFilter := fmt.Sprintf("(company=%s)", ldap.EscapeFilter(filter.Company))
		if filter.NegateCompany {
			companyFilter = fmt.Sprintf("(!%s)", companyFilter)
		}
		filterParts = append(filterParts, companyFilter)
	}
	if filter.Office != "" {
		officeFilter := fmt.Sprintf("(physicalDeliveryOfficeName=%s)", ldap.EscapeFilter(filter.Office))
		if filter.NegateOffice {
			officeFilter = fmt.Sprintf("(!%s)", officeFilter)
		}
		filterParts = append(filterParts, officeFilter)
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
		memberOfFilter := fmt.Sprintf("(memberOf:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(filter.MemberOf))
		if filter.NegateMemberOf {
			// Users who are NOT members of the specified group (including nested)
			memberOfFilter = fmt.Sprintf("(!%s)", memberOfFilter)
		}
		filterParts = append(filterParts, memberOfFilter)
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

// -----------------------------------------------------------------------------
// Internal Write Helpers
// -----------------------------------------------------------------------------

// setPasswordByDN sets the password for a user by their DN.
func (um *UserManager) setPasswordByDN(userDN string, password string) error {
	// Encode the password for AD
	encodedPassword := EncodeADPassword(password)

	// Modify the unicodePwd attribute
	modReq := &ModifyRequest{
		DN:                userDN,
		ReplaceAttributes: make(map[string][]string),
	}
	// Note: unicodePwd is a binary attribute, so we pass the encoded bytes as a string
	modReq.ReplaceAttributes["unicodePwd"] = []string{string(encodedPassword)}

	if err := um.client.Modify(um.ctx, modReq); err != nil {
		return WrapError("set_password", err)
	}

	return nil
}

// calculateUserAccountControl calculates the UAC value from the request flags.
func (um *UserManager) calculateUserAccountControl(req *CreateUserRequest) int32 {
	uac := UACNormalAccount

	// Handle enabled flag (default: true)
	if req.Enabled == nil || *req.Enabled {
		// Account is enabled, don't set disabled flag
	} else {
		uac |= UACAccountDisabled
	}

	// Handle other flags (default: false for all)
	if req.PasswordNeverExpires != nil && *req.PasswordNeverExpires {
		uac |= UACPasswordNeverExpires
	}

	if req.SmartCardLogonRequired != nil && *req.SmartCardLogonRequired {
		uac |= UACSmartCardRequired
	}

	if req.TrustedForDelegation != nil && *req.TrustedForDelegation {
		uac |= UACTrustedForDelegation
	}

	// Note: ChangePasswordAtLogon is handled separately via pwdLastSet attribute

	return uac
}

// calculateUACChanges determines if UAC needs to change and returns the new value.
func (um *UserManager) calculateUACChanges(req *UpdateUserRequest, currentUser *User) (bool, int32) {
	newUAC := currentUser.UserAccountControl
	changed := false

	// Handle enabled flag
	if req.Enabled != nil {
		if *req.Enabled && !currentUser.AccountEnabled {
			// Enable account - remove disabled flag
			newUAC &^= UACAccountDisabled
			changed = true
		} else if !*req.Enabled && currentUser.AccountEnabled {
			// Disable account - add disabled flag
			newUAC |= UACAccountDisabled
			changed = true
		}
	}

	// Handle PasswordNeverExpires flag
	if req.PasswordNeverExpires != nil {
		if *req.PasswordNeverExpires && !currentUser.PasswordNeverExpires {
			newUAC |= UACPasswordNeverExpires
			changed = true
		} else if !*req.PasswordNeverExpires && currentUser.PasswordNeverExpires {
			newUAC &^= UACPasswordNeverExpires
			changed = true
		}
	}

	// Handle SmartCardLogonRequired flag
	if req.SmartCardLogonRequired != nil {
		if *req.SmartCardLogonRequired && !currentUser.SmartCardLogonRequired {
			newUAC |= UACSmartCardRequired
			changed = true
		} else if !*req.SmartCardLogonRequired && currentUser.SmartCardLogonRequired {
			newUAC &^= UACSmartCardRequired
			changed = true
		}
	}

	// Handle TrustedForDelegation flag
	if req.TrustedForDelegation != nil {
		if *req.TrustedForDelegation && !currentUser.TrustedForDelegation {
			newUAC |= UACTrustedForDelegation
			changed = true
		} else if !*req.TrustedForDelegation && currentUser.TrustedForDelegation {
			newUAC &^= UACTrustedForDelegation
			changed = true
		}
	}

	return changed, newUAC
}

// renameAndMoveUser handles renaming and/or moving a user using ModifyDN operation.
func (um *UserManager) renameAndMoveUser(currentUser *User, newName, newContainer string) error {
	currentContainer, _ := GetDNParent(currentUser.DistinguishedName)

	// Check if any actual change is needed
	if newName == currentUser.CommonName && strings.EqualFold(newContainer, currentContainer) {
		return nil
	}

	tflog.SubsystemDebug(um.ctx, "ldap", "Renaming/moving user", map[string]any{
		"user_dn":           currentUser.DistinguishedName,
		"current_name":      currentUser.CommonName,
		"new_name":          newName,
		"current_container": currentContainer,
		"new_container":     newContainer,
	})

	// Parse the current DN
	parsedDN, err := ldap.ParseDN(currentUser.DistinguishedName)
	if err != nil {
		return fmt.Errorf("failed to parse current DN: %w", err)
	}

	if len(parsedDN.RDNs) == 0 {
		return fmt.Errorf("invalid DN structure")
	}

	// Create the new RDN
	var newRDN string
	if newName == currentUser.CommonName {
		newRDN = parsedDN.RDNs[0].String()
	} else {
		newRDN = fmt.Sprintf("CN=%s", ldap.EscapeDN(newName))
	}

	// Determine if we need to specify a new superior (container)
	var newSuperior string
	if !strings.EqualFold(newContainer, currentContainer) {
		newSuperior = newContainer
	}

	// Create the ModifyDN request
	modifyDNReq := &ModifyDNRequest{
		DN:           currentUser.DistinguishedName,
		NewRDN:       newRDN,
		DeleteOldRDN: true,
		NewSuperior:  newSuperior,
	}

	// Execute the ModifyDN operation
	if err := um.client.ModifyDN(um.ctx, modifyDNReq); err != nil {
		return WrapError("modify_user_dn", err)
	}

	return nil
}

// addOptionalAttribute adds an attribute to the map if the value is non-empty.
func (um *UserManager) addOptionalAttribute(attrs map[string][]string, name, value string) {
	if value != "" {
		attrs[name] = []string{value}
	}
}

// addModifyAttribute adds an attribute modification if the value differs from current.
// Returns true if a change was added.
func (um *UserManager) addModifyAttribute(modReq *ModifyRequest, ldapAttr string, newValue *string, currentValue string) bool {
	if newValue == nil {
		return false
	}

	if *newValue == currentValue {
		return false
	}

	if *newValue == "" {
		// Delete the attribute
		modReq.DeleteAttributes = append(modReq.DeleteAttributes, ldapAttr)
	} else {
		// Replace with new value
		modReq.ReplaceAttributes[ldapAttr] = []string{*newValue}
	}

	return true
}
