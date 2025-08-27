package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &UserDataSource{}
var _ datasource.DataSourceWithConfigValidators = &UserDataSource{}

func NewUserDataSource() datasource.DataSource {
	return &UserDataSource{}
}

// UserDataSource defines the data source implementation.
type UserDataSource struct {
	client     ldapclient.Client
	userReader *ldapclient.UserReader
}

// UserDataSourceModel describes the data source data model with multiple lookup methods.
type UserDataSourceModel struct {
	// Lookup methods (mutually exclusive)
	ID                types.String `tfsdk:"id"`               // objectGUID lookup
	DistinguishedName types.String `tfsdk:"dn"`               // Distinguished Name lookup
	UserPrincipalName types.String `tfsdk:"upn"`              // UPN lookup (user@domain.com)
	SAMAccountName    types.String `tfsdk:"sam_account_name"` // SAM account name lookup
	SID               types.String `tfsdk:"sid"`              // Security Identifier lookup

	// Core identity attributes (all computed)
	ObjectGUID  types.String `tfsdk:"object_guid"`  // objectGUID
	ObjectSid   types.String `tfsdk:"object_sid"`   // Security Identifier
	Name        types.String `tfsdk:"name"`         // Common name (cn)
	DisplayName types.String `tfsdk:"display_name"` // Display name
	GivenName   types.String `tfsdk:"given_name"`   // First name
	Surname     types.String `tfsdk:"surname"`      // Last name
	Initials    types.String `tfsdk:"initials"`     // Middle initials
	Description types.String `tfsdk:"description"`  // User description

	// Contact information
	EmailAddress types.String `tfsdk:"email_address"` // Primary email (mail attribute)
	HomePhone    types.String `tfsdk:"home_phone"`    // Home telephone number
	MobilePhone  types.String `tfsdk:"mobile_phone"`  // Mobile telephone number
	OfficePhone  types.String `tfsdk:"office_phone"`  // Office telephone number
	Fax          types.String `tfsdk:"fax"`           // Fax number
	HomePage     types.String `tfsdk:"home_page"`     // Web page URL

	// Address information
	StreetAddress types.String `tfsdk:"street_address"` // Street address
	City          types.String `tfsdk:"city"`           // City/locality
	State         types.String `tfsdk:"state"`          // State/province
	PostalCode    types.String `tfsdk:"postal_code"`    // ZIP/postal code
	Country       types.String `tfsdk:"country"`        // Country
	POBox         types.String `tfsdk:"po_box"`         // P.O. Box

	// Organizational information
	Title          types.String `tfsdk:"title"`           // Job title
	Department     types.String `tfsdk:"department"`      // Department
	Company        types.String `tfsdk:"company"`         // Company name
	Manager        types.String `tfsdk:"manager"`         // Manager DN
	EmployeeID     types.String `tfsdk:"employee_id"`     // Employee ID
	EmployeeNumber types.String `tfsdk:"employee_number"` // Employee number
	Office         types.String `tfsdk:"office"`          // Physical office location
	Division       types.String `tfsdk:"division"`        // Division
	Organization   types.String `tfsdk:"organization"`    // Organization

	// System information
	HomeDirectory types.String `tfsdk:"home_directory"` // Home directory path
	HomeDrive     types.String `tfsdk:"home_drive"`     // Home drive letter
	ProfilePath   types.String `tfsdk:"profile_path"`   // Profile path
	LogonScript   types.String `tfsdk:"logon_script"`   // Logon script path

	// Account status and security
	AccountEnabled         types.Bool  `tfsdk:"account_enabled"`           // Account is enabled
	PasswordNeverExpires   types.Bool  `tfsdk:"password_never_expires"`    // Password never expires
	PasswordNotRequired    types.Bool  `tfsdk:"password_not_required"`     // No password required
	ChangePasswordAtLogon  types.Bool  `tfsdk:"change_password_at_logon"`  // Must change password at next logon
	CannotChangePassword   types.Bool  `tfsdk:"cannot_change_password"`    // Cannot change password
	SmartCardLogonRequired types.Bool  `tfsdk:"smart_card_logon_required"` // Smart card required
	TrustedForDelegation   types.Bool  `tfsdk:"trusted_for_delegation"`    // Trusted for delegation
	AccountLockedOut       types.Bool  `tfsdk:"account_locked_out"`        // Account is locked out
	UserAccountControl     types.Int64 `tfsdk:"user_account_control"`      // Raw UAC value

	// Group memberships
	MemberOf     types.List   `tfsdk:"member_of"`     // Groups this user is a member of (DNs)
	PrimaryGroup types.String `tfsdk:"primary_group"` // Primary group DN

	// Timestamps
	WhenCreated     types.String `tfsdk:"when_created"`      // When user was created
	WhenChanged     types.String `tfsdk:"when_changed"`      // When user was last modified
	LastLogon       types.String `tfsdk:"last_logon"`        // Last logon timestamp
	PasswordLastSet types.String `tfsdk:"password_last_set"` // Password last set timestamp
	AccountExpires  types.String `tfsdk:"account_expires"`   // Account expiration timestamp
}

func (d *UserDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (d *UserDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about an Active Directory user. Supports multiple lookup methods: " +
			"objectGUID, Distinguished Name, User Principal Name (UPN), SAM account name, or Security Identifier (SID).",

		Attributes: map[string]schema.Attribute{
			// Lookup methods (mutually exclusive)
			"id": schema.StringAttribute{
				MarkdownDescription: "The objectGUID of the user to retrieve. This is the most reliable lookup method " +
					"as objectGUIDs are immutable and unique. Format: `550e8400-e29b-41d4-a716-446655440000`",
				Optional: true,
				Computed: true,
			},
			"dn": schema.StringAttribute{
				MarkdownDescription: "The Distinguished Name of the user to retrieve. " +
					"Example: `CN=John Doe,CN=Users,DC=example,DC=com`",
				Optional: true,
				Computed: true,
			},
			"upn": schema.StringAttribute{
				MarkdownDescription: "The User Principal Name (UPN) of the user to retrieve. " +
					"Example: `john.doe@example.com`",
				Optional: true,
				Computed: true,
			},
			"sam_account_name": schema.StringAttribute{
				MarkdownDescription: "The SAM account name (pre-Windows 2000 name) of the user to retrieve. " +
					"This performs a domain-wide search. Example: `jdoe`",
				Optional: true,
				Computed: true,
			},
			"sid": schema.StringAttribute{
				MarkdownDescription: "The Security Identifier (SID) of the user to retrieve. " +
					"Example: `S-1-5-21-123456789-123456789-123456789-1001`",
				Optional: true,
				Computed: true,
			},

			// Core identity attributes (all computed)
			"object_guid": schema.StringAttribute{
				MarkdownDescription: "The objectGUID of the user (immutable unique identifier).",
				Computed:            true,
			},
			"object_sid": schema.StringAttribute{
				MarkdownDescription: "The Security Identifier (SID) of the user.",
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The common name (cn) of the user.",
				Computed:            true,
			},
			"display_name": schema.StringAttribute{
				MarkdownDescription: "The display name of the user.",
				Computed:            true,
			},
			"given_name": schema.StringAttribute{
				MarkdownDescription: "The first name (given name) of the user.",
				Computed:            true,
			},
			"surname": schema.StringAttribute{
				MarkdownDescription: "The last name (surname) of the user.",
				Computed:            true,
			},
			"initials": schema.StringAttribute{
				MarkdownDescription: "The middle initials of the user.",
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "The description of the user.",
				Computed:            true,
			},

			// Contact information
			"email_address": schema.StringAttribute{
				MarkdownDescription: "The primary email address of the user (mail attribute).",
				Computed:            true,
			},
			"home_phone": schema.StringAttribute{
				MarkdownDescription: "The home telephone number of the user.",
				Computed:            true,
			},
			"mobile_phone": schema.StringAttribute{
				MarkdownDescription: "The mobile telephone number of the user.",
				Computed:            true,
			},
			"office_phone": schema.StringAttribute{
				MarkdownDescription: "The office telephone number of the user.",
				Computed:            true,
			},
			"fax": schema.StringAttribute{
				MarkdownDescription: "The fax number of the user.",
				Computed:            true,
			},
			"home_page": schema.StringAttribute{
				MarkdownDescription: "The web page URL of the user.",
				Computed:            true,
			},

			// Address information
			"street_address": schema.StringAttribute{
				MarkdownDescription: "The street address of the user.",
				Computed:            true,
			},
			"city": schema.StringAttribute{
				MarkdownDescription: "The city/locality of the user.",
				Computed:            true,
			},
			"state": schema.StringAttribute{
				MarkdownDescription: "The state/province of the user.",
				Computed:            true,
			},
			"postal_code": schema.StringAttribute{
				MarkdownDescription: "The ZIP/postal code of the user.",
				Computed:            true,
			},
			"country": schema.StringAttribute{
				MarkdownDescription: "The country of the user.",
				Computed:            true,
			},
			"po_box": schema.StringAttribute{
				MarkdownDescription: "The P.O. Box of the user.",
				Computed:            true,
			},

			// Organizational information
			"title": schema.StringAttribute{
				MarkdownDescription: "The job title of the user.",
				Computed:            true,
			},
			"department": schema.StringAttribute{
				MarkdownDescription: "The department of the user.",
				Computed:            true,
			},
			"company": schema.StringAttribute{
				MarkdownDescription: "The company name of the user.",
				Computed:            true,
			},
			"manager": schema.StringAttribute{
				MarkdownDescription: "The Distinguished Name of the user's manager.",
				Computed:            true,
			},
			"employee_id": schema.StringAttribute{
				MarkdownDescription: "The employee ID of the user.",
				Computed:            true,
			},
			"employee_number": schema.StringAttribute{
				MarkdownDescription: "The employee number of the user.",
				Computed:            true,
			},
			"office": schema.StringAttribute{
				MarkdownDescription: "The physical office location of the user.",
				Computed:            true,
			},
			"division": schema.StringAttribute{
				MarkdownDescription: "The division of the user.",
				Computed:            true,
			},
			"organization": schema.StringAttribute{
				MarkdownDescription: "The organization of the user.",
				Computed:            true,
			},

			// System information
			"home_directory": schema.StringAttribute{
				MarkdownDescription: "The home directory path of the user.",
				Computed:            true,
			},
			"home_drive": schema.StringAttribute{
				MarkdownDescription: "The home drive letter of the user.",
				Computed:            true,
			},
			"profile_path": schema.StringAttribute{
				MarkdownDescription: "The profile path of the user.",
				Computed:            true,
			},
			"logon_script": schema.StringAttribute{
				MarkdownDescription: "The logon script path of the user.",
				Computed:            true,
			},

			// Account status and security
			"account_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the user account is enabled.",
				Computed:            true,
			},
			"password_never_expires": schema.BoolAttribute{
				MarkdownDescription: "Whether the user's password never expires.",
				Computed:            true,
			},
			"password_not_required": schema.BoolAttribute{
				MarkdownDescription: "Whether the user account requires a password.",
				Computed:            true,
			},
			"change_password_at_logon": schema.BoolAttribute{
				MarkdownDescription: "Whether the user must change password at next logon.",
				Computed:            true,
			},
			"cannot_change_password": schema.BoolAttribute{
				MarkdownDescription: "Whether the user cannot change their password.",
				Computed:            true,
			},
			"smart_card_logon_required": schema.BoolAttribute{
				MarkdownDescription: "Whether the user requires smart card for logon.",
				Computed:            true,
			},
			"trusted_for_delegation": schema.BoolAttribute{
				MarkdownDescription: "Whether the user is trusted for delegation.",
				Computed:            true,
			},
			"account_locked_out": schema.BoolAttribute{
				MarkdownDescription: "Whether the user account is locked out.",
				Computed:            true,
			},
			"user_account_control": schema.Int64Attribute{
				MarkdownDescription: "The raw Active Directory userAccountControl value as an integer.",
				Computed:            true,
			},

			// Group memberships
			"member_of": schema.ListAttribute{
				MarkdownDescription: "A list of Distinguished Names of groups this user is a member of.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			"primary_group": schema.StringAttribute{
				MarkdownDescription: "The Distinguished Name of the user's primary group.",
				Computed:            true,
			},

			// Timestamps
			"when_created": schema.StringAttribute{
				MarkdownDescription: "When the user was created (RFC3339 format).",
				Computed:            true,
			},
			"when_changed": schema.StringAttribute{
				MarkdownDescription: "When the user was last modified (RFC3339 format).",
				Computed:            true,
			},
			"last_logon": schema.StringAttribute{
				MarkdownDescription: "When the user last logged on (RFC3339 format).",
				Computed:            true,
			},
			"password_last_set": schema.StringAttribute{
				MarkdownDescription: "When the user's password was last set (RFC3339 format).",
				Computed:            true,
			},
			"account_expires": schema.StringAttribute{
				MarkdownDescription: "When the user account expires (RFC3339 format).",
				Computed:            true,
			},
		},
	}
}

// ConfigValidators implements datasource.DataSourceWithConfigValidators.
func (d *UserDataSource) ConfigValidators(ctx context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		// Exactly one lookup method must be specified
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("id"),
			path.MatchRoot("dn"),
			path.MatchRoot("upn"),
			path.MatchRoot("sam_account_name"),
			path.MatchRoot("sid"),
		),
	}
}

func (d *UserDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(ldapclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected ldapclient.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client

	// Initialize user reader
	baseDN, err := client.GetBaseDN(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Get Base DN",
			fmt.Sprintf("Could not retrieve base DN from LDAP server: %s", err.Error()),
		)
		return
	}
	d.userReader = ldapclient.NewUserReader(ctx, client, baseDN)
}

func (d *UserDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data UserDataSourceModel

	// Initialize logging subsystem for consistent logging
	ctx = initializeLogging(ctx)

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Determine lookup method and retrieve user
	user, err := d.retrieveUser(ctx, &data)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading User",
			fmt.Sprintf("Could not read Active Directory user: %s", err.Error()),
		)
		return
	}

	if user == nil {
		resp.Diagnostics.AddError(
			"User Not Found",
			"The specified Active Directory user could not be found.",
		)
		return
	}

	// Log the successful retrieval
	tflog.Debug(ctx, "Successfully retrieved AD user", map[string]any{
		"user_guid": user.ObjectGUID,
		"user_dn":   user.DistinguishedName,
		"user_upn":  user.UserPrincipalName,
		"user_sam":  user.SAMAccountName,
	})

	// Map user data to model
	d.mapUserToModel(ctx, user, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// retrieveUser handles the different lookup methods and retrieves the user.
func (d *UserDataSource) retrieveUser(ctx context.Context, data *UserDataSourceModel) (*ldapclient.User, error) {
	// ID (objectGUID) lookup - most reliable
	if !data.ID.IsNull() && data.ID.ValueString() != "" {
		guid := data.ID.ValueString()
		tflog.Debug(ctx, "Looking up user by objectGUID", map[string]any{
			"guid": guid,
		})
		return d.userReader.GetUserByGUID(guid)
	}

	// DN lookup
	if !data.DistinguishedName.IsNull() && data.DistinguishedName.ValueString() != "" {
		dn := data.DistinguishedName.ValueString()
		tflog.Debug(ctx, "Looking up user by DN", map[string]any{
			"dn": dn,
		})
		return d.userReader.GetUserByDN(dn)
	}

	// UPN lookup
	if !data.UserPrincipalName.IsNull() && data.UserPrincipalName.ValueString() != "" {
		upn := data.UserPrincipalName.ValueString()
		tflog.Debug(ctx, "Looking up user by UPN", map[string]any{
			"upn": upn,
		})
		return d.userReader.GetUserByUPN(upn)
	}

	// SAM account name lookup
	if !data.SAMAccountName.IsNull() && data.SAMAccountName.ValueString() != "" {
		samAccountName := data.SAMAccountName.ValueString()
		tflog.Debug(ctx, "Looking up user by SAM account name", map[string]any{
			"sam_account_name": samAccountName,
		})
		return d.userReader.GetUserBySAM(samAccountName)
	}

	// SID lookup
	if !data.SID.IsNull() && data.SID.ValueString() != "" {
		sid := data.SID.ValueString()
		tflog.Debug(ctx, "Looking up user by SID", map[string]any{
			"sid": sid,
		})
		return d.userReader.GetUserBySID(sid)
	}

	return nil, fmt.Errorf("no valid lookup method provided")
}

// mapUserToModel maps the LDAP user data to the Terraform model.
func (d *UserDataSource) mapUserToModel(ctx context.Context, user *ldapclient.User, data *UserDataSourceModel, diags *diag.Diagnostics) {
	// Set the ID to objectGUID for state tracking
	data.ID = types.StringValue(user.ObjectGUID)

	// Populate lookup fields that can be referenced by other configurations
	data.DistinguishedName = types.StringValue(user.DistinguishedName)
	data.SAMAccountName = types.StringValue(user.SAMAccountName)
	data.UserPrincipalName = types.StringValue(user.UserPrincipalName)
	data.SID = types.StringValue(user.ObjectSid)

	// Core identity attributes (additional computed fields)
	data.ObjectGUID = types.StringValue(user.ObjectGUID)
	data.ObjectSid = types.StringValue(user.ObjectSid)
	data.Name = types.StringValue(user.CommonName)
	data.DisplayName = types.StringValue(user.DisplayName)
	data.GivenName = types.StringValue(user.GivenName)
	data.Surname = types.StringValue(user.Surname)
	data.Initials = types.StringValue(user.Initials)
	data.Description = types.StringValue(user.Description)

	// Contact information
	data.EmailAddress = types.StringValue(user.EmailAddress)
	data.HomePhone = types.StringValue(user.HomePhone)
	data.MobilePhone = types.StringValue(user.MobilePhone)
	data.OfficePhone = types.StringValue(user.OfficePhone)
	data.Fax = types.StringValue(user.Fax)
	data.HomePage = types.StringValue(user.HomePage)

	// Address information
	data.StreetAddress = types.StringValue(user.StreetAddress)
	data.City = types.StringValue(user.City)
	data.State = types.StringValue(user.State)
	data.PostalCode = types.StringValue(user.PostalCode)
	data.Country = types.StringValue(user.Country)
	data.POBox = types.StringValue(user.POBox)

	// Organizational information
	data.Title = types.StringValue(user.Title)
	data.Department = types.StringValue(user.Department)
	data.Company = types.StringValue(user.Company)
	data.Manager = types.StringValue(user.Manager)
	data.EmployeeID = types.StringValue(user.EmployeeID)
	data.EmployeeNumber = types.StringValue(user.EmployeeNumber)
	data.Office = types.StringValue(user.Office)
	data.Division = types.StringValue(user.Division)
	data.Organization = types.StringValue(user.Organization)

	// System information
	data.HomeDirectory = types.StringValue(user.HomeDirectory)
	data.HomeDrive = types.StringValue(user.HomeDrive)
	data.ProfilePath = types.StringValue(user.ProfilePath)
	data.LogonScript = types.StringValue(user.LogonScript)

	// Account status and security
	data.AccountEnabled = types.BoolValue(user.AccountEnabled)
	data.PasswordNeverExpires = types.BoolValue(user.PasswordNeverExpires)
	data.PasswordNotRequired = types.BoolValue(user.PasswordNotRequired)
	data.ChangePasswordAtLogon = types.BoolValue(user.ChangePasswordAtLogon)
	data.CannotChangePassword = types.BoolValue(user.CannotChangePassword)
	data.SmartCardLogonRequired = types.BoolValue(user.SmartCardLogonRequired)
	data.TrustedForDelegation = types.BoolValue(user.TrustedForDelegation)
	data.AccountLockedOut = types.BoolValue(user.AccountLockedOut)
	data.UserAccountControl = types.Int64Value(int64(user.UserAccountControl))

	// Group memberships
	data.PrimaryGroup = types.StringValue(user.PrimaryGroup)

	// Convert member DNs to a List, normalizing DN case
	if len(user.MemberOf) > 0 {
		memberElements := make([]attr.Value, len(user.MemberOf))
		for i, memberDN := range user.MemberOf {
			// Normalize member DN case
			normalizedMemberDN, err := ldapclient.NormalizeDNCase(memberDN)
			if err != nil {
				// Log error but use original DN as fallback
				tflog.Warn(ctx, "Failed to normalize member DN case", map[string]any{
					"original_member_dn": memberDN,
					"error":              err.Error(),
				})
				normalizedMemberDN = memberDN
			}
			memberElements[i] = types.StringValue(normalizedMemberDN)
		}

		memberList, memberDiags := types.ListValue(types.StringType, memberElements)
		diags.Append(memberDiags...)
		if !memberDiags.HasError() {
			data.MemberOf = memberList
		}
	} else {
		// Empty list for no memberships
		emptyList, memberDiags := types.ListValue(types.StringType, []attr.Value{})
		diags.Append(memberDiags...)
		if !memberDiags.HasError() {
			data.MemberOf = emptyList
		}
	}

	// Timestamps - convert to RFC3339 format
	data.WhenCreated = types.StringValue(user.WhenCreated.Format(time.RFC3339))
	data.WhenChanged = types.StringValue(user.WhenChanged.Format(time.RFC3339))

	// Handle nullable timestamps
	if user.LastLogon != nil {
		data.LastLogon = types.StringValue(user.LastLogon.Format(time.RFC3339))
	} else {
		data.LastLogon = types.StringNull()
	}

	if user.PasswordLastSet != nil {
		data.PasswordLastSet = types.StringValue(user.PasswordLastSet.Format(time.RFC3339))
	} else {
		data.PasswordLastSet = types.StringNull()
	}

	if user.AccountExpires != nil {
		data.AccountExpires = types.StringValue(user.AccountExpires.Format(time.RFC3339))
	} else {
		data.AccountExpires = types.StringNull()
	}

	tflog.Trace(ctx, "Mapped user data to model", map[string]any{
		"user_guid":    user.ObjectGUID,
		"user_upn":     user.UserPrincipalName,
		"user_sam":     user.SAMAccountName,
		"member_count": len(user.MemberOf),
	})
}
