package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	"github.com/isometry/terraform-provider-ad/internal/provider/helpers"
	"github.com/isometry/terraform-provider-ad/internal/provider/planmodifiers"
	customtypes "github.com/isometry/terraform-provider-ad/internal/provider/types"
	"github.com/isometry/terraform-provider-ad/internal/provider/validators"
	"github.com/isometry/terraform-provider-ad/internal/utils"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &UserResource{}
var _ resource.ResourceWithImportState = &UserResource{}

// NewUserResource creates a new instance of the user resource.
func NewUserResource() resource.Resource {
	return &UserResource{}
}

// UserResource defines the resource implementation.
type UserResource struct {
	client       ldapclient.Client
	cacheManager *ldapclient.CacheManager
}

// UserResourceModel describes the resource data model.
type UserResourceModel struct {
	// Identity (computed)
	ID  types.String              `tfsdk:"id"`  // objectGUID
	DN  customtypes.DNStringValue `tfsdk:"dn"`  // computed
	SID types.String              `tfsdk:"sid"` // computed

	// Required
	Name           types.String              `tfsdk:"name"`             // cn
	PrincipalName  types.String              `tfsdk:"principal_name"`   // UPN
	SAMAccountName types.String              `tfsdk:"sam_account_name"` // Optional+Computed (auto from name)
	Container      customtypes.DNStringValue `tfsdk:"container"`        // parent OU

	// Password (write-only with version trigger)
	Password        types.String `tfsdk:"password"`
	PasswordVersion types.Int64  `tfsdk:"password_version"`

	// Security flags (Optional+Computed+Default)
	Enabled                types.Bool `tfsdk:"enabled"`                   // default: true
	CannotChangePassword   types.Bool `tfsdk:"cannot_change_password"`    // default: false
	PasswordNeverExpires   types.Bool `tfsdk:"password_never_expires"`    // default: false
	SmartCardLogonRequired types.Bool `tfsdk:"smart_card_logon_required"` // default: false
	TrustedForDelegation   types.Bool `tfsdk:"trusted_for_delegation"`    // default: false
	ChangePasswordAtLogon  types.Bool `tfsdk:"change_password_at_logon"`  // default: false

	// Computed security (read-only)
	PasswordNotRequired types.Bool  `tfsdk:"password_not_required"` // computed
	AccountLockedOut    types.Bool  `tfsdk:"account_locked_out"`    // computed
	UserAccountControl  types.Int64 `tfsdk:"user_account_control"`  // computed (raw int)

	// Personal information
	DisplayName types.String `tfsdk:"display_name"` // optional
	Description types.String `tfsdk:"description"`  // optional
	GivenName   types.String `tfsdk:"given_name"`   // optional
	Surname     types.String `tfsdk:"surname"`      // optional
	Initials    types.String `tfsdk:"initials"`     // optional

	// Contact information
	EmailAddress types.String `tfsdk:"email_address"` // optional
	HomePhone    types.String `tfsdk:"home_phone"`    // optional
	MobilePhone  types.String `tfsdk:"mobile_phone"`  // optional
	OfficePhone  types.String `tfsdk:"office_phone"`  // optional
	Fax          types.String `tfsdk:"fax"`           // optional
	HomePage     types.String `tfsdk:"home_page"`     // optional

	// Address information
	StreetAddress types.String `tfsdk:"street_address"` // optional
	City          types.String `tfsdk:"city"`           // optional
	State         types.String `tfsdk:"state"`          // optional
	PostalCode    types.String `tfsdk:"postal_code"`    // optional
	Country       types.String `tfsdk:"country"`        // optional
	POBox         types.String `tfsdk:"po_box"`         // optional

	// Organizational information
	Title          types.String `tfsdk:"title"`           // optional
	Department     types.String `tfsdk:"department"`      // optional
	Company        types.String `tfsdk:"company"`         // optional
	Manager        types.String `tfsdk:"manager"`         // optional (DN)
	EmployeeID     types.String `tfsdk:"employee_id"`     // optional
	EmployeeNumber types.String `tfsdk:"employee_number"` // optional
	Office         types.String `tfsdk:"office"`          // optional
	Division       types.String `tfsdk:"division"`        // optional
	Organization   types.String `tfsdk:"organization"`    // optional

	// System information
	HomeDirectory types.String `tfsdk:"home_directory"` // optional
	HomeDrive     types.String `tfsdk:"home_drive"`     // optional
	ProfilePath   types.String `tfsdk:"profile_path"`   // optional
	LogonScript   types.String `tfsdk:"logon_script"`   // optional

	// Computed memberships
	MemberOf     types.List   `tfsdk:"member_of"`     // computed (list of group DNs)
	PrimaryGroup types.String `tfsdk:"primary_group"` // computed

	// Computed timestamps
	WhenCreated     types.String `tfsdk:"when_created"`      // computed
	WhenChanged     types.String `tfsdk:"when_changed"`      // computed
	LastLogon       types.String `tfsdk:"last_logon"`        // computed
	PasswordLastSet types.String `tfsdk:"password_last_set"` // computed
	AccountExpires  types.String `tfsdk:"account_expires"`   // computed
}

func (r *UserResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (r *UserResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an Active Directory user account. Users represent individuals or service accounts that can authenticate to the domain.",

		Attributes: map[string]schema.Attribute{
			// Identity (computed)
			"id": schema.StringAttribute{
				MarkdownDescription: "The objectGUID of the user. This is automatically assigned by Active Directory and used as the unique identifier.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dn": schema.StringAttribute{
				MarkdownDescription: "The distinguished name of the user. This is automatically generated based on the name and container.",
				Computed:            true,
				CustomType:          customtypes.DNStringType{},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sid": schema.StringAttribute{
				MarkdownDescription: "The Security Identifier (SID) of the user. This is automatically assigned by Active Directory.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// Required
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the user (cn attribute). This is the common name visible in Active Directory. " +
					"**Changing this value will destroy and recreate the user.**",
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 64),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[^"]+$`),
						"User name cannot contain double quotes",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"principal_name": schema.StringAttribute{
				MarkdownDescription: "The User Principal Name (UPN) for the user (e.g., `user@example.com`). " +
					"This is the primary login name for the user.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 256),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[^@]+@[^@]+$`),
						"UPN must be in the format user@domain",
					),
				},
			},
			"sam_account_name": schema.StringAttribute{
				MarkdownDescription: "The SAM account name (pre-Windows 2000 name). Must be unique within the domain and " +
					"cannot exceed 20 characters. If not specified, defaults to the value of 'name' if it's 20 characters or less.",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 20),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-zA-Z0-9._-]+$`),
						"SAM account name can only contain letters, numbers, dots, underscores, and hyphens",
					),
				},
				PlanModifiers: []planmodifier.String{
					planmodifiers.UseNameForSAMAccountName(true), // true = user (20 char limit)
				},
			},
			"container": schema.StringAttribute{
				MarkdownDescription: "The distinguished name of the container or organizational unit where the user will be created " +
					"(e.g., `OU=Users,DC=example,DC=com`). Changing this will move the user to the new location.",
				Required:   true,
				CustomType: customtypes.DNStringType{},
				Validators: []validator.String{
					validators.IsValidDN(),
				},
			},

			// Password (write-only with version trigger)
			"password": schema.StringAttribute{
				MarkdownDescription: "The password for the user. This is **write-only** and never stored in state. " +
					"When `password_version` is 0 or omitted, the password is only set on create. " +
					"When `password_version` > 0, the password is set whenever the version changes. " +
					"Requires LDAPS connection. **Note**: Requires Terraform 1.11+.",
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
			},
			"password_version": schema.Int64Attribute{
				MarkdownDescription: "Controls when the password is applied. When set to `0` (default), password is only " +
					"set on resource creation. When set to a value > 0, changing this value triggers a password reset. " +
					"Increment this value to force a password change on the next apply.",
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(0),
			},

			// Security flags
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the user account is enabled. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"cannot_change_password": schema.BoolAttribute{
				MarkdownDescription: "Whether the user cannot change their own password. Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"password_never_expires": schema.BoolAttribute{
				MarkdownDescription: "Whether the user's password never expires. Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"smart_card_logon_required": schema.BoolAttribute{
				MarkdownDescription: "Whether the user must use a smart card for logon. Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"trusted_for_delegation": schema.BoolAttribute{
				MarkdownDescription: "Whether the user is trusted for Kerberos delegation. Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"change_password_at_logon": schema.BoolAttribute{
				MarkdownDescription: "Whether the user must change their password at next logon. Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},

			// Computed security (read-only)
			"password_not_required": schema.BoolAttribute{
				MarkdownDescription: "Whether the user account is configured to not require a password.",
				Computed:            true,
			},
			"account_locked_out": schema.BoolAttribute{
				MarkdownDescription: "Whether the user account is currently locked out.",
				Computed:            true,
			},
			"user_account_control": schema.Int64Attribute{
				MarkdownDescription: "The raw Active Directory userAccountControl value as an integer.",
				Computed:            true,
			},

			// Personal information
			"display_name": schema.StringAttribute{
				MarkdownDescription: "The display name of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(256),
				},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description for the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(1024),
				},
			},
			"given_name": schema.StringAttribute{
				MarkdownDescription: "The first name (given name) of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
				},
			},
			"surname": schema.StringAttribute{
				MarkdownDescription: "The last name (surname) of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
				},
			},
			"initials": schema.StringAttribute{
				MarkdownDescription: "The middle initials of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(6),
				},
			},

			// Contact information
			"email_address": schema.StringAttribute{
				MarkdownDescription: "The primary email address of the user (mail attribute).",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(256),
				},
			},
			"home_phone": schema.StringAttribute{
				MarkdownDescription: "The home telephone number of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
				},
			},
			"mobile_phone": schema.StringAttribute{
				MarkdownDescription: "The mobile telephone number of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
				},
			},
			"office_phone": schema.StringAttribute{
				MarkdownDescription: "The office telephone number of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
				},
			},
			"fax": schema.StringAttribute{
				MarkdownDescription: "The fax number of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
				},
			},
			"home_page": schema.StringAttribute{
				MarkdownDescription: "The web page URL of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(2048),
				},
			},

			// Address information
			"street_address": schema.StringAttribute{
				MarkdownDescription: "The street address of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(1024),
				},
			},
			"city": schema.StringAttribute{
				MarkdownDescription: "The city/locality of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(128),
				},
			},
			"state": schema.StringAttribute{
				MarkdownDescription: "The state/province of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(128),
				},
			},
			"postal_code": schema.StringAttribute{
				MarkdownDescription: "The ZIP/postal code of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(40),
				},
			},
			"country": schema.StringAttribute{
				MarkdownDescription: "The country of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(128),
				},
			},
			"po_box": schema.StringAttribute{
				MarkdownDescription: "The P.O. Box of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(40),
				},
			},

			// Organizational information
			"title": schema.StringAttribute{
				MarkdownDescription: "The job title of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(128),
				},
			},
			"department": schema.StringAttribute{
				MarkdownDescription: "The department of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
				},
			},
			"company": schema.StringAttribute{
				MarkdownDescription: "The company name of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
				},
			},
			"manager": schema.StringAttribute{
				MarkdownDescription: "The Distinguished Name of the user's manager.",
				Optional:            true,
				Validators: []validator.String{
					validators.IsValidDN(),
				},
			},
			"employee_id": schema.StringAttribute{
				MarkdownDescription: "The employee ID of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(16),
				},
			},
			"employee_number": schema.StringAttribute{
				MarkdownDescription: "The employee number of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(512),
				},
			},
			"office": schema.StringAttribute{
				MarkdownDescription: "The physical office location of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(128),
				},
			},
			"division": schema.StringAttribute{
				MarkdownDescription: "The division of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(256),
				},
			},
			"organization": schema.StringAttribute{
				MarkdownDescription: "The organization of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
				},
			},

			// System information
			"home_directory": schema.StringAttribute{
				MarkdownDescription: "The home directory path of the user (e.g., `\\\\server\\share\\%username%`).",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(260),
				},
			},
			"home_drive": schema.StringAttribute{
				MarkdownDescription: "The home drive letter of the user (e.g., `H:`).",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(3),
				},
			},
			"profile_path": schema.StringAttribute{
				MarkdownDescription: "The profile path of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(260),
				},
			},
			"logon_script": schema.StringAttribute{
				MarkdownDescription: "The logon script path of the user.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(260),
				},
			},

			// Computed memberships
			"member_of": schema.ListAttribute{
				MarkdownDescription: "A list of Distinguished Names of groups this user is a member of.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			"primary_group": schema.StringAttribute{
				MarkdownDescription: "The primary group of the user (typically 'Domain Users').",
				Computed:            true,
			},

			// Computed timestamps
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

func (r *UserResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*ldapclient.ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *ldapclient.ProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = providerData.Client
	r.cacheManager = providerData.CacheManager
}

func (r *UserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data UserResourceModel

	ctx = utils.InitializeLogging(ctx)

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read write-only attribute from config (not available in plan)
	var config UserResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	start := time.Now()
	tflog.Debug(ctx, "Starting resource operation", map[string]any{
		"operation": "create",
		"resource":  "ad_user",
		"name":      data.Name.ValueString(),
	})
	defer func() {
		duration := time.Since(start)
		if resp.Diagnostics.HasError() {
			tflog.Error(ctx, "Resource operation failed", map[string]any{
				"operation":   "create",
				"resource":    "ad_user",
				"duration_ms": duration.Milliseconds(),
			})
		} else {
			tflog.Info(ctx, "Resource operation completed", map[string]any{
				"operation":   "create",
				"resource":    "ad_user",
				"duration_ms": duration.Milliseconds(),
			})
		}
	}()

	// Create UserManager
	userManager, err := r.getUserManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating User Manager",
			err.Error(),
		)
		return
	}

	// Convert Terraform model to LDAP create request
	createReq := r.modelToCreateRequest(&data)

	// Set password from config (WriteOnly attributes are only available in config)
	if !config.Password.IsNull() && config.Password.ValueString() != "" {
		createReq.InitialPassword = config.Password.ValueString()
	}

	// Create the user
	user, err := userManager.CreateUser(createReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating User",
			"Could not create user, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Created AD user", map[string]any{
		"guid": user.ObjectGUID,
		"dn":   user.DistinguishedName,
	})

	// Update the model with the created user data
	r.userToModel(ctx, user, &data, &resp.Diagnostics)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data UserResourceModel

	ctx = utils.InitializeLogging(ctx)

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading AD user", map[string]any{
		"guid": data.ID.ValueString(),
	})

	// Create UserManager
	userManager, err := r.getUserManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating User Manager",
			err.Error(),
		)
		return
	}

	// Get the user by GUID
	user, err := userManager.GetUserByGUID(data.ID.ValueString())
	if err != nil {
		if ldapErr, ok := err.(*ldapclient.LDAPError); ok {
			if strings.Contains(ldapErr.Error(), "not found") {
				resp.State.RemoveResource(ctx)
				return
			}
		}

		resp.Diagnostics.AddError(
			"Error Reading User",
			fmt.Sprintf("Could not read user with ID %s: %s", data.ID.ValueString(), err.Error()),
		)
		return
	}

	// Update the model with the current user data
	r.userToModel(ctx, user, &data, &resp.Diagnostics)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data UserResourceModel

	ctx = utils.InitializeLogging(ctx)

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating AD user", map[string]any{
		"guid": data.ID.ValueString(),
	})

	// Create UserManager
	userManager, err := r.getUserManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating User Manager",
			err.Error(),
		)
		return
	}

	// Get current state for comparison
	var currentData UserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &currentData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if password should be reset (version > 0 AND version changed)
	if !data.PasswordVersion.IsNull() &&
		data.PasswordVersion.ValueInt64() > 0 &&
		!data.PasswordVersion.Equal(currentData.PasswordVersion) {

		// Read password from config (WriteOnly attributes are only available in config)
		var config UserResourceModel
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if !config.Password.IsNull() && config.Password.ValueString() != "" {
			tflog.Debug(ctx, "Password version changed, resetting password", map[string]any{
				"old_version": currentData.PasswordVersion.ValueInt64(),
				"new_version": data.PasswordVersion.ValueInt64(),
			})

			err := userManager.SetPassword(data.ID.ValueString(), config.Password.ValueString())
			if err != nil {
				resp.Diagnostics.AddError(
					"Error Setting Password",
					"Could not set password: "+err.Error(),
				)
				return
			}
			tflog.Debug(ctx, "Password reset successfully")
		}
	}

	// Build update request by comparing plan to current state
	updateReq := r.buildUpdateRequest(&data, &currentData)

	// Check if there are any changes
	if updateReq == nil {
		tflog.Debug(ctx, "No changes detected for AD user")
		// Still need to refresh computed fields
		user, err := userManager.GetUserByGUID(data.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Reading User",
				fmt.Sprintf("Could not read user with ID %s: %s", data.ID.ValueString(), err.Error()),
			)
			return
		}
		r.userToModel(ctx, user, &data, &resp.Diagnostics)
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}

	// Update the user
	user, err := userManager.UpdateUser(data.ID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating User",
			"Could not update user, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Updated AD user", map[string]any{
		"guid": user.ObjectGUID,
	})

	// Update the model with the updated user data
	r.userToModel(ctx, user, &data, &resp.Diagnostics)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data UserResourceModel

	ctx = utils.InitializeLogging(ctx)

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting AD user", map[string]any{
		"guid": data.ID.ValueString(),
	})

	// Create UserManager
	userManager, err := r.getUserManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating User Manager",
			err.Error(),
		)
		return
	}

	// Delete the user
	err = userManager.DeleteUser(data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting User",
			"Could not delete user, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "Deleted AD user", map[string]any{
		"guid": data.ID.ValueString(),
	})
}

func (r *UserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importID := strings.TrimSpace(req.ID)

	tflog.Debug(ctx, "Importing AD user", map[string]any{
		"import_id": importID,
	})

	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Getting Base DN",
			fmt.Sprintf("Could not get base DN for identifier normalization: %s", err.Error()),
		)
		return
	}

	// Normalize the import ID to a DN (supports DN, GUID, SID, UPN, SAM formats)
	normalizer := ldapclient.NewMemberNormalizer(r.client, baseDN, r.cacheManager)
	userDN, err := normalizer.NormalizeToDN(importID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Resolving User Identifier",
			fmt.Sprintf("Could not resolve user identifier '%s' to DN. Supported formats: DN, GUID, SID, UPN, SAM Account Name. Error: %s", importID, err.Error()),
		)
		return
	}

	tflog.Debug(ctx, "Resolved user identifier to DN", map[string]any{
		"import_id": importID,
		"user_dn":   userDN,
	})

	// Create UserManager
	userManager, err := r.getUserManager(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating User Manager",
			err.Error(),
		)
		return
	}

	// Get the user by DN
	user, err := userManager.GetUserByDN(userDN)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing User",
			fmt.Sprintf("Could not import user at DN '%s': %s", userDN, err.Error()),
		)
		return
	}

	// Create model from the imported user
	var data UserResourceModel
	r.userToModel(ctx, user, &data, &resp.Diagnostics)

	tflog.Info(ctx, "Successfully imported AD user", map[string]any{
		"import_id": importID,
		"user_guid": user.ObjectGUID,
		"user_dn":   user.DistinguishedName,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), user.ObjectGUID)...)
}

// getUserManager creates a UserManager instance with base DN lookup.
func (r *UserResource) getUserManager(ctx context.Context) (*ldapclient.UserManager, error) {
	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get base DN from LDAP server: %w", err)
	}

	return ldapclient.NewUserManager(ctx, r.client, baseDN, r.cacheManager), nil
}

// modelToCreateRequest converts the Terraform model to an LDAP CreateUserRequest.
// Note: InitialPassword is handled separately in Create() from config (WriteOnly attribute).
func (r *UserResource) modelToCreateRequest(model *UserResourceModel) *ldapclient.CreateUserRequest {
	req := &ldapclient.CreateUserRequest{
		Name:              model.Name.ValueString(),
		UserPrincipalName: model.PrincipalName.ValueString(),
		SAMAccountName:    model.SAMAccountName.ValueString(),
		Container:         model.Container.ValueString(),
	}

	// Security flags
	if !model.Enabled.IsNull() {
		enabled := model.Enabled.ValueBool()
		req.Enabled = &enabled
	}
	if !model.CannotChangePassword.IsNull() {
		val := model.CannotChangePassword.ValueBool()
		req.CannotChangePassword = &val
	}
	if !model.PasswordNeverExpires.IsNull() {
		val := model.PasswordNeverExpires.ValueBool()
		req.PasswordNeverExpires = &val
	}
	if !model.SmartCardLogonRequired.IsNull() {
		val := model.SmartCardLogonRequired.ValueBool()
		req.SmartCardLogonRequired = &val
	}
	if !model.TrustedForDelegation.IsNull() {
		val := model.TrustedForDelegation.ValueBool()
		req.TrustedForDelegation = &val
	}
	if !model.ChangePasswordAtLogon.IsNull() {
		val := model.ChangePasswordAtLogon.ValueBool()
		req.ChangePasswordAtLogon = &val
	}

	// Personal information
	req.DisplayName = helpers.GetString(model.DisplayName)
	req.Description = helpers.GetString(model.Description)
	req.GivenName = helpers.GetString(model.GivenName)
	req.Surname = helpers.GetString(model.Surname)
	req.Initials = helpers.GetString(model.Initials)

	// Contact information
	req.EmailAddress = helpers.GetString(model.EmailAddress)
	req.HomePhone = helpers.GetString(model.HomePhone)
	req.MobilePhone = helpers.GetString(model.MobilePhone)
	req.OfficePhone = helpers.GetString(model.OfficePhone)
	req.Fax = helpers.GetString(model.Fax)
	req.HomePage = helpers.GetString(model.HomePage)

	// Address information
	req.StreetAddress = helpers.GetString(model.StreetAddress)
	req.City = helpers.GetString(model.City)
	req.State = helpers.GetString(model.State)
	req.PostalCode = helpers.GetString(model.PostalCode)
	req.Country = helpers.GetString(model.Country)
	req.POBox = helpers.GetString(model.POBox)

	// Organizational information
	req.Title = helpers.GetString(model.Title)
	req.Department = helpers.GetString(model.Department)
	req.Company = helpers.GetString(model.Company)
	req.Manager = helpers.GetString(model.Manager)
	req.EmployeeID = helpers.GetString(model.EmployeeID)
	req.EmployeeNumber = helpers.GetString(model.EmployeeNumber)
	req.Office = helpers.GetString(model.Office)
	req.Division = helpers.GetString(model.Division)
	req.Organization = helpers.GetString(model.Organization)

	// System information
	req.HomeDirectory = helpers.GetString(model.HomeDirectory)
	req.HomeDrive = helpers.GetString(model.HomeDrive)
	req.ProfilePath = helpers.GetString(model.ProfilePath)
	req.LogonScript = helpers.GetString(model.LogonScript)

	return req
}

// buildUpdateRequest creates an UpdateUserRequest by comparing plan to current state.
func (r *UserResource) buildUpdateRequest(plan, state *UserResourceModel) *ldapclient.UpdateUserRequest {
	updateReq := &ldapclient.UpdateUserRequest{}
	hasChanges := false

	// Check container change (triggers move)
	if !plan.Container.Equal(state.Container) {
		container := plan.Container.ValueString()
		updateReq.Container = &container
		hasChanges = true
	}

	// Check UPN change
	if !plan.PrincipalName.Equal(state.PrincipalName) {
		upn := plan.PrincipalName.ValueString()
		updateReq.UserPrincipalName = &upn
		hasChanges = true
	}

	// Check SAM account name change
	if !plan.SAMAccountName.Equal(state.SAMAccountName) {
		sam := plan.SAMAccountName.ValueString()
		updateReq.SAMAccountName = &sam
		hasChanges = true
	}

	// Check security flag changes
	hasChanges = helpers.BoolChanged(plan.Enabled, state.Enabled, &updateReq.Enabled) || hasChanges
	hasChanges = helpers.BoolChanged(plan.CannotChangePassword, state.CannotChangePassword, &updateReq.CannotChangePassword) || hasChanges
	hasChanges = helpers.BoolChanged(plan.PasswordNeverExpires, state.PasswordNeverExpires, &updateReq.PasswordNeverExpires) || hasChanges
	hasChanges = helpers.BoolChanged(plan.SmartCardLogonRequired, state.SmartCardLogonRequired, &updateReq.SmartCardLogonRequired) || hasChanges
	hasChanges = helpers.BoolChanged(plan.TrustedForDelegation, state.TrustedForDelegation, &updateReq.TrustedForDelegation) || hasChanges
	hasChanges = helpers.BoolChanged(plan.ChangePasswordAtLogon, state.ChangePasswordAtLogon, &updateReq.ChangePasswordAtLogon) || hasChanges

	// Check string attribute changes
	hasChanges = helpers.StringChanged(plan.DisplayName, state.DisplayName, &updateReq.DisplayName) || hasChanges
	hasChanges = helpers.StringChanged(plan.Description, state.Description, &updateReq.Description) || hasChanges
	hasChanges = helpers.StringChanged(plan.GivenName, state.GivenName, &updateReq.GivenName) || hasChanges
	hasChanges = helpers.StringChanged(plan.Surname, state.Surname, &updateReq.Surname) || hasChanges
	hasChanges = helpers.StringChanged(plan.Initials, state.Initials, &updateReq.Initials) || hasChanges
	hasChanges = helpers.StringChanged(plan.EmailAddress, state.EmailAddress, &updateReq.EmailAddress) || hasChanges
	hasChanges = helpers.StringChanged(plan.HomePhone, state.HomePhone, &updateReq.HomePhone) || hasChanges
	hasChanges = helpers.StringChanged(plan.MobilePhone, state.MobilePhone, &updateReq.MobilePhone) || hasChanges
	hasChanges = helpers.StringChanged(plan.OfficePhone, state.OfficePhone, &updateReq.OfficePhone) || hasChanges
	hasChanges = helpers.StringChanged(plan.Fax, state.Fax, &updateReq.Fax) || hasChanges
	hasChanges = helpers.StringChanged(plan.HomePage, state.HomePage, &updateReq.HomePage) || hasChanges
	hasChanges = helpers.StringChanged(plan.StreetAddress, state.StreetAddress, &updateReq.StreetAddress) || hasChanges
	hasChanges = helpers.StringChanged(plan.City, state.City, &updateReq.City) || hasChanges
	hasChanges = helpers.StringChanged(plan.State, state.State, &updateReq.State) || hasChanges
	hasChanges = helpers.StringChanged(plan.PostalCode, state.PostalCode, &updateReq.PostalCode) || hasChanges
	hasChanges = helpers.StringChanged(plan.Country, state.Country, &updateReq.Country) || hasChanges
	hasChanges = helpers.StringChanged(plan.POBox, state.POBox, &updateReq.POBox) || hasChanges
	hasChanges = helpers.StringChanged(plan.Title, state.Title, &updateReq.Title) || hasChanges
	hasChanges = helpers.StringChanged(plan.Department, state.Department, &updateReq.Department) || hasChanges
	hasChanges = helpers.StringChanged(plan.Company, state.Company, &updateReq.Company) || hasChanges
	hasChanges = helpers.StringChanged(plan.Manager, state.Manager, &updateReq.Manager) || hasChanges
	hasChanges = helpers.StringChanged(plan.EmployeeID, state.EmployeeID, &updateReq.EmployeeID) || hasChanges
	hasChanges = helpers.StringChanged(plan.EmployeeNumber, state.EmployeeNumber, &updateReq.EmployeeNumber) || hasChanges
	hasChanges = helpers.StringChanged(plan.Office, state.Office, &updateReq.Office) || hasChanges
	hasChanges = helpers.StringChanged(plan.Division, state.Division, &updateReq.Division) || hasChanges
	hasChanges = helpers.StringChanged(plan.Organization, state.Organization, &updateReq.Organization) || hasChanges
	hasChanges = helpers.StringChanged(plan.HomeDirectory, state.HomeDirectory, &updateReq.HomeDirectory) || hasChanges
	hasChanges = helpers.StringChanged(plan.HomeDrive, state.HomeDrive, &updateReq.HomeDrive) || hasChanges
	hasChanges = helpers.StringChanged(plan.ProfilePath, state.ProfilePath, &updateReq.ProfilePath) || hasChanges
	hasChanges = helpers.StringChanged(plan.LogonScript, state.LogonScript, &updateReq.LogonScript) || hasChanges

	if !hasChanges {
		return nil
	}

	return updateReq
}

// userToModel maps an LDAP User to the Terraform model.
func (r *UserResource) userToModel(ctx context.Context, user *ldapclient.User, model *UserResourceModel, diags *diag.Diagnostics) {
	// Identity
	model.ID = types.StringValue(user.ObjectGUID)
	model.SID = types.StringValue(user.ObjectSid)

	// Normalize DN and container
	model.DN = customtypes.DNString(helpers.NormalizeDN(ctx, user.DistinguishedName))
	model.Container = customtypes.DNString(helpers.NormalizeDN(ctx, r.extractContainer(user.DistinguishedName)))

	// Required fields
	model.Name = types.StringValue(user.CommonName)
	model.PrincipalName = types.StringValue(user.UserPrincipalName)
	model.SAMAccountName = types.StringValue(user.SAMAccountName)

	// Security flags
	model.Enabled = types.BoolValue(user.AccountEnabled)
	model.CannotChangePassword = types.BoolValue(user.CannotChangePassword)
	model.PasswordNeverExpires = types.BoolValue(user.PasswordNeverExpires)
	model.SmartCardLogonRequired = types.BoolValue(user.SmartCardLogonRequired)
	model.TrustedForDelegation = types.BoolValue(user.TrustedForDelegation)
	model.ChangePasswordAtLogon = types.BoolValue(user.ChangePasswordAtLogon)

	// Computed security
	model.PasswordNotRequired = types.BoolValue(user.PasswordNotRequired)
	model.AccountLockedOut = types.BoolValue(user.AccountLockedOut)
	model.UserAccountControl = types.Int64Value(int64(user.UserAccountControl))

	// Personal information
	model.DisplayName = helpers.StringOrNull(user.DisplayName)
	model.Description = helpers.StringOrNull(user.Description)
	model.GivenName = helpers.StringOrNull(user.GivenName)
	model.Surname = helpers.StringOrNull(user.Surname)
	model.Initials = helpers.StringOrNull(user.Initials)

	// Contact information
	model.EmailAddress = helpers.StringOrNull(user.EmailAddress)
	model.HomePhone = helpers.StringOrNull(user.HomePhone)
	model.MobilePhone = helpers.StringOrNull(user.MobilePhone)
	model.OfficePhone = helpers.StringOrNull(user.OfficePhone)
	model.Fax = helpers.StringOrNull(user.Fax)
	model.HomePage = helpers.StringOrNull(user.HomePage)

	// Address information
	model.StreetAddress = helpers.StringOrNull(user.StreetAddress)
	model.City = helpers.StringOrNull(user.City)
	model.State = helpers.StringOrNull(user.State)
	model.PostalCode = helpers.StringOrNull(user.PostalCode)
	model.Country = helpers.StringOrNull(user.Country)
	model.POBox = helpers.StringOrNull(user.POBox)

	// Organizational information
	model.Title = helpers.StringOrNull(user.Title)
	model.Department = helpers.StringOrNull(user.Department)
	model.Company = helpers.StringOrNull(user.Company)
	model.Manager = helpers.StringOrNull(user.Manager)
	model.EmployeeID = helpers.StringOrNull(user.EmployeeID)
	model.EmployeeNumber = helpers.StringOrNull(user.EmployeeNumber)
	model.Office = helpers.StringOrNull(user.Office)
	model.Division = helpers.StringOrNull(user.Division)
	model.Organization = helpers.StringOrNull(user.Organization)

	// System information
	model.HomeDirectory = helpers.StringOrNull(user.HomeDirectory)
	model.HomeDrive = helpers.StringOrNull(user.HomeDrive)
	model.ProfilePath = helpers.StringOrNull(user.ProfilePath)
	model.LogonScript = helpers.StringOrNull(user.LogonScript)

	// Group memberships
	model.PrimaryGroup = types.StringValue(user.PrimaryGroup)
	model.MemberOf = helpers.DNListOrNull(ctx, user.MemberOf, diags)

	// Timestamps - convert to RFC3339 format using shared helpers
	model.WhenCreated = helpers.Timestamp(user.WhenCreated)
	model.WhenChanged = helpers.Timestamp(user.WhenChanged)
	model.LastLogon = helpers.TimestampOrNull(user.LastLogon)
	model.PasswordLastSet = helpers.TimestampOrNull(user.PasswordLastSet)
	model.AccountExpires = helpers.TimestampOrNull(user.AccountExpires)
}

// extractContainer extracts the container DN from a full DN.
func (r *UserResource) extractContainer(dn string) string {
	// Find the first comma and return everything after it
	idx := strings.Index(dn, ",")
	if idx >= 0 && idx < len(dn)-1 {
		return dn[idx+1:]
	}
	return ""
}
