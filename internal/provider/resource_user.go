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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
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
var _ resource.ResourceWithValidateConfig = &UserResource{}
var _ resource.ResourceWithConfigValidators = &UserResource{}
var _ resource.ResourceWithModifyPlan = &UserResource{}

// Schema-level regex validators compiled once at package load.
var (
	userNameRegex          = regexp.MustCompile(`^[^"]+$`)
	userPrincipalNameRegex = regexp.MustCompile(`^[^@]+@[^@]+$`)
	userSAMAccountRegex    = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
)

// NewUserResource creates a new instance of the user resource.
func NewUserResource() resource.Resource {
	return &UserResource{}
}

// UserResource defines the resource implementation.
type UserResource struct {
	client       ldapclient.Client
	cacheManager *ldapclient.CacheManager
	baseDN       string
}

// UserResourceModel describes the resource data model.
type UserResourceModel struct {
	ID  types.String              `tfsdk:"id"`
	DN  customtypes.DNStringValue `tfsdk:"dn"`
	SID types.String              `tfsdk:"sid"`

	Name           types.String              `tfsdk:"name"`
	PrincipalName  types.String              `tfsdk:"principal_name"`
	SAMAccountName types.String              `tfsdk:"sam_account_name"`
	Container      customtypes.DNStringValue `tfsdk:"container"`

	Password        types.String `tfsdk:"password"`
	PasswordVersion types.Int64  `tfsdk:"password_version"`

	Enabled                types.Bool `tfsdk:"enabled"`
	PasswordNeverExpires   types.Bool `tfsdk:"password_never_expires"`
	SmartCardLogonRequired types.Bool `tfsdk:"smart_card_logon_required"`
	TrustedForDelegation   types.Bool `tfsdk:"trusted_for_delegation"`
	ChangePasswordAtLogon  types.Bool `tfsdk:"change_password_at_logon"`

	PasswordNotRequired types.Bool  `tfsdk:"password_not_required"`
	AccountLockedOut    types.Bool  `tfsdk:"account_locked_out"`
	UserAccountControl  types.Int64 `tfsdk:"user_account_control"`

	DisplayName types.String `tfsdk:"display_name"`
	Description types.String `tfsdk:"description"`
	GivenName   types.String `tfsdk:"given_name"`
	Surname     types.String `tfsdk:"surname"`
	Initials    types.String `tfsdk:"initials"`

	EmailAddress types.String `tfsdk:"email_address"`
	HomePhone    types.String `tfsdk:"home_phone"`
	MobilePhone  types.String `tfsdk:"mobile_phone"`
	OfficePhone  types.String `tfsdk:"office_phone"`
	Fax          types.String `tfsdk:"fax"`
	HomePage     types.String `tfsdk:"home_page"`

	StreetAddress types.String `tfsdk:"street_address"`
	City          types.String `tfsdk:"city"`
	State         types.String `tfsdk:"state"`
	PostalCode    types.String `tfsdk:"postal_code"`
	Country       types.String `tfsdk:"country"`
	POBox         types.String `tfsdk:"po_box"`

	Title          types.String `tfsdk:"title"`
	Department     types.String `tfsdk:"department"`
	Company        types.String `tfsdk:"company"`
	Manager        types.String `tfsdk:"manager"`
	EmployeeID     types.String `tfsdk:"employee_id"`
	EmployeeNumber types.String `tfsdk:"employee_number"`
	Office         types.String `tfsdk:"office"`
	Division       types.String `tfsdk:"division"`
	Organization   types.String `tfsdk:"organization"`

	HomeDirectory types.String `tfsdk:"home_directory"`
	HomeDrive     types.String `tfsdk:"home_drive"`
	ProfilePath   types.String `tfsdk:"profile_path"`
	LogonScript   types.String `tfsdk:"logon_script"`

	MemberOf     types.List   `tfsdk:"member_of"`
	PrimaryGroup types.String `tfsdk:"primary_group"`

	WhenCreated     types.String `tfsdk:"when_created"`
	WhenChanged     types.String `tfsdk:"when_changed"`
	LastLogon       types.String `tfsdk:"last_logon"`
	PasswordLastSet types.String `tfsdk:"password_last_set"`
	AccountExpires  types.String `tfsdk:"account_expires"`
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
					planmodifiers.ComputeDN("CN", "container"),
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
						userNameRegex,
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
						userPrincipalNameRegex,
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
						userSAMAccountRegex,
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
				PlanModifiers: []planmodifier.Bool{
					planmodifiers.EnabledRequiresPassword(path.Root("password")),
				},
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
				MarkdownDescription: "Whether the user must change their password at next logon. On Create, defaults to `true` when no `password` is set and `false` otherwise. On Update, the prior state value is preserved when this attribute is omitted from configuration.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					planmodifiers.DefaultChangePasswordAtLogon(),
				},
			},

			// Computed security (read-only)
			"password_not_required": schema.BoolAttribute{
				MarkdownDescription: "Whether the user account is configured to not require a password.",
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"account_locked_out": schema.BoolAttribute{
				MarkdownDescription: "Whether the user account is currently locked out.",
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"user_account_control": schema.Int64Attribute{
				MarkdownDescription: "The raw Active Directory userAccountControl value as an integer.",
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
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
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"primary_group": schema.StringAttribute{
				MarkdownDescription: "The primary group of the user (typically 'Domain Users').",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// Computed timestamps
			"when_created": schema.StringAttribute{
				MarkdownDescription: "When the user was created (RFC3339 format).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"when_changed": schema.StringAttribute{
				MarkdownDescription: "When the user was last modified (RFC3339 format).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_logon": schema.StringAttribute{
				MarkdownDescription: "When the user last logged on (RFC3339 format).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"password_last_set": schema.StringAttribute{
				MarkdownDescription: "When the user's password was last set (RFC3339 format).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					planmodifiers.PasswordLastSetUnknown(),
				},
			},
			"account_expires": schema.StringAttribute{
				MarkdownDescription: "When the user account expires (RFC3339 format).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *UserResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data UserResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Warn if enabled is true (or default) but no password is set.
	// Active Directory requires a password before an account can be enabled.
	if (data.Enabled.IsNull() || data.Enabled.ValueBool()) && (data.Password.IsNull() || data.Password.ValueString() == "") {
		resp.Diagnostics.AddWarning(
			"Account will be created disabled",
			"Active Directory requires a password before enabling an account. "+
				"The account will be created disabled because no password is provided. "+
				"Set 'password' to enable the account on creation.",
		)
	}
}

// ConfigValidators implements resource.ResourceWithConfigValidators.
func (r *UserResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		validators.ChangePasswordAtLogonRequiresPassword(),
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

	baseDN, err := r.client.GetBaseDN(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"LDAP Configuration Error",
			fmt.Sprintf("Could not determine base DN from LDAP server: %s", err.Error()),
		)
		return
	}
	r.baseDN = baseDN
}

// ModifyPlan adjusts computed attributes whose final value cannot be pinned to
// state when other attributes change. It must run after all attribute-level
// plan modifiers so the "driver" attributes have been fully resolved (e.g.
// booldefault and EnabledRequiresPassword on `enabled`).
//
// It marks:
//   - user_account_control as Unknown when any of the UAC driver attributes
//     differs between state and plan;
//   - when_changed as Unknown when any tracked attribute differs between state
//     and plan (i.e. an Update will occur).
//
// On create (state is null) and destroy (plan is null) it is a no-op: the
// framework's Unknown default for Computed attributes applies on create, and
// destroy leaves computed values untouched.
func (r *UserResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Destroy: nothing to do.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Create: leave framework Unknown defaults in place.
	if req.State.Raw.IsNull() {
		return
	}

	var plan, state, config UserResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if evaluatePasswordRotation(plan.PasswordVersion, state.PasswordVersion, config.Password) == rotationOutcomeMissingPassword {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			passwordRotationMissingTitle,
			passwordRotationMissingDetail,
		)
	}

	// Mark user_account_control Unknown when any UAC driver differs between
	// state and plan. Unknown plan driver values are treated as "no change"
	// (they will be resolved by the driver's own plan modifiers).
	if userAccountControlDriversDiffer(plan, state) {
		plan.UserAccountControl = types.Int64Unknown()
	}

	// Mark when_changed Unknown whenever the plan represents a real change
	// from state (i.e. an Update will happen). On pure refresh the helper
	// returns false and we leave the UseStateForUnknown-resolved value intact.
	differs, diags := planmodifiers.PlanDiffersFromState(ctx, req.Plan, req.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if differs {
		plan.WhenChanged = types.StringUnknown()
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

type rotationOutcome int

const (
	rotationOutcomeNone rotationOutcome = iota
	rotationOutcomeDefer
	rotationOutcomeReady
	rotationOutcomeMissingPassword
)

const (
	passwordRotationMissingTitle  = "Password Required For Rotation"
	passwordRotationMissingDetail = "Incrementing password_version triggers a password rotation, but no password is provided in configuration. " +
		"Provide a non-empty password attribute (e.g. via an ephemeral resource) when rotating."
	passwordRotationUnknownDetail = "Incrementing password_version triggers a password rotation, but the password value is unknown at apply time. " +
		"Provide a concrete password attribute when rotating."
)

// evaluatePasswordRotation classifies a possible password rotation triggered
// by a change to password_version. The apply path additionally gates on
// version > 0; this helper does not.
func evaluatePasswordRotation(planVersion, stateVersion types.Int64, configPassword types.String) rotationOutcome {
	if planVersion.IsUnknown() {
		return rotationOutcomeDefer
	}

	if planVersion.Equal(stateVersion) {
		return rotationOutcomeNone
	}

	// Rotation is triggered. Examine the password.
	if configPassword.IsUnknown() {
		return rotationOutcomeDefer
	}
	if configPassword.IsNull() || configPassword.ValueString() == "" {
		return rotationOutcomeMissingPassword
	}
	return rotationOutcomeReady
}

// userAccountControlDriversDiffer reports whether any of the boolean driver
// attributes that compose userAccountControl differ between state and plan.
// Unknown plan values are treated as "no change" — the framework resolves
// them via the driver attribute's own plan modifiers.
func userAccountControlDriversDiffer(plan, state UserResourceModel) bool {
	drivers := []struct {
		plan, state types.Bool
	}{
		{plan.Enabled, state.Enabled},
		{plan.PasswordNeverExpires, state.PasswordNeverExpires},
		{plan.SmartCardLogonRequired, state.SmartCardLogonRequired},
		{plan.TrustedForDelegation, state.TrustedForDelegation},
	}
	for _, d := range drivers {
		if d.plan.IsUnknown() {
			continue
		}
		if !d.plan.Equal(d.state) {
			return true
		}
	}
	return false
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

	userManager := r.getUserManager(ctx)

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

	userManager := r.getUserManager(ctx)

	// Get the user by GUID
	user, err := userManager.GetUserByGUID(data.ID.ValueString())
	if err != nil {
		if ldapclient.IsNotFoundError(err) {
			resp.State.RemoveResource(ctx)
			return
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

	userManager := r.getUserManager(ctx)

	// Get current state for comparison
	var currentData UserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &currentData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if password should be reset (version > 0 AND version changed).
	// evaluatePasswordRotation is reused here as a defence-in-depth check:
	// ModifyPlan may have deferred when config.password was Unknown (e.g.
	// sourced from an ephemeral resource) and the value could resolve to
	// empty at apply time.
	passwordReset := false
	if !data.PasswordVersion.IsNull() &&
		data.PasswordVersion.ValueInt64() > 0 &&
		!data.PasswordVersion.Equal(currentData.PasswordVersion) {

		// Read password from config (WriteOnly attributes are only available in config)
		var config UserResourceModel
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
		if resp.Diagnostics.HasError() {
			return
		}

		switch evaluatePasswordRotation(data.PasswordVersion, currentData.PasswordVersion, config.Password) {
		case rotationOutcomeMissingPassword:
			resp.Diagnostics.AddAttributeError(
				path.Root("password"),
				passwordRotationMissingTitle,
				passwordRotationMissingDetail,
			)
			return
		case rotationOutcomeDefer:
			resp.Diagnostics.AddAttributeError(
				path.Root("password"),
				passwordRotationMissingTitle,
				passwordRotationUnknownDetail,
			)
			return
		case rotationOutcomeReady:
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
			passwordReset = true
		}
	}

	// AD's unicodePwd modify side-effect bumps pwdLastSet to the current time,
	// silently clearing the "must change at next logon" flag. Re-read the user
	// before diffing so buildUpdateRequest sees the post-reset state; otherwise
	// an unchanged change_password_at_logon=true on both plan and prior state
	// would compare equal and the pwdLastSet=0 write would never be re-issued.
	if passwordReset {
		refreshed, err := userManager.GetUserByGUID(data.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Reading User After Password Reset",
				fmt.Sprintf("Could not refresh user with ID %s after password reset: %s", data.ID.ValueString(), err.Error()),
			)
			return
		}
		r.userToModel(ctx, refreshed, &currentData, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Build update request by comparing plan to current state
	updateReq := r.buildUpdateRequest(&data, &currentData)

	if updateReq == nil {
		tflog.Debug(ctx, "No changes detected for AD user")
		// Plan == state for AD-tracked attrs. After a rotation, currentData
		// already reflects the post-reset server state from the refresh above;
		// copy the server-computed fields onto data without a second round trip.
		if passwordReset {
			data.WhenChanged = currentData.WhenChanged
			data.PasswordLastSet = currentData.PasswordLastSet
			data.UserAccountControl = currentData.UserAccountControl
			data.PasswordNotRequired = currentData.PasswordNotRequired
			data.AccountLockedOut = currentData.AccountLockedOut
		}
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

	userManager := r.getUserManager(ctx)

	// Delete the user
	err := userManager.DeleteUser(data.ID.ValueString())
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

	// Normalize the import ID to a DN (supports DN, GUID, SID, UPN, SAM formats)
	normalizer := ldapclient.NewMemberNormalizer(r.client, r.baseDN, r.cacheManager)
	resolved, err := normalizer.Resolve(importID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Resolving User Identifier",
			fmt.Sprintf("Could not resolve user identifier '%s' to DN. Supported formats: DN, GUID, SID, UPN, SAM Account Name. Error: %s", importID, err.Error()),
		)
		return
	}
	userDN := resolved.DN

	tflog.Debug(ctx, "Resolved user identifier to DN", map[string]any{
		"import_id": importID,
		"user_dn":   userDN,
	})

	userManager := r.getUserManager(ctx)

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
}

// getUserManager creates a UserManager instance using the cached base DN.
func (r *UserResource) getUserManager(ctx context.Context) *ldapclient.UserManager {
	return ldapclient.NewUserManager(ctx, r.client, r.baseDN, r.cacheManager)
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
	containerDN, _ := ldapclient.GetDNParent(user.DistinguishedName)
	model.Container = customtypes.DNString(helpers.NormalizeDN(ctx, containerDN))

	// Required fields
	model.Name = types.StringValue(user.CommonName)
	model.PrincipalName = types.StringValue(user.UserPrincipalName)
	model.SAMAccountName = types.StringValue(user.SAMAccountName)

	// Security flags
	model.Enabled = types.BoolValue(user.AccountEnabled)
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
