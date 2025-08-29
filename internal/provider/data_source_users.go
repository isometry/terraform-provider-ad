package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	"github.com/isometry/terraform-provider-ad/internal/provider/validators"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &UsersDataSource{}

func NewUsersDataSource() datasource.DataSource {
	return &UsersDataSource{}
}

// UsersDataSource defines the data source implementation.
type UsersDataSource struct {
	client       ldapclient.Client
	cacheManager *ldapclient.CacheManager
	userReader   *ldapclient.UserReader
}

// UsersDataSourceModel describes the data source data model.
type UsersDataSourceModel struct {
	// Search configuration
	Container types.String `tfsdk:"container"` // Optional container DN to search within
	Scope     types.String `tfsdk:"scope"`     // Search scope: base, onelevel, subtree (default)
	Filter    types.Object `tfsdk:"filter"`    // Filter block for search criteria

	// Output
	Users     types.List   `tfsdk:"users"`      // List of users found
	UserCount types.Int64  `tfsdk:"user_count"` // Number of users found
	ID        types.String `tfsdk:"id"`         // Computed identifier for the data source
}

// UserFilterModel describes the nested filter block.
type UserFilterModel struct {
	// Name filters
	NamePrefix   types.String `tfsdk:"name_prefix"`   // Users whose common name starts with this string
	NameSuffix   types.String `tfsdk:"name_suffix"`   // Users whose common name ends with this string
	NameContains types.String `tfsdk:"name_contains"` // Users whose common name contains this string

	// Organizational filters
	Department types.String `tfsdk:"department"` // Department name
	Title      types.String `tfsdk:"title"`      // Job title
	Company    types.String `tfsdk:"company"`    // Company name (exact match)
	Office     types.String `tfsdk:"office"`     // Office location (exact match)
	Manager    types.String `tfsdk:"manager"`    // Manager DN, GUID, UPN, or SAM

	// Status filters
	Enabled types.Bool `tfsdk:"enabled"` // true=enabled accounts, false=disabled accounts

	// Email filters
	HasEmail    types.Bool   `tfsdk:"has_email"`    // true=users with email, false=users without email
	EmailDomain types.String `tfsdk:"email_domain"` // Email domain (e.g., "example.com")

	// Group membership filters (supports nested groups via LDAP_MATCHING_RULE_IN_CHAIN)
	MemberOf types.String `tfsdk:"member_of"` // Filter users who are members of specified group (DN), prefix with ! to negate
}

// UserDataModel describes a single user in the result set.
type UserDataModel struct {
	// Core identity
	ID                types.String `tfsdk:"id"`               // objectGUID
	DistinguishedName types.String `tfsdk:"dn"`               // full DN
	UserPrincipalName types.String `tfsdk:"upn"`              // UPN (user@domain.com)
	SAMAccountName    types.String `tfsdk:"sam_account_name"` // pre-Windows 2000 name
	Name              types.String `tfsdk:"name"`             // common name (cn)
	DisplayName       types.String `tfsdk:"display_name"`     // display name
	GivenName         types.String `tfsdk:"given_name"`       // first name
	Surname           types.String `tfsdk:"surname"`          // last name
	EmailAddress      types.String `tfsdk:"email_address"`    // primary email

	// Organizational information
	Title      types.String `tfsdk:"title"`      // job title
	Department types.String `tfsdk:"department"` // department
	Company    types.String `tfsdk:"company"`    // company name
	Manager    types.String `tfsdk:"manager"`    // manager DN
	Office     types.String `tfsdk:"office"`     // office location

	// Account status
	AccountEnabled types.Bool `tfsdk:"account_enabled"` // account is enabled

	// Timestamps
	WhenCreated types.String `tfsdk:"when_created"` // creation timestamp
	LastLogon   types.String `tfsdk:"last_logon"`   // last logon timestamp
}

func (d *UsersDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_users"
}

func (d *UsersDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of Active Directory users based on search criteria. " +
			"Supports filtering by name patterns, organizational information, account status, and email properties.",

		Attributes: map[string]schema.Attribute{
			// Search configuration
			"container": schema.StringAttribute{
				MarkdownDescription: "The DN of the container to search within. If not specified, searches from the base DN. " +
					"Example: `OU=Users,DC=example,DC=com`",
				Optional: true,
				Validators: []validator.String{
					validators.IsValidDN(),
				},
			},
			"scope": schema.StringAttribute{
				MarkdownDescription: "The search scope to use. Valid values: `base`, `onelevel`, `subtree`. Defaults to `subtree`.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("base", "onelevel", "subtree"),
				},
			},

			// Output attributes
			"user_count": schema.Int64Attribute{
				MarkdownDescription: "The total number of users found matching the search criteria.",
				Computed:            true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "A computed identifier for this data source instance.",
				Computed:            true,
			},
			"users": schema.ListNestedAttribute{
				MarkdownDescription: "List of users matching the search criteria.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The objectGUID of the user.",
							Computed:            true,
						},
						"dn": schema.StringAttribute{
							MarkdownDescription: "The full Distinguished Name of the user.",
							Computed:            true,
						},
						"upn": schema.StringAttribute{
							MarkdownDescription: "The User Principal Name (UPN) of the user.",
							Computed:            true,
						},
						"sam_account_name": schema.StringAttribute{
							MarkdownDescription: "The SAM account name (pre-Windows 2000 name) of the user.",
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
						"email_address": schema.StringAttribute{
							MarkdownDescription: "The primary email address of the user.",
							Computed:            true,
						},
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
						"office": schema.StringAttribute{
							MarkdownDescription: "The physical office location of the user.",
							Computed:            true,
						},
						"account_enabled": schema.BoolAttribute{
							MarkdownDescription: "Whether the user account is enabled.",
							Computed:            true,
						},
						"when_created": schema.StringAttribute{
							MarkdownDescription: "When the user was created (RFC3339 format).",
							Computed:            true,
						},
						"last_logon": schema.StringAttribute{
							MarkdownDescription: "When the user last logged on (RFC3339 format).",
							Computed:            true,
						},
					},
				},
			},
		},

		Blocks: map[string]schema.Block{
			"filter": schema.SingleNestedBlock{
				MarkdownDescription: "Filter criteria for searching users. All specified criteria must match (AND logic).",
				Attributes: map[string]schema.Attribute{
					"name_prefix": schema.StringAttribute{
						MarkdownDescription: "Users whose common name starts with this string. Case-insensitive.",
						Optional:            true,
					},
					"name_suffix": schema.StringAttribute{
						MarkdownDescription: "Users whose common name ends with this string. Case-insensitive.",
						Optional:            true,
					},
					"name_contains": schema.StringAttribute{
						MarkdownDescription: "Users whose common name contains this string. Case-insensitive.",
						Optional:            true,
					},
					"department": schema.StringAttribute{
						MarkdownDescription: "Filter by department. Case-insensitive partial match.",
						Optional:            true,
					},
					"title": schema.StringAttribute{
						MarkdownDescription: "Filter by job title. Case-insensitive partial match.",
						Optional:            true,
					},
					"manager": schema.StringAttribute{
						MarkdownDescription: "Filter by manager. Accepts Distinguished Name, GUID, UPN, or SAM account name.",
						Optional:            true,
					},
					"company": schema.StringAttribute{
						MarkdownDescription: "Filter by company name (exact match, case-insensitive).",
						Optional:            true,
					},
					"office": schema.StringAttribute{
						MarkdownDescription: "Filter by office location (exact match, case-insensitive).",
						Optional:            true,
					},
					"enabled": schema.BoolAttribute{
						MarkdownDescription: "Filter by account status. `true` returns only enabled accounts, " +
							"`false` returns only disabled accounts. If not specified, returns all accounts.",
						Optional: true,
					},
					"has_email": schema.BoolAttribute{
						MarkdownDescription: "Filter by email presence. `true` returns only users with email addresses, " +
							"`false` returns only users without email addresses. If not specified, returns all users.",
						Optional: true,
					},
					"email_domain": schema.StringAttribute{
						MarkdownDescription: "Filter by email domain (e.g., `example.com`). Only returns users whose " +
							"email addresses end with the specified domain.",
						Optional: true,
					},
					"member_of": schema.StringAttribute{
						MarkdownDescription: "Filter by group membership. Only returns users who are members of the " +
							"specified group (Distinguished Name). Includes nested group membership. " +
							"Prefix with `!` to negate (users NOT in group). " +
							"Examples: `CN=Domain Users,CN=Users,DC=example,DC=com` or `!CN=Disabled Users,CN=Users,DC=example,DC=com`",
						Optional: true,
						Validators: []validator.String{
							validators.IsValidDNWithNegation(),
						},
					},
				},
			},
		},
	}
}

func (d *UsersDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*ldapclient.ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *ldapclient.ProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = providerData.Client
	d.cacheManager = providerData.CacheManager

	// Initialize user reader
	baseDN, err := d.client.GetBaseDN(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Get Base DN",
			fmt.Sprintf("Could not retrieve base DN from LDAP server: %s", err.Error()),
		)
		return
	}
	d.userReader = ldapclient.NewUserReader(ctx, d.client, baseDN, d.cacheManager)
}

func (d *UsersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data UsersDataSourceModel

	// Initialize logging subsystem for consistent logging
	ctx = initializeLogging(ctx)

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build search filter from configuration
	searchFilter, err := d.buildSearchFilter(ctx, &data, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Building Search Filter",
			fmt.Sprintf("Could not build search filter: %s", err.Error()),
		)
		return
	}

	// Log the search parameters
	tflog.Debug(ctx, "Searching for AD users", map[string]any{
		"container":     searchFilter.Container,
		"name_prefix":   searchFilter.NamePrefix,
		"name_suffix":   searchFilter.NameSuffix,
		"name_contains": searchFilter.NameContains,
		"department":    searchFilter.Department,
		"title":         searchFilter.Title,
		"company":       searchFilter.Company,
		"office":        searchFilter.Office,
		"manager":       searchFilter.Manager,
		"enabled":       searchFilter.Enabled,
		"has_email":     searchFilter.HasEmail,
		"email_domain":  searchFilter.EmailDomain,
		"member_of":     searchFilter.MemberOf,
	})

	// Perform the search
	users, err := d.userReader.SearchUsersWithFilter(searchFilter)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Searching Users",
			fmt.Sprintf("Could not search Active Directory users: %s", err.Error()),
		)
		return
	}

	tflog.Debug(ctx, "Successfully found AD users", map[string]any{
		"user_count": len(users),
	})

	// Convert results to Terraform model
	d.mapUsersToModel(ctx, users, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set computed values
	data.UserCount = types.Int64Value(int64(len(users)))
	data.ID = types.StringValue(fmt.Sprintf("users-search-%d", len(users)))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// parseFilterValue parses a filter value and returns the clean value and whether it should be negated.
func parseFilterValue(value string) (cleanValue string, negate bool) {
	if strings.HasPrefix(value, "!") {
		return strings.TrimPrefix(value, "!"), true
	}
	return value, false
}

// buildSearchFilter converts the Terraform configuration to a UserSearchFilter.
func (d *UsersDataSource) buildSearchFilter(ctx context.Context, data *UsersDataSourceModel, diags *diag.Diagnostics) (*ldapclient.UserSearchFilter, error) {
	searchFilter := &ldapclient.UserSearchFilter{}

	// Set container if specified
	if !data.Container.IsNull() && data.Container.ValueString() != "" {
		searchFilter.Container = data.Container.ValueString()
	}

	// Parse filter block if present
	if !data.Filter.IsNull() {
		var filterModel UserFilterModel
		filterDiags := data.Filter.As(ctx, &filterModel, basetypes.ObjectAsOptions{})
		diags.Append(filterDiags...)
		if filterDiags.HasError() {
			return nil, fmt.Errorf("failed to parse filter block")
		}

		// Map name filter attributes
		if !filterModel.NamePrefix.IsNull() && filterModel.NamePrefix.ValueString() != "" {
			searchFilter.NamePrefix = filterModel.NamePrefix.ValueString()
		}

		if !filterModel.NameSuffix.IsNull() && filterModel.NameSuffix.ValueString() != "" {
			searchFilter.NameSuffix = filterModel.NameSuffix.ValueString()
		}

		if !filterModel.NameContains.IsNull() && filterModel.NameContains.ValueString() != "" {
			searchFilter.NameContains = filterModel.NameContains.ValueString()
		}

		// Map organizational filter attributes with negation support
		if !filterModel.Department.IsNull() && filterModel.Department.ValueString() != "" {
			departmentValue, negate := parseFilterValue(filterModel.Department.ValueString())
			searchFilter.Department = departmentValue
			searchFilter.NegateDepartment = negate
		}

		if !filterModel.Title.IsNull() && filterModel.Title.ValueString() != "" {
			titleValue, negate := parseFilterValue(filterModel.Title.ValueString())
			searchFilter.Title = titleValue
			searchFilter.NegateTitle = negate
		}

		if !filterModel.Manager.IsNull() && filterModel.Manager.ValueString() != "" {
			searchFilter.Manager = filterModel.Manager.ValueString()
		}

		if !filterModel.Company.IsNull() && filterModel.Company.ValueString() != "" {
			companyValue, negate := parseFilterValue(filterModel.Company.ValueString())
			searchFilter.Company = companyValue
			searchFilter.NegateCompany = negate
		}

		if !filterModel.Office.IsNull() && filterModel.Office.ValueString() != "" {
			officeValue, negate := parseFilterValue(filterModel.Office.ValueString())
			searchFilter.Office = officeValue
			searchFilter.NegateOffice = negate
		}

		// Map status filter attributes
		if !filterModel.Enabled.IsNull() {
			enabled := filterModel.Enabled.ValueBool()
			searchFilter.Enabled = &enabled
		}

		// Map email filter attributes
		if !filterModel.HasEmail.IsNull() {
			hasEmail := filterModel.HasEmail.ValueBool()
			searchFilter.HasEmail = &hasEmail
		}

		if !filterModel.EmailDomain.IsNull() && filterModel.EmailDomain.ValueString() != "" {
			searchFilter.EmailDomain = filterModel.EmailDomain.ValueString()
		}

		// Map group membership filter attributes with negation support
		if !filterModel.MemberOf.IsNull() && filterModel.MemberOf.ValueString() != "" {
			memberOfValue, negate := parseFilterValue(filterModel.MemberOf.ValueString())
			searchFilter.MemberOf = memberOfValue
			searchFilter.NegateMemberOf = negate
		}
	}

	return searchFilter, nil
}

// mapUsersToModel converts the LDAP user results to the Terraform model.
func (d *UsersDataSource) mapUsersToModel(ctx context.Context, users []*ldapclient.User, data *UsersDataSourceModel, diags *diag.Diagnostics) {
	// Define the object type for user elements
	userObjectType := types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"id":               types.StringType,
			"dn":               types.StringType,
			"upn":              types.StringType,
			"sam_account_name": types.StringType,
			"name":             types.StringType,
			"display_name":     types.StringType,
			"given_name":       types.StringType,
			"surname":          types.StringType,
			"email_address":    types.StringType,
			"title":            types.StringType,
			"department":       types.StringType,
			"company":          types.StringType,
			"manager":          types.StringType,
			"office":           types.StringType,
			"account_enabled":  types.BoolType,
			"when_created":     types.StringType,
			"last_logon":       types.StringType,
		},
	}

	// Convert each user to a Terraform object
	userElements := make([]attr.Value, len(users))
	for i, user := range users {
		// Handle nullable timestamp for last logon
		lastLogonValue := types.StringNull()
		if user.LastLogon != nil {
			lastLogonValue = types.StringValue(user.LastLogon.Format(time.RFC3339))
		}

		userAttrs := map[string]attr.Value{
			"id":               types.StringValue(user.ObjectGUID),
			"dn":               types.StringValue(user.DistinguishedName),
			"upn":              types.StringValue(user.UserPrincipalName),
			"sam_account_name": types.StringValue(user.SAMAccountName),
			"name":             types.StringValue(user.CommonName),
			"display_name":     types.StringValue(user.DisplayName),
			"given_name":       types.StringValue(user.GivenName),
			"surname":          types.StringValue(user.Surname),
			"email_address":    types.StringValue(user.EmailAddress),
			"title":            types.StringValue(user.Title),
			"department":       types.StringValue(user.Department),
			"company":          types.StringValue(user.Company),
			"manager":          types.StringValue(user.Manager),
			"office":           types.StringValue(user.Office),
			"account_enabled":  types.BoolValue(user.AccountEnabled),
			"when_created":     types.StringValue(user.WhenCreated.Format(time.RFC3339)),
			"last_logon":       lastLogonValue,
		}

		userObj, objDiags := types.ObjectValue(userObjectType.AttrTypes, userAttrs)
		diags.Append(objDiags...)
		if objDiags.HasError() {
			return
		}

		userElements[i] = userObj
	}

	// Create the list of users
	usersList, listDiags := types.ListValue(userObjectType, userElements)
	diags.Append(listDiags...)
	if listDiags.HasError() {
		return
	}

	data.Users = usersList

	tflog.Trace(ctx, "Mapped users data to model", map[string]any{
		"total_users": len(users),
	})
}
