package provider

import (
	"context"
	"fmt"

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
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &GroupsDataSource{}

func NewGroupsDataSource() datasource.DataSource {
	return &GroupsDataSource{}
}

// GroupsDataSource defines the data source implementation.
type GroupsDataSource struct {
	client       ldapclient.Client
	groupManager *ldapclient.GroupManager
}

// GroupsDataSourceModel describes the data source data model.
type GroupsDataSourceModel struct {
	// Search configuration
	Container types.String `tfsdk:"container"` // Optional container DN to search within
	Scope     types.String `tfsdk:"scope"`     // Search scope: base, onelevel, subtree (default)
	Filter    types.Object `tfsdk:"filter"`    // Filter block for search criteria

	// Output
	Groups     types.List   `tfsdk:"groups"`      // List of groups found
	GroupCount types.Int64  `tfsdk:"group_count"` // Number of groups found
	ID         types.String `tfsdk:"id"`          // Computed identifier for the data source
}

// GroupFilterModel describes the nested filter block.
type GroupFilterModel struct {
	NamePrefix   types.String `tfsdk:"name_prefix"`   // Groups whose name starts with this string
	NameSuffix   types.String `tfsdk:"name_suffix"`   // Groups whose name ends with this string
	NameContains types.String `tfsdk:"name_contains"` // Groups whose name contains this string
	Category     types.String `tfsdk:"category"`      // security, distribution
	Scope        types.String `tfsdk:"scope"`         // global, domainlocal, universal
	HasMembers   types.Bool   `tfsdk:"has_members"`   // true=groups with members, false=empty groups
}

// GroupDataModel describes a single group in the result set.
type GroupDataModel struct {
	ID                types.String `tfsdk:"id"`                 // objectGUID
	Name              types.String `tfsdk:"name"`               // cn attribute
	DisplayName       types.String `tfsdk:"display_name"`       // displayName (same as cn)
	Description       types.String `tfsdk:"description"`        // description attribute
	DistinguishedName types.String `tfsdk:"distinguished_name"` // full DN
	SAMAccountName    types.String `tfsdk:"sam_account_name"`   // pre-Windows 2000 name
	Scope             types.String `tfsdk:"scope"`              // global, universal, domainlocal
	Category          types.String `tfsdk:"category"`           // security, distribution
	GroupType         types.Int64  `tfsdk:"group_type"`         // raw AD group type
	SID               types.String `tfsdk:"sid"`                // security identifier
	MemberCount       types.Int64  `tfsdk:"member_count"`       // number of members
}

func (d *GroupsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_groups"
}

func (d *GroupsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of Active Directory groups based on search criteria. " +
			"Supports filtering by name patterns, group type, location, and membership status.",

		Attributes: map[string]schema.Attribute{
			// Search configuration
			"container": schema.StringAttribute{
				MarkdownDescription: "The DN of the container to search within. If not specified, searches from the base DN. " +
					"Example: `OU=Groups,DC=example,DC=com`",
				Optional: true,
			},
			"scope": schema.StringAttribute{
				MarkdownDescription: "The search scope to use. Valid values: `base`, `onelevel`, `subtree`. Defaults to `subtree`.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("base", "onelevel", "subtree"),
				},
			},

			// Output attributes
			"group_count": schema.Int64Attribute{
				MarkdownDescription: "The total number of groups found matching the search criteria.",
				Computed:            true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "A computed identifier for this data source instance.",
				Computed:            true,
			},
			"groups": schema.ListNestedAttribute{
				MarkdownDescription: "List of groups matching the search criteria.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The objectGUID of the group.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "The common name (cn) of the group.",
							Computed:            true,
						},
						"display_name": schema.StringAttribute{
							MarkdownDescription: "The display name of the group (equivalent to name).",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "The description of the group.",
							Computed:            true,
						},
						"distinguished_name": schema.StringAttribute{
							MarkdownDescription: "The full Distinguished Name of the group.",
							Computed:            true,
						},
						"sam_account_name": schema.StringAttribute{
							MarkdownDescription: "The SAM account name (pre-Windows 2000 name) of the group.",
							Computed:            true,
						},
						"scope": schema.StringAttribute{
							MarkdownDescription: "The scope of the group (Global, Universal, DomainLocal).",
							Computed:            true,
						},
						"category": schema.StringAttribute{
							MarkdownDescription: "The category of the group (Security, Distribution).",
							Computed:            true,
						},
						"group_type": schema.Int64Attribute{
							MarkdownDescription: "The raw Active Directory groupType value.",
							Computed:            true,
						},
						"sid": schema.StringAttribute{
							MarkdownDescription: "The Security Identifier (SID) of the group.",
							Computed:            true,
						},
						"member_count": schema.Int64Attribute{
							MarkdownDescription: "The total number of members in the group.",
							Computed:            true,
						},
					},
				},
			},
		},

		Blocks: map[string]schema.Block{
			"filter": schema.SingleNestedBlock{
				MarkdownDescription: "Filter criteria for searching groups. All specified criteria must match (AND logic).",
				Attributes: map[string]schema.Attribute{
					"name_prefix": schema.StringAttribute{
						MarkdownDescription: "Groups whose name starts with this string. Case-insensitive.",
						Optional:            true,
					},
					"name_suffix": schema.StringAttribute{
						MarkdownDescription: "Groups whose name ends with this string. Case-insensitive.",
						Optional:            true,
					},
					"name_contains": schema.StringAttribute{
						MarkdownDescription: "Groups whose name contains this string. Case-insensitive.",
						Optional:            true,
					},
					"category": schema.StringAttribute{
						MarkdownDescription: "Filter by group category. Valid values: `security`, `distribution`.",
						Optional:            true,
						Validators: []validator.String{
							stringvalidator.OneOf("security", "distribution"),
						},
					},
					"scope": schema.StringAttribute{
						MarkdownDescription: "Filter by group scope. Valid values: `global`, `domainlocal`, `universal`.",
						Optional:            true,
						Validators: []validator.String{
							stringvalidator.OneOf("global", "domainlocal", "universal"),
						},
					},
					"has_members": schema.BoolAttribute{
						MarkdownDescription: "Filter by membership status. `true` returns only groups with members, " +
							"`false` returns only empty groups. If not specified, returns all groups.",
						Optional: true,
					},
				},
			},
		},
	}
}

func (d *GroupsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

	// Initialize group manager
	baseDN, err := client.GetBaseDN(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Get Base DN",
			fmt.Sprintf("Could not retrieve base DN from LDAP server: %s", err.Error()),
		)
		return
	}
	d.groupManager = ldapclient.NewGroupManager(client, baseDN)
}

func (d *GroupsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data GroupsDataSourceModel

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
	tflog.Debug(ctx, "Searching for AD groups", map[string]interface{}{
		"container":     searchFilter.Container,
		"name_prefix":   searchFilter.NamePrefix,
		"name_suffix":   searchFilter.NameSuffix,
		"name_contains": searchFilter.NameContains,
		"category":      searchFilter.Category,
		"scope":         searchFilter.Scope,
		"has_members":   searchFilter.HasMembers,
	})

	// Perform the search
	groups, err := d.groupManager.SearchGroupsWithFilter(ctx, searchFilter)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Searching Groups",
			fmt.Sprintf("Could not search Active Directory groups: %s", err.Error()),
		)
		return
	}

	tflog.Debug(ctx, "Successfully found AD groups", map[string]interface{}{
		"group_count": len(groups),
	})

	// Convert results to Terraform model
	d.mapGroupsToModel(ctx, groups, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set computed values
	data.GroupCount = types.Int64Value(int64(len(groups)))
	data.ID = types.StringValue(fmt.Sprintf("groups-search-%d", len(groups)))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// buildSearchFilter converts the Terraform configuration to a GroupSearchFilter.
func (d *GroupsDataSource) buildSearchFilter(ctx context.Context, data *GroupsDataSourceModel, diags *diag.Diagnostics) (*ldapclient.GroupSearchFilter, error) {
	searchFilter := &ldapclient.GroupSearchFilter{}

	// Set container if specified
	if !data.Container.IsNull() && data.Container.ValueString() != "" {
		searchFilter.Container = data.Container.ValueString()
	}

	// Parse filter block if present
	if !data.Filter.IsNull() {
		var filterModel GroupFilterModel
		filterDiags := data.Filter.As(ctx, &filterModel, basetypes.ObjectAsOptions{})
		diags.Append(filterDiags...)
		if filterDiags.HasError() {
			return nil, fmt.Errorf("failed to parse filter block")
		}

		// Map filter attributes
		if !filterModel.NamePrefix.IsNull() && filterModel.NamePrefix.ValueString() != "" {
			searchFilter.NamePrefix = filterModel.NamePrefix.ValueString()
		}

		if !filterModel.NameSuffix.IsNull() && filterModel.NameSuffix.ValueString() != "" {
			searchFilter.NameSuffix = filterModel.NameSuffix.ValueString()
		}

		if !filterModel.NameContains.IsNull() && filterModel.NameContains.ValueString() != "" {
			searchFilter.NameContains = filterModel.NameContains.ValueString()
		}

		if !filterModel.Category.IsNull() && filterModel.Category.ValueString() != "" {
			searchFilter.Category = filterModel.Category.ValueString()
		}

		if !filterModel.Scope.IsNull() && filterModel.Scope.ValueString() != "" {
			searchFilter.Scope = filterModel.Scope.ValueString()
		}

		if !filterModel.HasMembers.IsNull() {
			hasMembers := filterModel.HasMembers.ValueBool()
			searchFilter.HasMembers = &hasMembers
		}
	}

	return searchFilter, nil
}

// mapGroupsToModel converts the LDAP group results to the Terraform model.
func (d *GroupsDataSource) mapGroupsToModel(ctx context.Context, groups []*ldapclient.Group, data *GroupsDataSourceModel, diags *diag.Diagnostics) {
	// Define the object type for group elements
	groupObjectType := types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"id":                 types.StringType,
			"name":               types.StringType,
			"display_name":       types.StringType,
			"description":        types.StringType,
			"distinguished_name": types.StringType,
			"sam_account_name":   types.StringType,
			"scope":              types.StringType,
			"category":           types.StringType,
			"group_type":         types.Int64Type,
			"sid":                types.StringType,
			"member_count":       types.Int64Type,
		},
	}

	// Convert each group to a Terraform object
	groupElements := make([]attr.Value, len(groups))
	for i, group := range groups {
		groupAttrs := map[string]attr.Value{
			"id":                 types.StringValue(group.ObjectGUID),
			"name":               types.StringValue(group.Name),
			"display_name":       types.StringValue(group.Name), // Display name is same as name
			"description":        types.StringValue(group.Description),
			"distinguished_name": types.StringValue(group.DistinguishedName),
			"sam_account_name":   types.StringValue(group.SAMAccountName),
			"scope":              types.StringValue(string(group.Scope)),
			"category":           types.StringValue(string(group.Category)),
			"group_type":         types.Int64Value(int64(group.GroupType)),
			"sid":                types.StringValue(group.ObjectSid),
			"member_count":       types.Int64Value(int64(len(group.MemberDNs))),
		}

		groupObj, objDiags := types.ObjectValue(groupObjectType.AttrTypes, groupAttrs)
		diags.Append(objDiags...)
		if objDiags.HasError() {
			return
		}

		groupElements[i] = groupObj
	}

	// Create the list of groups
	groupsList, listDiags := types.ListValue(groupObjectType, groupElements)
	diags.Append(listDiags...)
	if listDiags.HasError() {
		return
	}

	data.Groups = groupsList

	tflog.Trace(ctx, "Mapped groups data to model", map[string]interface{}{
		"total_groups": len(groups),
	})
}
