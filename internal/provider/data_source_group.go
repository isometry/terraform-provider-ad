package provider

import (
	"context"
	"fmt"

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
var _ datasource.DataSource = &GroupDataSource{}
var _ datasource.DataSourceWithConfigValidators = &GroupDataSource{}

func NewGroupDataSource() datasource.DataSource {
	return &GroupDataSource{}
}

// GroupDataSource defines the data source implementation.
type GroupDataSource struct {
	client       ldapclient.Client
	groupManager *ldapclient.GroupManager
}

// GroupDataSourceModel describes the data source data model with multiple lookup methods.
type GroupDataSourceModel struct {
	// Lookup methods (mutually exclusive)
	ID                types.String `tfsdk:"id"`               // objectGUID lookup
	DistinguishedName types.String `tfsdk:"dn"`               // Distinguished Name lookup
	Name              types.String `tfsdk:"name"`             // Common name lookup (requires container)
	SAMAccountName    types.String `tfsdk:"sam_account_name"` // SAM account name lookup

	// Optional container for name-based lookups
	Container types.String `tfsdk:"container"` // Container DN for name lookup

	// Group attributes (all computed)
	DisplayName types.String `tfsdk:"display_name"` // Display name (computed from cn)
	Description types.String `tfsdk:"description"`  // Description
	Scope       types.String `tfsdk:"scope"`        // Global/Universal/DomainLocal
	Category    types.String `tfsdk:"category"`     // Security/Distribution
	GroupType   types.Int64  `tfsdk:"group_type"`   // Raw AD group type
	SID         types.String `tfsdk:"sid"`          // Security Identifier

	// Member information
	Members     types.Set   `tfsdk:"members"`      // Set of member DNs
	MemberCount types.Int64 `tfsdk:"member_count"` // Total member count
}

func (d *GroupDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (d *GroupDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about an Active Directory group. Supports multiple lookup methods: " +
			"objectGUID, Distinguished Name, common name with container, or SAM account name.",

		Attributes: map[string]schema.Attribute{
			// Lookup methods (mutually exclusive)
			"id": schema.StringAttribute{
				MarkdownDescription: "The objectGUID of the group to retrieve. This is the most reliable lookup method " +
					"as objectGUIDs are immutable and unique. Format: `550e8400-e29b-41d4-a716-446655440000`",
				Optional: true,
				Computed: true,
			},
			"dn": schema.StringAttribute{
				MarkdownDescription: "The Distinguished Name of the group to retrieve. " +
					"Example: `CN=Domain Admins,CN=Users,DC=example,DC=com`",
				Optional: true,
				Computed: true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The common name (cn) of the group to retrieve. When using this lookup method, " +
					"the `container` attribute must also be specified to avoid ambiguity. Example: `Domain Admins`",
				Optional: true,
				Computed: true,
			},
			"sam_account_name": schema.StringAttribute{
				MarkdownDescription: "The SAM account name (pre-Windows 2000 name) of the group to retrieve. " +
					"This performs a domain-wide search. Example: `Domain Admins`",
				Optional: true,
				Computed: true,
			},

			// Optional container for name-based lookups
			"container": schema.StringAttribute{
				MarkdownDescription: "The container DN where the group is located. Required when using the `name` " +
					"lookup method. Example: `CN=Users,DC=example,DC=com`",
				Optional: true,
			},

			// Group attributes (all computed)
			"display_name": schema.StringAttribute{
				MarkdownDescription: "The display name of the group (equivalent to common name).",
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "The description of the group.",
				Computed:            true,
			},
			"scope": schema.StringAttribute{
				MarkdownDescription: "The scope of the group. Valid values: `Global`, `Universal`, `DomainLocal`.",
				Computed:            true,
			},
			"category": schema.StringAttribute{
				MarkdownDescription: "The category of the group. Valid values: `Security`, `Distribution`.",
				Computed:            true,
			},
			"group_type": schema.Int64Attribute{
				MarkdownDescription: "The raw Active Directory groupType value as an integer.",
				Computed:            true,
			},
			"sid": schema.StringAttribute{
				MarkdownDescription: "The Security Identifier (SID) of the group.",
				Computed:            true,
			},

			// Member information
			"members": schema.SetAttribute{
				MarkdownDescription: "A set of Distinguished Names of all group members. Includes users, groups, and other objects.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			"member_count": schema.Int64Attribute{
				MarkdownDescription: "The total number of members in the group.",
				Computed:            true,
			},
		},
	}
}

// ConfigValidators implements datasource.DataSourceWithConfigValidators.
func (d *GroupDataSource) ConfigValidators(ctx context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		// Exactly one lookup method must be specified
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("id"),
			path.MatchRoot("dn"),
			path.MatchRoot("name"),
			path.MatchRoot("sam_account_name"),
		),
		// Container is required when using name lookup
		datasourcevalidator.RequiredTogether(
			path.MatchRoot("name"),
			path.MatchRoot("container"),
		),
		// Container can only be used with name lookup
		datasourcevalidator.RequiredTogether(
			path.MatchRoot("container"),
			path.MatchRoot("name"),
		),
	}
}

func (d *GroupDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *GroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data GroupDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Determine lookup method and retrieve group
	group, err := d.retrieveGroup(ctx, &data, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Group",
			fmt.Sprintf("Could not read Active Directory group: %s", err.Error()),
		)
		return
	}

	if group == nil {
		resp.Diagnostics.AddError(
			"Group Not Found",
			"The specified Active Directory group could not be found.",
		)
		return
	}

	// Log the successful retrieval
	tflog.Debug(ctx, "Successfully retrieved AD group", map[string]any{
		"group_guid": group.ObjectGUID,
		"group_dn":   group.DistinguishedName,
		"group_name": group.Name,
	})

	// Map group data to model
	d.mapGroupToModel(ctx, group, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// retrieveGroup handles the different lookup methods and retrieves the group.
func (d *GroupDataSource) retrieveGroup(ctx context.Context, data *GroupDataSourceModel, diags *diag.Diagnostics) (*ldapclient.Group, error) {
	// ID (objectGUID) lookup - most reliable
	if !data.ID.IsNull() && data.ID.ValueString() != "" {
		guid := data.ID.ValueString()
		tflog.Debug(ctx, "Looking up group by objectGUID", map[string]any{
			"guid": guid,
		})
		return d.groupManager.GetGroup(ctx, guid)
	}

	// DN lookup
	if !data.DistinguishedName.IsNull() && data.DistinguishedName.ValueString() != "" {
		dn := data.DistinguishedName.ValueString()
		tflog.Debug(ctx, "Looking up group by DN", map[string]any{
			"dn": dn,
		})
		return d.groupManager.GetGroupByDN(ctx, dn)
	}

	// Name + Container lookup
	if !data.Name.IsNull() && data.Name.ValueString() != "" {
		name := data.Name.ValueString()
		container := data.Container.ValueString()

		// Construct the full DN from name and container
		groupDN := fmt.Sprintf("CN=%s,%s", name, container)
		tflog.Debug(ctx, "Looking up group by name in container", map[string]any{
			"name":      name,
			"container": container,
			"full_dn":   groupDN,
		})
		return d.groupManager.GetGroupByDN(ctx, groupDN)
	}

	// SAM account name lookup - requires search
	if !data.SAMAccountName.IsNull() && data.SAMAccountName.ValueString() != "" {
		samAccountName := data.SAMAccountName.ValueString()
		tflog.Debug(ctx, "Looking up group by SAM account name", map[string]any{
			"sam_account_name": samAccountName,
		})

		// Use search to find group by SAM account name
		filter := fmt.Sprintf("(sAMAccountName=%s)", samAccountName)
		groups, err := d.groupManager.SearchGroups(ctx, filter, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to search for group by SAM account name: %w", err)
		}

		if len(groups) == 0 {
			return nil, fmt.Errorf("no group found with SAM account name: %s", samAccountName)
		}

		if len(groups) > 1 {
			diags.AddWarning(
				"Multiple Groups Found",
				fmt.Sprintf("Multiple groups found with SAM account name '%s'. Using the first match: %s",
					samAccountName, groups[0].DistinguishedName),
			)
		}

		return groups[0], nil
	}

	return nil, fmt.Errorf("no valid lookup method provided")
}

// mapGroupToModel maps the LDAP group data to the Terraform model.
func (d *GroupDataSource) mapGroupToModel(ctx context.Context, group *ldapclient.Group, data *GroupDataSourceModel, diags *diag.Diagnostics) {
	// Set the ID to objectGUID for state tracking
	data.ID = types.StringValue(group.ObjectGUID)

	// Populate lookup fields that can be referenced by other configurations
	data.Name = types.StringValue(group.Name)
	data.SAMAccountName = types.StringValue(group.SAMAccountName)

	// Core group attributes
	data.DisplayName = types.StringValue(group.Name)
	data.Description = types.StringValue(group.Description)
	data.Scope = types.StringValue(string(group.Scope))
	data.Category = types.StringValue(string(group.Category))
	data.GroupType = types.Int64Value(int64(group.GroupType))
	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := ldapclient.NormalizeDNCase(group.DistinguishedName)
	if err != nil {
		// Log error but use original DN as fallback
		tflog.Warn(ctx, "Failed to normalize group DN case", map[string]any{
			"original_dn": group.DistinguishedName,
			"error":       err.Error(),
		})
		normalizedDN = group.DistinguishedName
	}
	data.DistinguishedName = types.StringValue(normalizedDN)
	data.SID = types.StringValue(group.ObjectSid)

	// Members information
	memberCount := int64(len(group.MemberDNs))
	data.MemberCount = types.Int64Value(memberCount)

	// Convert member DNs to a Set, normalizing DN case
	if len(group.MemberDNs) > 0 {
		memberElements := make([]attr.Value, len(group.MemberDNs))
		for i, memberDN := range group.MemberDNs {
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

		memberSet, memberDiags := types.SetValue(types.StringType, memberElements)
		diags.Append(memberDiags...)
		if !memberDiags.HasError() {
			data.Members = memberSet
		}
	} else {
		// Empty set for no members
		emptySet, memberDiags := types.SetValue(types.StringType, []attr.Value{})
		diags.Append(memberDiags...)
		if !memberDiags.HasError() {
			data.Members = emptySet
		}
	}

	tflog.Trace(ctx, "Mapped group data to model", map[string]any{
		"group_guid":   group.ObjectGUID,
		"group_name":   group.Name,
		"member_count": memberCount,
		"scope":        group.Scope,
		"category":     group.Category,
	})
}
