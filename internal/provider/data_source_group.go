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
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	"github.com/isometry/terraform-provider-ad/internal/provider/validators"
	"github.com/isometry/terraform-provider-ad/internal/utils"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &GroupDataSource{}
var _ datasource.DataSourceWithConfigValidators = &GroupDataSource{}

// NewGroupDataSource creates a new instance of the group data source.
func NewGroupDataSource() datasource.DataSource {
	return &GroupDataSource{}
}

// GroupDataSource defines the data source implementation.
type GroupDataSource struct {
	client       ldapclient.Client
	cacheManager *ldapclient.CacheManager
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

	// Member flattening option
	FlattenMembers types.Bool `tfsdk:"flatten_members"` // If true, return flattened list of users only

	// Group attributes (all computed)
	DisplayName types.String `tfsdk:"display_name"` // Display name (computed from cn)
	Description types.String `tfsdk:"description"`  // Description
	Scope       types.String `tfsdk:"scope"`        // Global/Universal/DomainLocal
	Category    types.String `tfsdk:"category"`     // Security/Distribution
	SID         types.String `tfsdk:"sid"`          // Security Identifier
	ManagedBy   types.String `tfsdk:"managed_by"`   // ManagedBy DN

	// Member information
	Members     types.Set   `tfsdk:"members"`      // Set of member DNs
	MemberCount types.Int64 `tfsdk:"member_count"` // Total member count
	MemberOf    types.Set   `tfsdk:"member_of"`    // Set of group DNs this group is a member of

	// Email information
	Mail         types.String `tfsdk:"mail"`          // Email address for distribution groups
	MailNickname types.String `tfsdk:"mail_nickname"` // Exchange mail nickname

	// Timestamps
	WhenCreated types.String `tfsdk:"when_created"` // When the group was created
	WhenChanged types.String `tfsdk:"when_changed"` // When the group was last modified
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
				Validators: []validator.String{
					validators.IsValidDN(),
				},
			},

			// Member flattening option
			"flatten_members": schema.BoolAttribute{
				MarkdownDescription: "If set to true, returns a flattened list of users only (excludes groups) from " +
					"recursive group membership. This traverses nested group membership to return all user members. " +
					"When false or unset, the `members` attribute contains direct members only (users and groups).",
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
			"sid": schema.StringAttribute{
				MarkdownDescription: "The Security Identifier (SID) of the group.",
				Computed:            true,
			},
			"managed_by": schema.StringAttribute{
				MarkdownDescription: "Distinguished Name (DN) of the user or computer that manages this group.",
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
			"member_of": schema.SetAttribute{
				MarkdownDescription: "A set of Distinguished Names of groups that this group is a member of. This represents nested group membership.",
				ElementType:         types.StringType,
				Computed:            true,
			},

			// Email information
			"mail": schema.StringAttribute{
				MarkdownDescription: "The email address for distribution groups.",
				Computed:            true,
			},
			"mail_nickname": schema.StringAttribute{
				MarkdownDescription: "The Exchange mail nickname for distribution groups.",
				Computed:            true,
			},

			// Timestamps
			"when_created": schema.StringAttribute{
				MarkdownDescription: "The timestamp when the group was created (RFC3339 format).",
				Computed:            true,
			},
			"when_changed": schema.StringAttribute{
				MarkdownDescription: "The timestamp when the group was last modified (RFC3339 format).",
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

	// Initialize group manager
	baseDN, err := d.client.GetBaseDN(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Get Base DN",
			fmt.Sprintf("Could not retrieve base DN from LDAP server: %s", err.Error()),
		)
		return
	}
	d.groupManager = ldapclient.NewGroupManager(ctx, d.client, baseDN, d.cacheManager)
}

func (d *GroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data GroupDataSourceModel

	// Initialize logging subsystem for consistent logging
	ctx = utils.InitializeLogging(ctx)

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
		return d.groupManager.GetGroup(guid)
	}

	// DN lookup
	if !data.DistinguishedName.IsNull() && data.DistinguishedName.ValueString() != "" {
		dn := data.DistinguishedName.ValueString()
		tflog.Debug(ctx, "Looking up group by DN", map[string]any{
			"dn": dn,
		})
		return d.groupManager.GetGroupByDN(dn)
	}

	// Name + Container lookup
	if !data.Name.IsNull() && data.Name.ValueString() != "" {
		name := data.Name.ValueString()
		container := data.Container.ValueString()

		// Escape the name value for DN construction per RFC 4514
		// This handles special characters like commas, quotes, angle brackets, etc.
		escapedName := ldapclient.EscapeDNValue(name)

		// Construct the full DN from name and container
		groupDN := fmt.Sprintf("CN=%s,%s", escapedName, container)
		tflog.Debug(ctx, "Looking up group by name in container", map[string]any{
			"name":         name,
			"escaped_name": escapedName,
			"container":    container,
			"full_dn":      groupDN,
		})

		group, err := d.groupManager.GetGroupByDN(groupDN)
		if err != nil {
			// Enhance error with troubleshooting guidance
			return nil, fmt.Errorf("failed to find group '%s' in container '%s': %w\n\n"+
				"Troubleshooting:\n"+
				"  • Verify the group name is correct (CN attribute in AD)\n"+
				"  • Check if you should use 'sam_account_name' instead of 'name'\n"+
				"  • Confirm the container DN is accurate\n"+
				"  • Check if the group is in a nested OU (e.g., OU=Groups,%s)\n"+
				"  • Try using 'id' (GUID) or 'dn' lookup instead\n"+
				"  • Verify the group exists: Get-ADGroup -Filter \"Name -eq '%s'\"",
				name, container, err, container, name)
		}
		return group, nil
	}

	// SAM account name lookup - requires search
	if !data.SAMAccountName.IsNull() && data.SAMAccountName.ValueString() != "" {
		samAccountName := data.SAMAccountName.ValueString()
		tflog.Debug(ctx, "Looking up group by SAM account name", map[string]any{
			"sam_account_name": samAccountName,
		})

		// Use search to find group by SAM account name
		filter := fmt.Sprintf("(sAMAccountName=%s)", samAccountName)
		groups, err := d.groupManager.SearchGroups(filter, nil)
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

	// ManagedBy information
	if group.ManagedBy != "" {
		// Normalize managedBy DN case
		normalizedManagedBy, err := ldapclient.NormalizeDNCase(group.ManagedBy)
		if err != nil {
			// Log error but use original DN as fallback
			tflog.Warn(ctx, "Failed to normalize managedBy DN case", map[string]any{
				"original_managed_by": group.ManagedBy,
				"error":               err.Error(),
			})
			normalizedManagedBy = group.ManagedBy
		}
		data.ManagedBy = types.StringValue(normalizedManagedBy)
	} else {
		data.ManagedBy = types.StringNull()
	}

	// Members information
	var memberDNs []string
	var memberCount int64

	// Check if we should flatten members to users only
	if !data.FlattenMembers.IsNull() && data.FlattenMembers.ValueBool() {
		// Get flattened user members
		flattenedUsers, err := d.groupManager.GetFlattenedUserMembers(group.ObjectGUID)
		if err != nil {
			tflog.Warn(ctx, "Failed to get flattened user members", map[string]any{
				"group_guid": group.ObjectGUID,
				"error":      err.Error(),
			})
			// Fall back to regular members
			memberDNs = group.MemberDNs
		} else {
			memberDNs = flattenedUsers
		}
	} else {
		// Use regular direct members
		memberDNs = group.MemberDNs
	}

	memberCount = int64(len(memberDNs))
	data.MemberCount = types.Int64Value(memberCount)

	// Convert member DNs to a Set, normalizing DN case
	if len(memberDNs) > 0 {
		memberElements := make([]attr.Value, len(memberDNs))
		for i, memberDN := range memberDNs {
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

	// Convert memberOf DNs to a Set, normalizing DN case
	if len(group.MemberOf) > 0 {
		memberOfElements := make([]attr.Value, len(group.MemberOf))
		for i, memberOfDN := range group.MemberOf {
			// Normalize member of DN case
			normalizedMemberOfDN, err := ldapclient.NormalizeDNCase(memberOfDN)
			if err != nil {
				// Log error but use original DN as fallback
				tflog.Warn(ctx, "Failed to normalize member of DN case", map[string]any{
					"original_member_of_dn": memberOfDN,
					"error":                 err.Error(),
				})
				normalizedMemberOfDN = memberOfDN
			}
			memberOfElements[i] = types.StringValue(normalizedMemberOfDN)
		}

		memberOfSet, memberOfDiags := types.SetValue(types.StringType, memberOfElements)
		diags.Append(memberOfDiags...)
		if !memberOfDiags.HasError() {
			data.MemberOf = memberOfSet
		}
	} else {
		// Empty set for no member of
		emptySet, memberOfDiags := types.SetValue(types.StringType, []attr.Value{})
		diags.Append(memberOfDiags...)
		if !memberOfDiags.HasError() {
			data.MemberOf = emptySet
		}
	}

	// Email information
	data.Mail = types.StringValue(group.Mail)
	data.MailNickname = types.StringValue(group.MailNickname)

	// Timestamps
	if !group.WhenCreated.IsZero() {
		data.WhenCreated = types.StringValue(group.WhenCreated.Format(time.RFC3339))
	} else {
		data.WhenCreated = types.StringNull()
	}

	if !group.WhenChanged.IsZero() {
		data.WhenChanged = types.StringValue(group.WhenChanged.Format(time.RFC3339))
	} else {
		data.WhenChanged = types.StringNull()
	}

	tflog.Trace(ctx, "Mapped group data to model", map[string]any{
		"group_guid":      group.ObjectGUID,
		"group_name":      group.Name,
		"member_count":    memberCount,
		"member_of_count": len(group.MemberOf),
		"scope":           group.Scope,
		"category":        group.Category,
	})
}
