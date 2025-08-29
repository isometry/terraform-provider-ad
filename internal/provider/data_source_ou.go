package provider

import (
	"context"
	"fmt"
	"regexp"
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
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &OUDataSource{}
var _ datasource.DataSourceWithConfigValidators = &OUDataSource{}

func NewOUDataSource() datasource.DataSource {
	return &OUDataSource{}
}

// OUDataSource defines the data source implementation.
type OUDataSource struct {
	client       ldapclient.Client
	cacheManager *ldapclient.CacheManager
	ouManager    *ldapclient.OUManager
}

// OUDataSourceModel describes the data source data model with multiple lookup methods.
type OUDataSourceModel struct {
	// Lookup methods (mutually exclusive)
	ID   types.String `tfsdk:"id"`   // objectGUID lookup
	DN   types.String `tfsdk:"dn"`   // Distinguished Name lookup
	Name types.String `tfsdk:"name"` // Name + Path lookup (both required)
	Path types.String `tfsdk:"path"` // Parent container for name lookup

	// Computed outputs
	Description types.String `tfsdk:"description"` // OU description
	Protected   types.Bool   `tfsdk:"protected"`   // Protection status
	Children    types.List   `tfsdk:"children"`    // Child OU DNs
	ChildCount  types.Int64  `tfsdk:"child_count"` // Number of children
	Parent      types.String `tfsdk:"parent"`      // Parent container DN

	// Timestamps
	WhenCreated types.String `tfsdk:"when_created"` // When the OU was created
	WhenChanged types.String `tfsdk:"when_changed"` // When the OU was last modified
}

func (d *OUDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ou"
}

func (d *OUDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about an Active Directory organizational unit (OU). Supports multiple lookup methods: " +
			"objectGUID, Distinguished Name, or name with parent path.",

		Attributes: map[string]schema.Attribute{
			// Lookup methods (mutually exclusive)
			"id": schema.StringAttribute{
				MarkdownDescription: "The objectGUID of the OU to retrieve. This is the most reliable lookup method " +
					"as objectGUIDs are immutable and unique. Format: `550e8400-e29b-41d4-a716-446655440000`",
				Optional: true,
				Computed: true,
			},
			"dn": schema.StringAttribute{
				MarkdownDescription: "The Distinguished Name of the OU to retrieve. " +
					"Example: `OU=IT,OU=Departments,DC=example,DC=com`",
				Optional: true,
				Computed: true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the OU to retrieve. When using this lookup method, " +
					"the `path` attribute must also be specified to identify the parent container. Example: `IT`",
				Optional: true,
				Computed: true,
			},
			"path": schema.StringAttribute{
				MarkdownDescription: "The parent container DN where the OU is located. Required when using the `name` " +
					"lookup method. Example: `OU=Departments,DC=example,DC=com`",
				Optional: true,
				Validators: []validator.String{
					validators.IsValidDN(),
				},
			},

			// Computed outputs
			"description": schema.StringAttribute{
				MarkdownDescription: "The description of the organizational unit.",
				Computed:            true,
			},
			"protected": schema.BoolAttribute{
				MarkdownDescription: "Whether the OU is protected from accidental deletion.",
				Computed:            true,
			},
			"children": schema.ListAttribute{
				MarkdownDescription: "A list of Distinguished Names of all immediate child OUs.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			"child_count": schema.Int64Attribute{
				MarkdownDescription: "The total number of immediate child OUs.",
				Computed:            true,
			},
			"parent": schema.StringAttribute{
				MarkdownDescription: "The parent container DN of the OU.",
				Computed:            true,
			},

			// Timestamps
			"when_created": schema.StringAttribute{
				MarkdownDescription: "The timestamp when the OU was created (RFC3339 format).",
				Computed:            true,
			},
			"when_changed": schema.StringAttribute{
				MarkdownDescription: "The timestamp when the OU was last modified (RFC3339 format).",
				Computed:            true,
			},
		},
	}
}

// ConfigValidators implements datasource.DataSourceWithConfigValidators.
func (d *OUDataSource) ConfigValidators(ctx context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		// Exactly one lookup method must be specified
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("id"),
			path.MatchRoot("dn"),
			path.MatchRoot("name"),
		),
		// Name and Path must be used together
		datasourcevalidator.RequiredTogether(
			path.MatchRoot("name"),
			path.MatchRoot("path"),
		),
		// Path can only be used with name lookup
		datasourcevalidator.RequiredTogether(
			path.MatchRoot("path"),
			path.MatchRoot("name"),
		),
	}
}

func (d *OUDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

	// Initialize OU manager
	baseDN, err := d.client.GetBaseDN(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Get Base DN",
			fmt.Sprintf("Could not retrieve base DN from LDAP server: %s", err.Error()),
		)
		return
	}
	d.ouManager = ldapclient.NewOUManager(ctx, d.client, baseDN)
}

func (d *OUDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data OUDataSourceModel

	// Initialize logging subsystem for consistent logging
	ctx = initializeLogging(ctx)

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Determine lookup method and retrieve OU
	ou, err := d.retrieveOU(ctx, &data, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading OU",
			fmt.Sprintf("Could not read Active Directory organizational unit: %s", err.Error()),
		)
		return
	}

	if ou == nil {
		resp.Diagnostics.AddError(
			"OU Not Found",
			"The specified Active Directory organizational unit could not be found.",
		)
		return
	}

	// Log the successful retrieval
	tflog.Debug(ctx, "Successfully retrieved AD OU", map[string]any{
		"ou_guid": ou.ObjectGUID,
		"ou_dn":   ou.DistinguishedName,
		"ou_name": ou.Name,
	})

	// Map OU data to model
	d.mapOUToModel(ctx, ou, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// retrieveOU handles the different lookup methods and retrieves the OU.
func (d *OUDataSource) retrieveOU(ctx context.Context, data *OUDataSourceModel, diags *diag.Diagnostics) (*ldapclient.OU, error) {
	// ID (objectGUID) lookup - most reliable
	if !data.ID.IsNull() && data.ID.ValueString() != "" {
		guid := data.ID.ValueString()

		// Validate GUID format
		if !d.isValidGUID(guid) {
			diags.AddError(
				"Invalid GUID Format",
				fmt.Sprintf("The provided GUID '%s' is not in valid format. Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", guid),
			)
			return nil, fmt.Errorf("invalid GUID format: %s", guid)
		}

		tflog.Debug(ctx, "Looking up OU by objectGUID", map[string]any{
			"guid": guid,
		})
		return d.ouManager.GetOU(guid)
	}

	// DN lookup
	if !data.DN.IsNull() && data.DN.ValueString() != "" {
		dn := data.DN.ValueString()
		tflog.Debug(ctx, "Looking up OU by DN", map[string]any{
			"dn": dn,
		})
		return d.ouManager.GetOUByDN(dn)
	}

	// Name + Path lookup
	if !data.Name.IsNull() && data.Name.ValueString() != "" {
		name := data.Name.ValueString()
		path := data.Path.ValueString()

		// Construct the full DN from name and path
		ouDN := fmt.Sprintf("OU=%s,%s", name, path)
		tflog.Debug(ctx, "Looking up OU by name and path", map[string]any{
			"name":    name,
			"path":    path,
			"full_dn": ouDN,
		})
		return d.ouManager.GetOUByDN(ouDN)
	}

	return nil, fmt.Errorf("no valid lookup method provided")
}

// mapOUToModel maps the LDAP OU data to the Terraform model.
func (d *OUDataSource) mapOUToModel(ctx context.Context, ou *ldapclient.OU, data *OUDataSourceModel, diags *diag.Diagnostics) {
	// Set the ID to objectGUID for state tracking
	data.ID = types.StringValue(ou.ObjectGUID)

	// Normalize DN case to ensure uppercase attribute types
	normalizedDN, err := ldapclient.NormalizeDNCase(ou.DistinguishedName)
	if err != nil {
		// Log error but use original DN as fallback
		tflog.Warn(ctx, "Failed to normalize OU DN case", map[string]any{
			"original_dn": ou.DistinguishedName,
			"error":       err.Error(),
		})
		normalizedDN = ou.DistinguishedName
	}
	data.DN = types.StringValue(normalizedDN)

	// Set name from OU data
	data.Name = types.StringValue(ou.Name)

	// Normalize path (parent) DN case
	normalizedPath, err := ldapclient.NormalizeDNCase(ou.Parent)
	if err != nil {
		// Log error but use original path as fallback
		tflog.Warn(ctx, "Failed to normalize path DN case", map[string]any{
			"original_path": ou.Parent,
			"error":         err.Error(),
		})
		normalizedPath = ou.Parent
	}
	data.Path = types.StringValue(normalizedPath)

	// Core OU attributes
	data.Description = types.StringValue(ou.Description)
	data.Protected = types.BoolValue(ou.Protected)
	data.Parent = types.StringValue(normalizedPath) // Already normalized above

	// Get child OUs
	children, err := d.ouManager.GetOUChildren(ctx, ou.DistinguishedName)
	if err != nil {
		tflog.Warn(ctx, "Failed to retrieve child OUs", map[string]any{
			"ou_dn": ou.DistinguishedName,
			"error": err.Error(),
		})
		// Set empty values on error but don't fail the operation
		children = []*ldapclient.OU{}
	}

	// Convert child OUs to a List
	childCount := int64(len(children))
	data.ChildCount = types.Int64Value(childCount)

	if len(children) > 0 {
		childElements := make([]attr.Value, len(children))
		for i, child := range children {
			// Normalize child DN case
			normalizedChildDN, err := ldapclient.NormalizeDNCase(child.DistinguishedName)
			if err != nil {
				// Log error but use original DN as fallback
				tflog.Warn(ctx, "Failed to normalize child OU DN case", map[string]any{
					"original_child_dn": child.DistinguishedName,
					"error":             err.Error(),
				})
				normalizedChildDN = child.DistinguishedName
			}
			childElements[i] = types.StringValue(normalizedChildDN)
		}

		childList, childDiags := types.ListValue(types.StringType, childElements)
		diags.Append(childDiags...)
		if !childDiags.HasError() {
			data.Children = childList
		}
	} else {
		// Empty list for no children
		emptyList, childDiags := types.ListValue(types.StringType, []attr.Value{})
		diags.Append(childDiags...)
		if !childDiags.HasError() {
			data.Children = emptyList
		}
	}

	// Timestamps
	if !ou.WhenCreated.IsZero() {
		data.WhenCreated = types.StringValue(ou.WhenCreated.Format(time.RFC3339))
	} else {
		data.WhenCreated = types.StringNull()
	}

	if !ou.WhenChanged.IsZero() {
		data.WhenChanged = types.StringValue(ou.WhenChanged.Format(time.RFC3339))
	} else {
		data.WhenChanged = types.StringNull()
	}

	tflog.Trace(ctx, "Mapped OU data to model", map[string]any{
		"ou_guid":     ou.ObjectGUID,
		"ou_name":     ou.Name,
		"child_count": childCount,
		"protected":   ou.Protected,
	})
}

// isValidGUID checks if a string is in valid GUID format.
func (d *OUDataSource) isValidGUID(guid string) bool {
	// GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	guidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return guidRegex.MatchString(guid)
}
