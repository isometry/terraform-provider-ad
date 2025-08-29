package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &WhoAmIDataSource{}

func NewWhoAmIDataSource() datasource.DataSource {
	return &WhoAmIDataSource{}
}

// WhoAmIDataSource defines the data source implementation.
type WhoAmIDataSource struct {
	client       ldapclient.Client
	cacheManager *ldapclient.CacheManager
}

// WhoAmIDataSourceModel describes the data source data model.
type WhoAmIDataSourceModel struct {
	// ID      types.String `tfsdk:"id"`       // Set to authz_id for state tracking
	ID types.String `tfsdk:"id"` // Raw authorization ID from server
}

func (d *WhoAmIDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_whoami"
}

func (d *WhoAmIDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about the authenticated identity using the LDAP \"Who Am I?\" extended operation (RFC 4532). " +
			"This data source requires no configuration and returns the raw authorization identity the Active Directory server has associated with the current connection.",

		Attributes: map[string]schema.Attribute{
			// "id": schema.StringAttribute{
			// 	MarkdownDescription: "Unique identifier for this data source (same as authz_id).",
			// 	Computed:            true,
			// },
			"id": schema.StringAttribute{
				MarkdownDescription: "The raw authorization ID returned by the server. This may include a prefix like 'u:' followed by the identity " +
					"in various formats such as DN, UPN, SAM account name, or SID.",
				Computed: true,
			},
		},
	}
}

func (d *WhoAmIDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
}

func (d *WhoAmIDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data WhoAmIDataSourceModel

	// Initialize logging subsystem for consistent logging
	ctx = initializeLogging(ctx)

	// Set up entry/exit logging
	start := time.Now()
	tflog.Debug(ctx, "Starting data source operation", map[string]any{
		"operation":   "read",
		"data_source": "ad_whoami",
	})
	defer func() {
		duration := time.Since(start)
		if resp.Diagnostics.HasError() {
			tflog.Error(ctx, "Data source operation failed", map[string]any{
				"operation":   "read",
				"data_source": "ad_whoami",
				"duration_ms": duration.Milliseconds(),
			})
		} else {
			tflog.Info(ctx, "Data source operation completed", map[string]any{
				"operation":   "read",
				"data_source": "ad_whoami",
				"duration_ms": duration.Milliseconds(),
			})
		}
	}()

	// The WhoAmI data source doesn't require any input configuration
	// All attributes are computed, so we don't need to read from config

	// Perform the Who Am I? operation
	result, err := d.client.WhoAmI(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Performing WhoAmI Operation",
			fmt.Sprintf("Could not perform LDAP Who Am I? operation: %s", err.Error()),
		)
		return
	}

	if result == nil {
		resp.Diagnostics.AddError(
			"WhoAmI Operation Returned Nil",
			"The LDAP Who Am I? operation returned a nil result, which should not happen. Please report this issue to the provider developers.",
		)
		return
	}

	// Log the successful operation
	tflog.Debug(ctx, "Successfully performed WhoAmI operation", map[string]any{
		"authz_id": result.AuthzID,
	})

	// Map result to model
	d.mapResultToModel(result, &data)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// mapResultToModel maps the LDAP WhoAmI result to the Terraform model.
func (d *WhoAmIDataSource) mapResultToModel(result *ldapclient.WhoAmIResult, data *WhoAmIDataSourceModel) {
	// Set ID to the authz_id for state tracking
	// data.ID = types.StringValue(result.AuthzID)

	// Set the raw authorization ID
	data.ID = types.StringValue(result.AuthzID)
}
