package provider

import (
	"context"
	"fmt"

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
	client ldapclient.Client
}

// WhoAmIDataSourceModel describes the data source data model.
type WhoAmIDataSourceModel struct {
	ID                types.String `tfsdk:"id"`               // Set to authz_id for state tracking
	AuthzID           types.String `tfsdk:"authz_id"`         // Raw authorization ID from server
	DN                types.String `tfsdk:"dn"`               // Distinguished Name (if authzID is in DN format)
	UserPrincipalName types.String `tfsdk:"upn"`              // User Principal Name (if authzID is in UPN format)
	SAMAccountName    types.String `tfsdk:"sam_account_name"` // SAM Account Name (if authzID is in SAM format)
	SID               types.String `tfsdk:"sid"`              // Security Identifier (if authzID is in SID format)
	Format            types.String `tfsdk:"format"`           // Format of the authzID: "dn", "upn", "sam", "sid", "empty", or "unknown"
}

func (d *WhoAmIDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_whoami"
}

func (d *WhoAmIDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about the authenticated identity using the LDAP \"Who Am I?\" extended operation (RFC 4532). " +
			"This data source requires no configuration and returns the authorization identity the Active Directory server has associated with the current connection.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Unique identifier for this data source (same as authz_id).",
				Computed:            true,
			},
			"authz_id": schema.StringAttribute{
				MarkdownDescription: "The raw authorization ID returned by the server. This may include a prefix like 'u:' followed by the identity " +
					"in various formats such as DN, UPN, SAM account name, or SID.",
				Computed: true,
			},
			"dn": schema.StringAttribute{
				MarkdownDescription: "The Distinguished Name of the authenticated user, populated when the authorization ID is in DN format. " +
					"Example: `CN=John Doe,CN=Users,DC=example,DC=com`",
				Computed: true,
			},
			"upn": schema.StringAttribute{
				MarkdownDescription: "The User Principal Name of the authenticated user, populated when the authorization ID is in UPN format. " +
					"Example: `john.doe@example.com`",
				Computed: true,
			},
			"sam_account_name": schema.StringAttribute{
				MarkdownDescription: "The SAM account name of the authenticated user, populated when the authorization ID is in SAM format. " +
					"Example: `DOMAIN\\jdoe`",
				Computed: true,
			},
			"sid": schema.StringAttribute{
				MarkdownDescription: "The Security Identifier (SID) of the authenticated user, populated when the authorization ID is in SID format. " +
					"Example: `S-1-5-21-123456789-123456789-123456789-1001`",
				Computed: true,
			},
			"format": schema.StringAttribute{
				MarkdownDescription: "The format of the authorization ID. Possible values: `dn` (Distinguished Name), `upn` (User Principal Name), " +
					"`sam` (SAM Account Name), `sid` (Security Identifier), `empty` (no authorization ID), or `unknown` (unrecognized format).",
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

	client, ok := req.ProviderData.(ldapclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected ldapclient.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

func (d *WhoAmIDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data WhoAmIDataSourceModel

	// Set up entry/exit logging
	logCompletion := ldapclient.LogDataSourceOperation(ctx, "ad_whoami", "read", nil)
	defer func() {
		var err error
		if resp.Diagnostics.HasError() {
			// Get first error for logging
			for _, diag := range resp.Diagnostics.Errors() {
				err = fmt.Errorf("%s: %s", diag.Summary(), diag.Detail())
				break
			}
		}
		logCompletion(err)
	}()

	// The WhoAmI data source doesn't require any input configuration
	// Read Terraform configuration data into the model (should be empty)
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

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
		"format":   result.Format,
	})

	// Map result to model
	d.mapResultToModel(result, &data)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// mapResultToModel maps the LDAP WhoAmI result to the Terraform model.
func (d *WhoAmIDataSource) mapResultToModel(result *ldapclient.WhoAmIResult, data *WhoAmIDataSourceModel) {
	// Set ID to the authz_id for state tracking
	data.ID = types.StringValue(result.AuthzID)

	// Set the raw authorization ID
	data.AuthzID = types.StringValue(result.AuthzID)

	// Set the format
	data.Format = types.StringValue(result.Format)

	// Set parsed fields based on format
	if result.DN != "" {
		data.DN = types.StringValue(result.DN)
	} else {
		data.DN = types.StringNull()
	}

	if result.UserPrincipalName != "" {
		data.UserPrincipalName = types.StringValue(result.UserPrincipalName)
	} else {
		data.UserPrincipalName = types.StringNull()
	}

	if result.SAMAccountName != "" {
		data.SAMAccountName = types.StringValue(result.SAMAccountName)
	} else {
		data.SAMAccountName = types.StringNull()
	}

	if result.SID != "" {
		data.SID = types.StringValue(result.SID)
	} else {
		data.SID = types.StringNull()
	}
}
