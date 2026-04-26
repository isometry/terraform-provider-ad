package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	"github.com/isometry/terraform-provider-ad/internal/provider/helpers"
	"github.com/isometry/terraform-provider-ad/internal/utils"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &RootDSEDataSource{}

func NewRootDSEDataSource() datasource.DataSource {
	return &RootDSEDataSource{}
}

// RootDSEDataSource defines the data source implementation.
type RootDSEDataSource struct {
	client ldapclient.Client
}

// RootDSEDataSourceModel describes the data source data model.
type RootDSEDataSourceModel struct {
	ID                            types.String `tfsdk:"id"`
	DefaultNamingContext          types.String `tfsdk:"default_naming_context"`
	ConfigurationNamingContext    types.String `tfsdk:"configuration_naming_context"`
	SchemaNamingContext           types.String `tfsdk:"schema_naming_context"`
	RootDomainNamingContext       types.String `tfsdk:"root_domain_naming_context"`
	DomainName                    types.String `tfsdk:"domain_name"`
	DNSHostName                   types.String `tfsdk:"dns_host_name"`
	ServerName                    types.String `tfsdk:"server_name"`
	LDAPServiceName               types.String `tfsdk:"ldap_service_name"`
	DomainFunctionality           types.Int64  `tfsdk:"domain_functionality"`
	ForestFunctionality           types.Int64  `tfsdk:"forest_functionality"`
	DomainControllerFunctionality types.Int64  `tfsdk:"domain_controller_functionality"`
	SupportedLDAPVersions         types.List   `tfsdk:"supported_ldap_versions"`
	SupportedSASLMechanisms       types.List   `tfsdk:"supported_sasl_mechanisms"`
	IsGlobalCatalogReady          types.Bool   `tfsdk:"is_global_catalog_ready"`
	IsSynchronized                types.Bool   `tfsdk:"is_synchronized"`
	Forest                        types.Object `tfsdk:"forest"`
}

// ForestModel describes the nested forest configuration block.
type ForestModel struct {
	Name             types.String `tfsdk:"name"`
	DefaultUPNSuffix types.String `tfsdk:"default_upn_suffix"`
	UPNSuffixes      types.List   `tfsdk:"upn_suffixes"`
	AllUPNSuffixes   types.List   `tfsdk:"all_upn_suffixes"`
	SPNSuffixes      types.List   `tfsdk:"spn_suffixes"`
}

// forestAttrTypes defines the attribute types for the forest nested object.
var forestAttrTypes = map[string]attr.Type{
	"name":               types.StringType,
	"default_upn_suffix": types.StringType,
	"upn_suffixes":       types.ListType{ElemType: types.StringType},
	"all_upn_suffixes":   types.ListType{ElemType: types.StringType},
	"spn_suffixes":       types.ListType{ElemType: types.StringType},
}

func (d *RootDSEDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rootdse"
}

func (d *RootDSEDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves Active Directory RootDSE attributes and forest configuration from the connected domain controller. " +
			"This data source requires no configuration and returns server identity, naming contexts, functional levels, " +
			"capabilities, and forest-level principal name suffix configuration.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Unique identifier for this data source (same as `dns_host_name`).",
				Computed:            true,
			},

			// Naming contexts
			"default_naming_context": schema.StringAttribute{
				MarkdownDescription: "The default naming context (base DN) for the domain, e.g. `DC=example,DC=com`.",
				Computed:            true,
			},
			"configuration_naming_context": schema.StringAttribute{
				MarkdownDescription: "The distinguished name of the Configuration partition.",
				Computed:            true,
			},
			"schema_naming_context": schema.StringAttribute{
				MarkdownDescription: "The distinguished name of the Schema partition.",
				Computed:            true,
			},
			"root_domain_naming_context": schema.StringAttribute{
				MarkdownDescription: "The distinguished name of the forest root domain.",
				Computed:            true,
			},
			"domain_name": schema.StringAttribute{
				MarkdownDescription: "The DNS domain name derived from the default naming context, e.g. `example.com`.",
				Computed:            true,
			},

			// Server identity
			"dns_host_name": schema.StringAttribute{
				MarkdownDescription: "The fully qualified DNS hostname of the connected domain controller.",
				Computed:            true,
			},
			"server_name": schema.StringAttribute{
				MarkdownDescription: "The distinguished name of the domain controller's server object in the Configuration partition.",
				Computed:            true,
			},
			"ldap_service_name": schema.StringAttribute{
				MarkdownDescription: "The Kerberos service principal name (SPN) of the LDAP service.",
				Computed:            true,
			},

			// Functional levels
			"domain_functionality": schema.Int64Attribute{
				MarkdownDescription: "The domain functional level. Common values: 0 (2000), 1 (2003 interim), 2 (2003), 3 (2008), 4 (2008 R2), 5 (2012), 6 (2012 R2), 7 (2016).",
				Computed:            true,
			},
			"forest_functionality": schema.Int64Attribute{
				MarkdownDescription: "The forest functional level.",
				Computed:            true,
			},
			"domain_controller_functionality": schema.Int64Attribute{
				MarkdownDescription: "The domain controller functional level.",
				Computed:            true,
			},

			// Capabilities
			"supported_ldap_versions": schema.ListAttribute{
				MarkdownDescription: "The LDAP protocol versions supported by the server.",
				Computed:            true,
				ElementType:         types.Int64Type,
			},
			"supported_sasl_mechanisms": schema.ListAttribute{
				MarkdownDescription: "The SASL authentication mechanisms supported by the server.",
				Computed:            true,
				ElementType:         types.StringType,
			},

			// Status
			"is_global_catalog_ready": schema.BoolAttribute{
				MarkdownDescription: "Whether the domain controller is advertising as a Global Catalog server.",
				Computed:            true,
			},
			"is_synchronized": schema.BoolAttribute{
				MarkdownDescription: "Whether the domain controller has completed initial replication synchronization.",
				Computed:            true,
			},

			// Forest configuration (nested)
			"forest": schema.SingleNestedAttribute{
				MarkdownDescription: "Forest-level configuration retrieved from the Configuration partition's Partitions container.",
				Computed:            true,
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						MarkdownDescription: "The DNS name of the Active Directory forest.",
						Computed:            true,
					},
					"default_upn_suffix": schema.StringAttribute{
						MarkdownDescription: "The default User Principal Name suffix for the domain (same as `domain_name`).",
						Computed:            true,
					},
					"upn_suffixes": schema.ListAttribute{
						MarkdownDescription: "Additional User Principal Name suffixes configured in the forest.",
						Computed:            true,
						ElementType:         types.StringType,
					},
					"all_upn_suffixes": schema.ListAttribute{
						MarkdownDescription: "All available User Principal Name suffixes: the default suffix combined with any additional configured suffixes.",
						Computed:            true,
						ElementType:         types.StringType,
					},
					"spn_suffixes": schema.ListAttribute{
						MarkdownDescription: "Additional Service Principal Name suffixes configured in the forest.",
						Computed:            true,
						ElementType:         types.StringType,
					},
				},
			},
		},
	}
}

func (d *RootDSEDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
}

func (d *RootDSEDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RootDSEDataSourceModel

	// Initialize logging subsystem for consistent logging
	ctx = utils.InitializeLogging(ctx)

	// Set up entry/exit logging
	start := time.Now()
	tflog.Debug(ctx, "Starting data source operation", map[string]any{
		"operation":   "read",
		"data_source": "ad_rootdse",
	})
	defer func() {
		duration := time.Since(start)
		if resp.Diagnostics.HasError() {
			tflog.Error(ctx, "Data source operation failed", map[string]any{
				"operation":   "read",
				"data_source": "ad_rootdse",
				"duration_ms": duration.Milliseconds(),
			})
		} else {
			tflog.Info(ctx, "Data source operation completed", map[string]any{
				"operation":   "read",
				"data_source": "ad_rootdse",
				"duration_ms": duration.Milliseconds(),
			})
		}
	}()

	result, err := d.client.GetRootDSE(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading RootDSE",
			fmt.Sprintf("Could not read Active Directory RootDSE: %s", err.Error()),
		)
		return
	}

	if result == nil {
		resp.Diagnostics.AddError(
			"RootDSE Returned Nil",
			"The RootDSE query returned a nil result. Please report this issue to the provider developers.",
		)
		return
	}

	tflog.Debug(ctx, "Successfully read RootDSE", map[string]any{
		"dns_host_name":           result.DNSHostName,
		"domain_name":             result.DomainName,
		"forest_name":             result.Forest.Name,
		"domain_functionality":    result.DomainFunctionality,
		"forest_functionality":    result.ForestFunctionality,
		"is_global_catalog_ready": result.IsGlobalCatalogReady,
		"additional_upn_suffixes": len(result.Forest.UPNSuffixes),
	})

	d.mapRootDSEToModel(ctx, result, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// mapRootDSEToModel maps the LDAP RootDSEInfo to the Terraform data model.
func (d *RootDSEDataSource) mapRootDSEToModel(ctx context.Context, info *ldapclient.RootDSEInfo, data *RootDSEDataSourceModel, diags *diag.Diagnostics) {
	data.ID = types.StringValue(info.DNSHostName)
	data.DefaultNamingContext = types.StringValue(info.DefaultNamingContext)
	data.ConfigurationNamingContext = types.StringValue(info.ConfigurationNamingContext)
	data.SchemaNamingContext = types.StringValue(info.SchemaNamingContext)
	data.RootDomainNamingContext = types.StringValue(info.RootDomainNamingContext)
	data.DomainName = types.StringValue(info.DomainName)
	data.DNSHostName = types.StringValue(info.DNSHostName)
	data.ServerName = types.StringValue(info.ServerName)
	data.LDAPServiceName = types.StringValue(info.LDAPServiceName)
	data.DomainFunctionality = types.Int64Value(info.DomainFunctionality)
	data.ForestFunctionality = types.Int64Value(info.ForestFunctionality)
	data.DomainControllerFunctionality = types.Int64Value(info.DomainControllerFunctionality)
	data.IsGlobalCatalogReady = types.BoolValue(info.IsGlobalCatalogReady)
	data.IsSynchronized = types.BoolValue(info.IsSynchronized)
	data.SupportedLDAPVersions = helpers.Int64List(info.SupportedLDAPVersions, diags)
	data.SupportedSASLMechanisms = helpers.StringList(info.SupportedSASLMechanisms, diags)

	forestModel := ForestModel{
		Name:             types.StringValue(info.Forest.Name),
		DefaultUPNSuffix: types.StringValue(info.Forest.DefaultUPNSuffix),
		UPNSuffixes:      helpers.StringList(info.Forest.UPNSuffixes, diags),
		AllUPNSuffixes:   helpers.StringList(info.Forest.AllUPNSuffixes, diags),
		SPNSuffixes:      helpers.StringList(info.Forest.SPNSuffixes, diags),
	}

	forestObj, objDiags := types.ObjectValueFrom(ctx, forestAttrTypes, forestModel)
	diags.Append(objDiags...)
	data.Forest = forestObj
}
