package provider_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	"github.com/isometry/terraform-provider-ad/internal/provider"
)

func TestRootDSEDataSource_Schema(t *testing.T) {
	dataSource := provider.NewRootDSEDataSource()

	req := datasource.SchemaRequest{}
	resp := &datasource.SchemaResponse{}

	dataSource.Schema(t.Context(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
	assert.NotNil(t, resp.Schema)

	// Check top-level attributes
	expectedAttrs := []string{
		"id",
		"default_naming_context",
		"configuration_naming_context",
		"schema_naming_context",
		"root_domain_naming_context",
		"domain_name",
		"dns_host_name",
		"server_name",
		"ldap_service_name",
		"domain_functionality",
		"forest_functionality",
		"domain_controller_functionality",
		"supported_ldap_versions",
		"supported_sasl_mechanisms",
		"is_global_catalog_ready",
		"is_synchronized",
		"forest",
	}
	for _, attr := range expectedAttrs {
		assert.Contains(t, resp.Schema.Attributes, attr, "Schema should contain attribute %s", attr)
		assert.True(t, resp.Schema.Attributes[attr].IsComputed(), "Attribute %s should be computed", attr)
	}
}

func TestRootDSEDataSource_Configure(t *testing.T) {
	dataSource := &provider.RootDSEDataSource{}
	mockClient := NewMockLDAPClient()
	providerData := &ldapclient.ProviderData{
		Client:       mockClient,
		CacheManager: nil,
	}

	req := datasource.ConfigureRequest{
		ProviderData: providerData,
	}
	resp := &datasource.ConfigureResponse{}

	dataSource.Configure(t.Context(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
}

func TestRootDSEDataSource_Configure_WrongType(t *testing.T) {
	dataSource := &provider.RootDSEDataSource{}

	req := datasource.ConfigureRequest{
		ProviderData: "not a client",
	}
	resp := &datasource.ConfigureResponse{}

	dataSource.Configure(t.Context(), req, resp)

	assert.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics.Errors()[0].Summary(), "Unexpected Data Source Configure Type")
}

func TestRootDSEDataSource_Read(t *testing.T) {
	dataSource := &provider.RootDSEDataSource{}
	mockClient := NewMockLDAPClient()

	// Configure the data source
	providerData := &ldapclient.ProviderData{
		Client:       mockClient,
		CacheManager: nil,
	}
	configReq := datasource.ConfigureRequest{ProviderData: providerData}
	configResp := &datasource.ConfigureResponse{}
	dataSource.Configure(t.Context(), configReq, configResp)
	require.False(t, configResp.Diagnostics.HasError())

	// Set up mock result
	mockClient.SetRootDSEResult(&ldapclient.RootDSEInfo{
		DefaultNamingContext:       "DC=example,DC=com",
		ConfigurationNamingContext: "CN=Configuration,DC=example,DC=com",
		SchemaNamingContext:        "CN=Schema,CN=Configuration,DC=example,DC=com",
		RootDomainNamingContext:    "DC=example,DC=com",
		DomainName:                 "example.com",
		DNSHostName:                "dc01.example.com",
		ServerName:                 "CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com",
		LDAPServiceName:            "example.com:dc01$@EXAMPLE.COM",

		DomainFunctionality:           7,
		ForestFunctionality:           7,
		DomainControllerFunctionality: 7,

		SupportedLDAPVersions:   []int64{3, 2},
		SupportedSASLMechanisms: []string{"GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"},

		IsGlobalCatalogReady: true,
		IsSynchronized:       true,

		Forest: ldapclient.ForestInfo{
			Name:             "example.com",
			DefaultUPNSuffix: "example.com",
			UPNSuffixes:      []string{"alt.example.com", "other.example.com"},
			AllUPNSuffixes:   []string{"example.com", "alt.example.com", "other.example.com"},
			SPNSuffixes:      []string{},
		},
	})

	// Create the read request
	readReq := createReadRequest(dataSource)

	// Initialize the response with proper State
	schemaResp := &datasource.SchemaResponse{}
	dataSource.Schema(t.Context(), datasource.SchemaRequest{}, schemaResp)

	readResp := &datasource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(t.Context()), nil),
		},
	}

	dataSource.Read(t.Context(), readReq, readResp)

	if readResp.Diagnostics.HasError() {
		for _, diag := range readResp.Diagnostics.Errors() {
			t.Logf("Error: %s: %s", diag.Summary(), diag.Detail())
		}
	}
	require.False(t, readResp.Diagnostics.HasError())

	// Verify the result was set correctly
	var data provider.RootDSEDataSourceModel
	readResp.State.Get(t.Context(), &data)

	assert.Equal(t, "dc01.example.com", data.ID.ValueString())
	assert.Equal(t, "DC=example,DC=com", data.DefaultNamingContext.ValueString())
	assert.Equal(t, "CN=Configuration,DC=example,DC=com", data.ConfigurationNamingContext.ValueString())
	assert.Equal(t, "CN=Schema,CN=Configuration,DC=example,DC=com", data.SchemaNamingContext.ValueString())
	assert.Equal(t, "DC=example,DC=com", data.RootDomainNamingContext.ValueString())
	assert.Equal(t, "example.com", data.DomainName.ValueString())
	assert.Equal(t, "dc01.example.com", data.DNSHostName.ValueString())
	assert.Equal(t, int64(7), data.DomainFunctionality.ValueInt64())
	assert.Equal(t, int64(7), data.ForestFunctionality.ValueInt64())
	assert.Equal(t, int64(7), data.DomainControllerFunctionality.ValueInt64())
	assert.Equal(t, true, data.IsGlobalCatalogReady.ValueBool())
	assert.Equal(t, true, data.IsSynchronized.ValueBool())

	// Verify forest nested object
	assert.False(t, data.Forest.IsNull())
	assert.False(t, data.Forest.IsUnknown())

	var forestModel provider.ForestModel
	diags := data.Forest.As(context.Background(), &forestModel, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError(), "Failed to extract forest model")

	assert.Equal(t, "example.com", forestModel.Name.ValueString())
	assert.Equal(t, "example.com", forestModel.DefaultUPNSuffix.ValueString())
}

func TestRootDSEDataSource_Read_Error(t *testing.T) {
	dataSource := &provider.RootDSEDataSource{}
	mockClient := NewMockLDAPClient()

	providerData := &ldapclient.ProviderData{
		Client:       mockClient,
		CacheManager: nil,
	}
	configReq := datasource.ConfigureRequest{ProviderData: providerData}
	configResp := &datasource.ConfigureResponse{}
	dataSource.Configure(t.Context(), configReq, configResp)

	mockClient.SetError(assert.AnError)

	readReq := createReadRequest(dataSource)

	schemaResp := &datasource.SchemaResponse{}
	dataSource.Schema(t.Context(), datasource.SchemaRequest{}, schemaResp)

	readResp := &datasource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(t.Context()), nil),
		},
	}

	dataSource.Read(t.Context(), readReq, readResp)

	assert.True(t, readResp.Diagnostics.HasError())
	assert.Contains(t, readResp.Diagnostics.Errors()[0].Summary(), "Error Reading RootDSE")
}

func TestRootDSEDataSource_Read_Nil(t *testing.T) {
	dataSource := &provider.RootDSEDataSource{}
	mockClient := NewMockLDAPClient()

	providerData := &ldapclient.ProviderData{
		Client:       mockClient,
		CacheManager: nil,
	}
	configReq := datasource.ConfigureRequest{ProviderData: providerData}
	configResp := &datasource.ConfigureResponse{}
	dataSource.Configure(t.Context(), configReq, configResp)

	mockClient.SetRootDSEResult(nil)

	readReq := createReadRequest(dataSource)

	schemaResp := &datasource.SchemaResponse{}
	dataSource.Schema(t.Context(), datasource.SchemaRequest{}, schemaResp)

	readResp := &datasource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(t.Context()), nil),
		},
	}

	dataSource.Read(t.Context(), readReq, readResp)

	assert.True(t, readResp.Diagnostics.HasError())
	assert.Contains(t, readResp.Diagnostics.Errors()[0].Summary(), "RootDSE Returned Nil")
}

// Acceptance test (requires TF_ACC=1 and actual AD connection).
func TestAccRootDSEDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRootDSEDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_rootdse.test", "id"),
					resource.TestCheckResourceAttrSet("data.ad_rootdse.test", "dns_host_name"),
					resource.TestCheckResourceAttrSet("data.ad_rootdse.test", "default_naming_context"),
					resource.TestCheckResourceAttrSet("data.ad_rootdse.test", "domain_name"),
					resource.TestCheckResourceAttrSet("data.ad_rootdse.test", "forest.name"),
					resource.TestCheckResourceAttrSet("data.ad_rootdse.test", "forest.default_upn_suffix"),
				),
			},
		},
	})
}

func testAccRootDSEDataSourceConfig() string {
	return testProviderConfig() + "\n\n" + `data "ad_rootdse" "test" {}`
}
