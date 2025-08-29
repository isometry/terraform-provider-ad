package provider_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
	"github.com/isometry/terraform-provider-ad/internal/provider"
)

// Helper function to create a proper datasource.ReadRequest for data sources with no configuration.
func createReadRequest(dataSource datasource.DataSource) datasource.ReadRequest {
	// Get the schema
	schemaResp := &datasource.SchemaResponse{}
	dataSource.Schema(context.Background(), datasource.SchemaRequest{}, schemaResp)

	// For data sources with no configuration attributes, create empty config
	return datasource.ReadRequest{
		Config: tfsdk.Config{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}
}

func TestWhoAmIDataSource_Schema(t *testing.T) {
	dataSource := provider.NewWhoAmIDataSource()

	req := datasource.SchemaRequest{}
	resp := &datasource.SchemaResponse{}

	dataSource.Schema(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
	assert.NotNil(t, resp.Schema)

	// Check that all expected attributes are present
	expectedAttrs := []string{"id"}
	for _, attr := range expectedAttrs {
		assert.Contains(t, resp.Schema.Attributes, attr, "Schema should contain attribute %s", attr)
		assert.True(t, resp.Schema.Attributes[attr].IsComputed(), "Attribute %s should be computed", attr)
	}
}

func TestWhoAmIDataSource_Configure(t *testing.T) {
	dataSource := &provider.WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()
	providerData := &ldapclient.ProviderData{
		Client:       mockClient,
		CacheManager: nil, // Tests use nil cache manager
	}

	req := datasource.ConfigureRequest{
		ProviderData: providerData,
	}
	resp := &datasource.ConfigureResponse{}

	dataSource.Configure(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
	assert.Equal(t, mockClient, dataSource.Client)
}

func TestWhoAmIDataSource_Configure_WrongType(t *testing.T) {
	dataSource := &provider.WhoAmIDataSource{}

	req := datasource.ConfigureRequest{
		ProviderData: "not a client",
	}
	resp := &datasource.ConfigureResponse{}

	dataSource.Configure(context.Background(), req, resp)

	assert.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics.Errors()[0].Summary(), "Unexpected Data Source Configure Type")
}

func TestWhoAmIDataSource_Read(t *testing.T) {
	dataSource := &provider.WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()
	dataSource.Client = mockClient

	whoAmIResult := &ldapclient.WhoAmIResult{
		AuthzID: "u:CN=John Doe,CN=Users,DC=example,DC=com",
	}

	mockClient.SetWhoAmIResult(whoAmIResult)

	// Create a proper ReadRequest
	req := createReadRequest(dataSource)

	// Initialize the response with proper State
	schemaResp := &datasource.SchemaResponse{}
	dataSource.Schema(context.Background(), datasource.SchemaRequest{}, schemaResp)

	resp := &datasource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	dataSource.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		for _, diag := range resp.Diagnostics.Errors() {
			t.Logf("Error: %s: %s", diag.Summary(), diag.Detail())
		}
	}
	assert.False(t, resp.Diagnostics.HasError())

	// Verify the result was set correctly
	var data provider.WhoAmIDataSourceModel
	resp.State.Get(context.Background(), &data)

	assert.Equal(t, "u:CN=John Doe,CN=Users,DC=example,DC=com", data.ID.ValueString())
	assert.Equal(t, "u:CN=John Doe,CN=Users,DC=example,DC=com", data.ID.ValueString())
}

func TestWhoAmIDataSource_Read_WhoAmI_Error(t *testing.T) {
	dataSource := &provider.WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()
	dataSource.Client = mockClient

	mockClient.SetError(assert.AnError)

	// Create a proper ReadRequest
	req := createReadRequest(dataSource)

	// Initialize the response with proper State
	schemaResp := &datasource.SchemaResponse{}
	dataSource.Schema(context.Background(), datasource.SchemaRequest{}, schemaResp)

	resp := &datasource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	dataSource.Read(context.Background(), req, resp)

	assert.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics.Errors()[0].Summary(), "Error Performing WhoAmI Operation")
}

func TestWhoAmIDataSource_Read_Nil_Result(t *testing.T) {
	dataSource := &provider.WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()
	dataSource.Client = mockClient

	mockClient.SetWhoAmIResult(nil)

	// Create a proper ReadRequest
	req := createReadRequest(dataSource)

	// Initialize the response with proper State
	schemaResp := &datasource.SchemaResponse{}
	dataSource.Schema(context.Background(), datasource.SchemaRequest{}, schemaResp)

	resp := &datasource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(context.Background()), nil),
		},
	}

	dataSource.Read(context.Background(), req, resp)

	assert.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics.Errors()[0].Summary(), "WhoAmI Operation Returned Nil")
}

// Acceptance test (requires TF_ACC=1 and actual AD connection).
func TestAccWhoAmIDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccWhoAmIDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ad_whoami.test", "id"),
				),
			},
		},
	})
}

func testAccWhoAmIDataSourceConfig() string {
	return `
data "ad_whoami" "test" {}
`
}
