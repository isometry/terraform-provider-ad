package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

func TestWhoAmIDataSource_Schema(t *testing.T) {
	dataSource := NewWhoAmIDataSource()

	req := datasource.SchemaRequest{}
	resp := &datasource.SchemaResponse{}

	dataSource.Schema(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
	assert.NotNil(t, resp.Schema)

	// Check that all expected attributes are present
	expectedAttrs := []string{"id", "authz_id", "dn", "upn", "sam_account_name", "sid", "format"}
	for _, attr := range expectedAttrs {
		assert.Contains(t, resp.Schema.Attributes, attr, "Schema should contain attribute %s", attr)
		assert.True(t, resp.Schema.Attributes[attr].IsComputed(), "Attribute %s should be computed", attr)
	}
}

func TestWhoAmIDataSource_Configure(t *testing.T) {
	dataSource := &WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()

	req := datasource.ConfigureRequest{
		ProviderData: mockClient,
	}
	resp := &datasource.ConfigureResponse{}

	dataSource.Configure(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
	assert.Equal(t, mockClient, dataSource.client)
}

func TestWhoAmIDataSource_Configure_WrongType(t *testing.T) {
	dataSource := &WhoAmIDataSource{}

	req := datasource.ConfigureRequest{
		ProviderData: "not a client",
	}
	resp := &datasource.ConfigureResponse{}

	dataSource.Configure(context.Background(), req, resp)

	assert.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics.Errors()[0].Summary(), "Unexpected Data Source Configure Type")
}

func TestWhoAmIDataSource_Read_DN_Format(t *testing.T) {
	dataSource := &WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()
	dataSource.client = mockClient

	whoAmIResult := &ldapclient.WhoAmIResult{
		AuthzID: "u:CN=John Doe,CN=Users,DC=example,DC=com",
		DN:      "CN=John Doe,CN=Users,DC=example,DC=com",
		Format:  "dn",
	}

	mockClient.SetWhoAmIResult(whoAmIResult)

	req := datasource.ReadRequest{}
	resp := &datasource.ReadResponse{}

	dataSource.Read(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
}

func TestWhoAmIDataSource_Read_UPN_Format(t *testing.T) {
	dataSource := &WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()
	dataSource.client = mockClient

	whoAmIResult := &ldapclient.WhoAmIResult{
		AuthzID:           "u:john.doe@example.com",
		UserPrincipalName: "john.doe@example.com",
		Format:            "upn",
	}

	mockClient.SetWhoAmIResult(whoAmIResult)

	req := datasource.ReadRequest{}
	resp := &datasource.ReadResponse{}

	dataSource.Read(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
}

func TestWhoAmIDataSource_Read_SAM_Format(t *testing.T) {
	dataSource := &WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()
	dataSource.client = mockClient

	whoAmIResult := &ldapclient.WhoAmIResult{
		AuthzID:        "u:EXAMPLE\\jdoe",
		SAMAccountName: "EXAMPLE\\jdoe",
		Format:         "sam",
	}

	mockClient.SetWhoAmIResult(whoAmIResult)

	req := datasource.ReadRequest{}
	resp := &datasource.ReadResponse{}

	dataSource.Read(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
}

func TestWhoAmIDataSource_Read_SID_Format(t *testing.T) {
	dataSource := &WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()
	dataSource.client = mockClient

	whoAmIResult := &ldapclient.WhoAmIResult{
		AuthzID: "u:S-1-5-21-123456789-123456789-123456789-1001",
		SID:     "S-1-5-21-123456789-123456789-123456789-1001",
		Format:  "sid",
	}

	mockClient.SetWhoAmIResult(whoAmIResult)

	req := datasource.ReadRequest{}
	resp := &datasource.ReadResponse{}

	dataSource.Read(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
}

func TestWhoAmIDataSource_Read_WhoAmI_Error(t *testing.T) {
	dataSource := &WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()
	dataSource.client = mockClient

	mockClient.SetError(assert.AnError)

	req := datasource.ReadRequest{}
	resp := &datasource.ReadResponse{}

	dataSource.Read(context.Background(), req, resp)

	assert.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics.Errors()[0].Summary(), "Error Performing WhoAmI Operation")
}

func TestWhoAmIDataSource_Read_Nil_Result(t *testing.T) {
	dataSource := &WhoAmIDataSource{}
	mockClient := NewMockLDAPClient()
	dataSource.client = mockClient

	mockClient.SetWhoAmIResult(nil)

	req := datasource.ReadRequest{}
	resp := &datasource.ReadResponse{}

	dataSource.Read(context.Background(), req, resp)

	assert.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics.Errors()[0].Summary(), "WhoAmI Operation Returned Nil")
}

// Test mapResultToModel function.
func TestWhoAmIDataSource_MapResultToModel(t *testing.T) {
	dataSource := &WhoAmIDataSource{}

	tests := []struct {
		name     string
		result   *ldapclient.WhoAmIResult
		expected map[string]string
	}{
		{
			name: "DN format",
			result: &ldapclient.WhoAmIResult{
				AuthzID: "u:CN=John Doe,CN=Users,DC=example,DC=com",
				DN:      "CN=John Doe,CN=Users,DC=example,DC=com",
				Format:  "dn",
			},
			expected: map[string]string{
				"authz_id": "u:CN=John Doe,CN=Users,DC=example,DC=com",
				"dn":       "CN=John Doe,CN=Users,DC=example,DC=com",
				"format":   "dn",
			},
		},
		{
			name: "UPN format",
			result: &ldapclient.WhoAmIResult{
				AuthzID:           "u:john.doe@example.com",
				UserPrincipalName: "john.doe@example.com",
				Format:            "upn",
			},
			expected: map[string]string{
				"authz_id": "u:john.doe@example.com",
				"upn":      "john.doe@example.com",
				"format":   "upn",
			},
		},
		{
			name: "SAM format",
			result: &ldapclient.WhoAmIResult{
				AuthzID:        "u:EXAMPLE\\jdoe",
				SAMAccountName: "EXAMPLE\\jdoe",
				Format:         "sam",
			},
			expected: map[string]string{
				"authz_id":         "u:EXAMPLE\\jdoe",
				"sam_account_name": "EXAMPLE\\jdoe",
				"format":           "sam",
			},
		},
		{
			name: "SID format",
			result: &ldapclient.WhoAmIResult{
				AuthzID: "u:S-1-5-21-123456789-123456789-123456789-1001",
				SID:     "S-1-5-21-123456789-123456789-123456789-1001",
				Format:  "sid",
			},
			expected: map[string]string{
				"authz_id": "u:S-1-5-21-123456789-123456789-123456789-1001",
				"sid":      "S-1-5-21-123456789-123456789-123456789-1001",
				"format":   "sid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data WhoAmIDataSourceModel
			dataSource.mapResultToModel(tt.result, &data)

			assert.Equal(t, tt.expected["authz_id"], data.AuthzID.ValueString())
			assert.Equal(t, tt.expected["authz_id"], data.ID.ValueString()) // ID should equal authz_id
			assert.Equal(t, tt.expected["format"], data.Format.ValueString())

			if expectedDN, ok := tt.expected["dn"]; ok {
				assert.Equal(t, expectedDN, data.DN.ValueString())
			} else {
				assert.True(t, data.DN.IsNull())
			}

			if expectedUPN, ok := tt.expected["upn"]; ok {
				assert.Equal(t, expectedUPN, data.UserPrincipalName.ValueString())
			} else {
				assert.True(t, data.UserPrincipalName.IsNull())
			}

			if expectedSAM, ok := tt.expected["sam_account_name"]; ok {
				assert.Equal(t, expectedSAM, data.SAMAccountName.ValueString())
			} else {
				assert.True(t, data.SAMAccountName.IsNull())
			}

			if expectedSID, ok := tt.expected["sid"]; ok {
				assert.Equal(t, expectedSID, data.SID.ValueString())
			} else {
				assert.True(t, data.SID.IsNull())
			}
		})
	}
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
					resource.TestCheckResourceAttrSet("data.ad_whoami.test", "authz_id"),
					resource.TestCheckResourceAttrSet("data.ad_whoami.test", "format"),
					// At least one of the identity fields should be populated
					resource.TestCheckResourceAttrWith("data.ad_whoami.test", "format", func(value string) error {
						if value == "empty" || value == "unknown" {
							t.Errorf("Expected a recognized identity format, got: %s", value)
						}
						return nil
					}),
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
