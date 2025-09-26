package planmodifiers_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/isometry/terraform-provider-ad/internal/provider/planmodifiers"
)

func TestUseNameForSAMAccountName_Description(t *testing.T) {
	t.Run("group", func(t *testing.T) {
		modifier := planmodifiers.UseNameForSAMAccountName(false)
		expected := "uses the value of name if sam_account_name is not explicitly configured for group objects"

		actual := modifier.Description(t.Context())
		if actual != expected {
			t.Errorf("Expected description %q, got %q", expected, actual)
		}
	})

	t.Run("user", func(t *testing.T) {
		modifier := planmodifiers.UseNameForSAMAccountName(true)
		expected := "uses the value of name if sam_account_name is not explicitly configured for user objects"

		actual := modifier.Description(t.Context())
		if actual != expected {
			t.Errorf("Expected description %q, got %q", expected, actual)
		}
	})
}

func TestUseNameForSAMAccountName_MarkdownDescription(t *testing.T) {
	t.Run("group", func(t *testing.T) {
		modifier := planmodifiers.UseNameForSAMAccountName(false)
		expected := "uses the value of `name` if `sam_account_name` is not explicitly configured for group objects"

		actual := modifier.MarkdownDescription(t.Context())
		if actual != expected {
			t.Errorf("Expected markdown description %q, got %q", expected, actual)
		}
	})

	t.Run("user", func(t *testing.T) {
		modifier := planmodifiers.UseNameForSAMAccountName(true)
		expected := "uses the value of `name` if `sam_account_name` is not explicitly configured for user objects"

		actual := modifier.MarkdownDescription(t.Context())
		if actual != expected {
			t.Errorf("Expected markdown description %q, got %q", expected, actual)
		}
	})
}

func TestUseNameForSAMAccountName_PlanModifyString_Groups(t *testing.T) {
	tests := map[string]struct {
		configValue        types.String
		nameValue          types.String
		expectedPlanValue  types.String
		expectDiagnostics  bool
		expectErrorSummary string
	}{
		"explicit_sam_account_name_provided": {
			configValue:       types.StringValue("explicit"),
			nameValue:         types.StringValue("TestGroup"),
			expectedPlanValue: types.StringValue("explicit"), // Should keep explicit value
			expectDiagnostics: false,
		},
		"short_valid_name": {
			configValue:       types.StringNull(), // Not explicitly set
			nameValue:         types.StringValue("TestGroup"),
			expectedPlanValue: types.StringValue("TestGroup"), // Should use name
			expectDiagnostics: false,
		},
		"name_at_20_character_limit": {
			configValue:       types.StringNull(),
			nameValue:         types.StringValue("ExactlyTwentyChars_"), // 20 chars - should work for groups
			expectedPlanValue: types.StringValue("ExactlyTwentyChars_"),
			expectDiagnostics: false,
		},
		"name_at_64_character_limit": {
			configValue:       types.StringNull(),
			nameValue:         types.StringValue("This_is_a_very_long_group_name_that_is_exactly_64_characters"), // 64 chars
			expectedPlanValue: types.StringValue("This_is_a_very_long_group_name_that_is_exactly_64_characters"),
			expectDiagnostics: false,
		},
		"name_too_long_for_group": {
			configValue:        types.StringNull(),
			nameValue:          types.StringValue("This_name_is_way_too_long_for_a_SAM_account_name_even_for_groups_65chars"), // >64 chars
			expectedPlanValue:  types.StringNull(),                                                                            // Should not set value
			expectDiagnostics:  true,
			expectErrorSummary: "SAM Account Name Required",
		},
		"name_with_invalid_characters": {
			configValue:        types.StringNull(),
			nameValue:          types.StringValue("Invalid Name!"), // Contains space and !
			expectedPlanValue:  types.StringNull(),
			expectDiagnostics:  true,
			expectErrorSummary: "SAM Account Name Required",
		},
		"name_with_valid_special_chars": {
			configValue:       types.StringNull(),
			nameValue:         types.StringValue("Test.Group_1-2"), // Contains ._- which are valid
			expectedPlanValue: types.StringValue("Test.Group_1-2"),
			expectDiagnostics: false,
		},
		"name_unknown": {
			configValue:       types.StringNull(),
			nameValue:         types.StringUnknown(), // Name is not yet known
			expectedPlanValue: types.StringNull(),    // Should not set value
			expectDiagnostics: false,                 // No error, just wait for name to be known
		},
		"name_null": {
			configValue:       types.StringNull(),
			nameValue:         types.StringNull(),
			expectedPlanValue: types.StringNull(),
			expectDiagnostics: false,
		},
		"config_unknown": {
			configValue:       types.StringUnknown(), // Value will be computed
			nameValue:         types.StringValue("TestGroup"),
			expectedPlanValue: types.StringUnknown(), // Should preserve unknown state
			expectDiagnostics: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			modifier := planmodifiers.UseNameForSAMAccountName(false) // false = group mode

			// Convert name value to terraform value
			nameValue, err := test.nameValue.ToTerraformValue(t.Context())
			if err != nil {
				t.Fatalf("Failed to convert name value: %v", err)
			}

			configValue, err := test.configValue.ToTerraformValue(t.Context())
			if err != nil {
				t.Fatalf("Failed to convert config value: %v", err)
			}

			// Create a plan with the name attribute
			plan := tfsdk.Plan{
				Raw: tftypes.NewValue(tftypes.Object{
					AttributeTypes: map[string]tftypes.Type{
						"name":             tftypes.String,
						"sam_account_name": tftypes.String,
					},
				}, map[string]tftypes.Value{
					"name":             nameValue,
					"sam_account_name": configValue,
				}),
				Schema: schema.Schema{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required: true,
						},
						"sam_account_name": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			}

			req := planmodifier.StringRequest{
				Path:        path.Root("sam_account_name"),
				ConfigValue: test.configValue,
				Plan:        plan,
			}

			resp := &planmodifier.StringResponse{
				PlanValue: test.configValue, // Start with config value
			}

			modifier.PlanModifyString(t.Context(), req, resp)

			// Check diagnostics
			if test.expectDiagnostics && !resp.Diagnostics.HasError() {
				t.Errorf("Expected diagnostics but got none")
			}
			if !test.expectDiagnostics && resp.Diagnostics.HasError() {
				t.Errorf("Expected no diagnostics but got: %v", resp.Diagnostics)
			}

			if test.expectDiagnostics && resp.Diagnostics.HasError() {
				foundExpectedError := false
				for _, diag := range resp.Diagnostics.Errors() {
					if diag.Summary() == test.expectErrorSummary {
						foundExpectedError = true
						break
					}
				}
				if !foundExpectedError {
					t.Errorf("Expected error with summary %q, but got errors: %v",
						test.expectErrorSummary, resp.Diagnostics.Errors())
				}
			}

			// Check plan value
			if !resp.PlanValue.Equal(test.expectedPlanValue) {
				t.Errorf("Expected plan value %v, got %v", test.expectedPlanValue, resp.PlanValue)
			}
		})
	}
}

func TestUseNameForSAMAccountName_PlanModifyString_Users(t *testing.T) {
	tests := map[string]struct {
		configValue        types.String
		nameValue          types.String
		expectedPlanValue  types.String
		expectDiagnostics  bool
		expectErrorSummary string
	}{
		"explicit_sam_account_name_provided": {
			configValue:       types.StringValue("explicit"),
			nameValue:         types.StringValue("TestUser"),
			expectedPlanValue: types.StringValue("explicit"), // Should keep explicit value
			expectDiagnostics: false,
		},
		"short_valid_name": {
			configValue:       types.StringNull(), // Not explicitly set
			nameValue:         types.StringValue("TestUser"),
			expectedPlanValue: types.StringValue("TestUser"), // Should use name
			expectDiagnostics: false,
		},
		"name_at_20_character_limit": {
			configValue:       types.StringNull(),
			nameValue:         types.StringValue("ExactlyTwentyChars_"), // 20 chars - limit for users
			expectedPlanValue: types.StringValue("ExactlyTwentyChars_"),
			expectDiagnostics: false,
		},
		"name_21_characters_too_long_for_user": {
			configValue:        types.StringNull(),
			nameValue:          types.StringValue("This_is_21_characters"), // 21 chars - too long for users
			expectedPlanValue:  types.StringNull(),                         // Should not set value
			expectDiagnostics:  true,
			expectErrorSummary: "SAM Account Name Required",
		},
		"name_with_invalid_characters": {
			configValue:        types.StringNull(),
			nameValue:          types.StringValue("Invalid Name!"), // Contains space and !
			expectedPlanValue:  types.StringNull(),
			expectDiagnostics:  true,
			expectErrorSummary: "SAM Account Name Required",
		},
		"name_with_valid_special_chars": {
			configValue:       types.StringNull(),
			nameValue:         types.StringValue("Test.User_1-2"), // Contains ._- which are valid
			expectedPlanValue: types.StringValue("Test.User_1-2"),
			expectDiagnostics: false,
		},
		"name_unknown": {
			configValue:       types.StringNull(),
			nameValue:         types.StringUnknown(), // Name is not yet known
			expectedPlanValue: types.StringNull(),    // Should not set value
			expectDiagnostics: false,                 // No error, just wait for name to be known
		},
		"name_null": {
			configValue:       types.StringNull(),
			nameValue:         types.StringNull(),
			expectedPlanValue: types.StringNull(),
			expectDiagnostics: false,
		},
		"config_unknown": {
			configValue:       types.StringUnknown(), // Value will be computed
			nameValue:         types.StringValue("TestUser"),
			expectedPlanValue: types.StringUnknown(), // Should preserve unknown state
			expectDiagnostics: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			modifier := planmodifiers.UseNameForSAMAccountName(true) // true = user mode

			// Convert name value to terraform value
			nameValue, err := test.nameValue.ToTerraformValue(t.Context())
			if err != nil {
				t.Fatalf("Failed to convert name value: %v", err)
			}

			configValue, err := test.configValue.ToTerraformValue(t.Context())
			if err != nil {
				t.Fatalf("Failed to convert config value: %v", err)
			}

			// Create a plan with the name attribute
			plan := tfsdk.Plan{
				Raw: tftypes.NewValue(tftypes.Object{
					AttributeTypes: map[string]tftypes.Type{
						"name":             tftypes.String,
						"sam_account_name": tftypes.String,
					},
				}, map[string]tftypes.Value{
					"name":             nameValue,
					"sam_account_name": configValue,
				}),
				Schema: schema.Schema{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required: true,
						},
						"sam_account_name": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			}

			req := planmodifier.StringRequest{
				Path:        path.Root("sam_account_name"),
				ConfigValue: test.configValue,
				Plan:        plan,
			}

			resp := &planmodifier.StringResponse{
				PlanValue: test.configValue, // Start with config value
			}

			modifier.PlanModifyString(t.Context(), req, resp)

			// Check diagnostics
			if test.expectDiagnostics && !resp.Diagnostics.HasError() {
				t.Errorf("Expected diagnostics but got none")
			}
			if !test.expectDiagnostics && resp.Diagnostics.HasError() {
				t.Errorf("Expected no diagnostics but got: %v", resp.Diagnostics)
			}

			if test.expectDiagnostics && resp.Diagnostics.HasError() {
				foundExpectedError := false
				for _, diag := range resp.Diagnostics.Errors() {
					if diag.Summary() == test.expectErrorSummary {
						foundExpectedError = true
						break
					}
				}
				if !foundExpectedError {
					t.Errorf("Expected error with summary %q, but got errors: %v",
						test.expectErrorSummary, resp.Diagnostics.Errors())
				}
			}

			// Check plan value
			if !resp.PlanValue.Equal(test.expectedPlanValue) {
				t.Errorf("Expected plan value %v, got %v", test.expectedPlanValue, resp.PlanValue)
			}
		})
	}
}

func TestUseNameForSAMAccountName_EdgeCases(t *testing.T) {
	t.Run("exactly_one_character", func(t *testing.T) {
		modifier := planmodifiers.UseNameForSAMAccountName(false) // false = group mode

		plan := tfsdk.Plan{
			Raw: tftypes.NewValue(tftypes.Object{
				AttributeTypes: map[string]tftypes.Type{
					"name":             tftypes.String,
					"sam_account_name": tftypes.String,
				},
			}, map[string]tftypes.Value{
				"name":             tftypes.NewValue(tftypes.String, "A"),
				"sam_account_name": tftypes.NewValue(tftypes.String, nil),
			}),
			Schema: schema.Schema{
				Attributes: map[string]schema.Attribute{
					"name":             schema.StringAttribute{Required: true},
					"sam_account_name": schema.StringAttribute{Optional: true},
				},
			},
		}

		req := planmodifier.StringRequest{
			Path:        path.Root("sam_account_name"),
			ConfigValue: types.StringNull(),
			Plan:        plan,
		}

		resp := &planmodifier.StringResponse{
			PlanValue: types.StringNull(),
		}

		modifier.PlanModifyString(t.Context(), req, resp)

		if resp.Diagnostics.HasError() {
			t.Errorf("Single character name should be valid: %v", resp.Diagnostics)
		}

		expected := types.StringValue("A")
		if !resp.PlanValue.Equal(expected) {
			t.Errorf("Expected plan value %v, got %v", expected, resp.PlanValue)
		}
	})

	t.Run("empty_name", func(t *testing.T) {
		modifier := planmodifiers.UseNameForSAMAccountName(false) // false = group mode

		plan := tfsdk.Plan{
			Raw: tftypes.NewValue(tftypes.Object{
				AttributeTypes: map[string]tftypes.Type{
					"name":             tftypes.String,
					"sam_account_name": tftypes.String,
				},
			}, map[string]tftypes.Value{
				"name":             tftypes.NewValue(tftypes.String, ""),
				"sam_account_name": tftypes.NewValue(tftypes.String, nil),
			}),
			Schema: schema.Schema{
				Attributes: map[string]schema.Attribute{
					"name":             schema.StringAttribute{Required: true},
					"sam_account_name": schema.StringAttribute{Optional: true},
				},
			},
		}

		req := planmodifier.StringRequest{
			Path:        path.Root("sam_account_name"),
			ConfigValue: types.StringNull(),
			Plan:        plan,
		}

		resp := &planmodifier.StringResponse{
			PlanValue: types.StringNull(),
		}

		modifier.PlanModifyString(t.Context(), req, resp)

		// Empty name should produce an error since it's not valid for SAM account names
		if !resp.Diagnostics.HasError() {
			t.Errorf("Expected error for empty name, but got none")
		}

		// Should contain error about invalid characters
		foundExpectedError := false
		for _, diag := range resp.Diagnostics.Errors() {
			if diag.Summary() == "SAM Account Name Required" {
				foundExpectedError = true
				break
			}
		}
		if !foundExpectedError {
			t.Errorf("Expected error with summary 'SAM Account Name Required', but got errors: %v", resp.Diagnostics.Errors())
		}

		// Plan value should remain null since we couldn't set a valid default
		expected := types.StringNull()
		if !resp.PlanValue.Equal(expected) {
			t.Errorf("Expected plan value %v, got %v", expected, resp.PlanValue)
		}
	})
}
