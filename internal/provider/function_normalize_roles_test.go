package provider_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isometry/terraform-provider-ad/internal/provider"
	"github.com/isometry/terraform-provider-ad/internal/provider/helpers"
)

func TestNormalizeRolesFunction_Metadata(t *testing.T) {
	ctx := context.Background()
	f := &provider.NormalizeRolesFunction{}

	var req function.MetadataRequest
	var resp function.MetadataResponse

	f.Metadata(ctx, req, &resp)

	assert.Equal(t, "normalize_roles", resp.Name)
}

func TestNormalizeRolesFunction_Definition(t *testing.T) {
	ctx := context.Background()
	f := &provider.NormalizeRolesFunction{}

	var req function.DefinitionRequest
	var resp function.DefinitionResponse

	f.Definition(ctx, req, &resp)

	assert.NotEmpty(t, resp.Definition.Summary)
	assert.Len(t, resp.Definition.Parameters, 2)

	// Verify parameter names and types
	assert.Equal(t, "teams", resp.Definition.Parameters[0].GetName())
	assert.Equal(t, "roles", resp.Definition.Parameters[1].GetName())

	// Verify both parameters are dynamic
	_, ok := resp.Definition.Parameters[0].(function.DynamicParameter)
	assert.True(t, ok)
	_, ok = resp.Definition.Parameters[1].(function.DynamicParameter)
	assert.True(t, ok)
}

// Helper function to execute the normalize_roles function with Go values.
func executeNormalizeRoles(t *testing.T, teams map[string]any, roles map[string]any) (map[string]any, error) {
	ctx := context.Background()
	f := &provider.NormalizeRolesFunction{}

	// Convert input to Terraform types
	teamsVal, err := helpers.GoValueToTerraform(ctx, teams)
	require.NoError(t, err)
	teamsDynamic := types.DynamicValue(teamsVal)

	rolesVal, err := helpers.GoValueToTerraform(ctx, roles)
	require.NoError(t, err)
	rolesDynamic := types.DynamicValue(rolesVal)

	// Call the function
	var req function.RunRequest
	resp := function.RunResponse{
		Result: function.NewResultData(types.DynamicUnknown()),
	}
	req.Arguments = function.NewArgumentsData([]attr.Value{teamsDynamic, rolesDynamic})

	f.Run(ctx, req, &resp)

	if resp.Error != nil {
		return nil, resp.Error
	}

	// Extract result
	resultValue := resp.Result.Value()
	resultDynamic, ok := resultValue.(types.Dynamic)
	if !ok {
		return nil, fmt.Errorf("expected Dynamic result, got %T", resultValue)
	}
	resultMap, err := helpers.ExtractMapFromDynamic(ctx, resultDynamic)
	if err != nil {
		return nil, err
	}

	// Convert back to Go values for easy testing
	result := make(map[string]any)
	for key, value := range resultMap {
		goVal, err := helpers.TerraformValueToGo(ctx, value)
		if err != nil {
			return nil, err
		}
		result[key] = goVal
	}

	return result, nil
}

func TestNormalizeRoles_StringToSet(t *testing.T) {
	teams := map[string]any{
		"team1": map[string]any{
			"role1": "single_value",
			"role2": "another_value",
		},
	}

	roles := map[string]any{
		"role1": "irrelevant",
		"role2": "also_irrelevant",
	}

	result, err := executeNormalizeRoles(t, teams, roles)
	require.NoError(t, err)

	team1, ok := result["team1"].(map[string]any)
	require.True(t, ok)

	role1, ok := team1["role1"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"single_value"}, role1)

	role2, ok := team1["role2"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"another_value"}, role2)
}

func TestNormalizeRoles_ListToSet(t *testing.T) {
	teams := map[string]any{
		"team1": map[string]any{
			"role1": []any{"a1"},
			"role2": []any{"a2", "a3", "a2"}, // Contains duplicate
		},
	}

	roles := map[string]any{
		"role1": "irrelevant",
		"role2": "irrelevant",
	}

	result, err := executeNormalizeRoles(t, teams, roles)
	require.NoError(t, err)

	team1, ok := result["team1"].(map[string]any)
	require.True(t, ok)

	role1, ok := team1["role1"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"a1"}, role1)

	role2, ok := team1["role2"].([]any)
	require.True(t, ok)
	// Should be sorted and deduplicated
	assert.Equal(t, []any{"a2", "a3"}, role2)
}

func TestNormalizeRoles_NullAndEmpty(t *testing.T) {
	teams := map[string]any{
		"team1": map[string]any{
			"role1": "",
			"role2": []any{},
		},
	}

	roles := map[string]any{
		"role1": "irrelevant",
		"role2": "irrelevant",
	}

	result, err := executeNormalizeRoles(t, teams, roles)
	require.NoError(t, err)

	team1, ok := result["team1"].(map[string]any)
	require.True(t, ok)

	role1, ok := team1["role1"].([]any)
	require.True(t, ok)
	assert.Empty(t, role1)

	role2, ok := team1["role2"].([]any)
	require.True(t, ok)
	assert.Empty(t, role2)
}

func TestNormalizeRoles_UnchangedFields(t *testing.T) {
	teams := map[string]any{
		"team1": map[string]any{
			"role1":     "normalized",
			"unrelated": "unchanged",
			"another":   []any{"keep", "as", "is"},
			"nested": map[string]any{
				"deep": "structure",
			},
		},
	}

	roles := map[string]any{
		"role1": "irrelevant",
	}

	result, err := executeNormalizeRoles(t, teams, roles)
	require.NoError(t, err)

	team1, ok := result["team1"].(map[string]any)
	require.True(t, ok)

	// role1 should be normalized
	role1, ok := team1["role1"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"normalized"}, role1)

	// unrelated should be unchanged
	assert.Equal(t, "unchanged", team1["unrelated"])

	// another should be unchanged (it's not in roles)
	another, ok := team1["another"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"keep", "as", "is"}, another)

	// nested should be unchanged
	nested, ok := team1["nested"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "structure", nested["deep"])
}

func TestNormalizeRoles_ComplexScenario(t *testing.T) {
	// This mirrors the example from the requirements
	teams := map[string]any{
		"a": map[string]any{
			"role1":     []any{"a1"},
			"role2":     []any{"a2", "a3"},
			"unrelated": "anything",
		},
		"b": map[string]any{
			"role1": "b1",
			"role2": []any{"a1", "b2", "b3"},
			"role3": []any{"b4", "b5"}, // Not in roles
			"role4": "",                // Empty string
		},
	}

	roles := map[string]any{
		"role1": "irrelevant",
		"role2": "irrelevant",
		"role4": "irrelevant",
	}

	result, err := executeNormalizeRoles(t, teams, roles)
	require.NoError(t, err)

	// Verify team a
	teamA, ok := result["a"].(map[string]any)
	require.True(t, ok)

	role1A, ok := teamA["role1"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"a1"}, role1A)

	role2A, ok := teamA["role2"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"a2", "a3"}, role2A)

	assert.Equal(t, "anything", teamA["unrelated"]) // Unchanged

	// Verify team b
	teamB, ok := result["b"].(map[string]any)
	require.True(t, ok)

	role1B, ok := teamB["role1"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"b1"}, role1B)

	role2B, ok := teamB["role2"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"a1", "b2", "b3"}, role2B) // Should be sorted

	// role3 should be unchanged (not in roles map)
	role3B, ok := teamB["role3"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"b4", "b5"}, role3B)

	// role4 should be empty set (empty string normalized)
	role4B, ok := teamB["role4"].([]any)
	require.True(t, ok)
	assert.Empty(t, role4B)
}

func TestNormalizeRoles_ErrorCases(t *testing.T) {
	ctx := context.Background()
	f := &provider.NormalizeRolesFunction{}

	testCases := []struct {
		name        string
		teams       types.Dynamic
		roles       types.Dynamic
		expectedErr string
	}{
		{
			name:        "null teams",
			teams:       types.DynamicNull(),
			roles:       types.DynamicValue(types.ObjectValueMust(map[string]attr.Type{}, map[string]attr.Value{})),
			expectedErr: "teams parameter cannot be null",
		},
		{
			name:        "null roles",
			teams:       types.DynamicValue(types.ObjectValueMust(map[string]attr.Type{}, map[string]attr.Value{})),
			roles:       types.DynamicNull(),
			expectedErr: "roles parameter cannot be null",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var req function.RunRequest
			resp := function.RunResponse{
				Result: function.NewResultData(types.DynamicUnknown()),
			}
			req.Arguments = function.NewArgumentsData([]attr.Value{tc.teams, tc.roles})

			f.Run(ctx, req, &resp)

			require.Error(t, resp.Error)
			assert.Contains(t, resp.Error.Error(), tc.expectedErr)
		})
	}
}

func TestNormalizeRoles_EmptyInputs(t *testing.T) {
	teams := map[string]any{}
	roles := map[string]any{}

	result, err := executeNormalizeRoles(t, teams, roles)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestNormalizeRoles_NoMatchingRoles(t *testing.T) {
	teams := map[string]any{
		"team1": map[string]any{
			"field1": "value1",
			"field2": []any{"value2", "value3"},
		},
	}

	roles := map[string]any{
		"different_role": "irrelevant",
	}

	result, err := executeNormalizeRoles(t, teams, roles)
	require.NoError(t, err)

	// Should return teams unchanged since no fields match role keys
	team1, ok := result["team1"].(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "value1", team1["field1"])
	field2, ok := team1["field2"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"value2", "value3"}, field2)
}

func TestNormalizeRoles_SortedOutput(t *testing.T) {
	teams := map[string]any{
		"team1": map[string]any{
			"role1": []any{"z", "a", "m", "b"},
		},
	}

	roles := map[string]any{
		"role1": "irrelevant",
	}

	result, err := executeNormalizeRoles(t, teams, roles)
	require.NoError(t, err)

	team1, ok := result["team1"].(map[string]any)
	require.True(t, ok)

	role1, ok := team1["role1"].([]any)
	require.True(t, ok)

	// Should be sorted alphabetically
	assert.Equal(t, []any{"a", "b", "m", "z"}, role1)
}

func TestNormalizeRoles_ListWithNils(t *testing.T) {
	teams := map[string]any{
		"team1": map[string]any{
			"role1": []any{nil},                         // Only nil -> empty set
			"role2": []any{"a", nil, "b"},               // Mixed with nil -> sorted set without nil
			"role3": []any{nil, nil, "c"},               // Multiple nils -> single element set
			"role4": []any{"b", nil, "a", nil, "b"},     // Duplicates with nils -> deduplicated sorted set
			"role5": []any{nil, "", nil, ""},            // Nils and empty strings -> empty set
			"role6": []any{"x", nil, "", "y", nil, "x"}, // Complex case -> deduplicated sorted set
		},
	}

	roles := map[string]any{
		"role1": "irrelevant",
		"role2": "irrelevant",
		"role3": "irrelevant",
		"role4": "irrelevant",
		"role5": "irrelevant",
		"role6": "irrelevant",
	}

	result, err := executeNormalizeRoles(t, teams, roles)
	require.NoError(t, err)

	team1, ok := result["team1"].(map[string]any)
	require.True(t, ok)

	// role1: [nil] -> []
	role1, ok := team1["role1"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{}, role1)

	// role2: ["a", nil, "b"] -> ["a", "b"]
	role2, ok := team1["role2"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"a", "b"}, role2)

	// role3: [nil, nil, "c"] -> ["c"]
	role3, ok := team1["role3"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"c"}, role3)

	// role4: ["b", nil, "a", nil, "b"] -> ["a", "b"]
	role4, ok := team1["role4"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"a", "b"}, role4)

	// role5: [nil, "", nil, ""] -> []
	role5, ok := team1["role5"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{}, role5)

	// role6: ["x", nil, "", "y", nil, "x"] -> ["x", "y"]
	role6, ok := team1["role6"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"x", "y"}, role6)
}
