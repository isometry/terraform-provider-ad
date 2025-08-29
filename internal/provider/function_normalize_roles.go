package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/isometry/terraform-provider-ad/internal/provider/helpers"
)

var _ function.Function = &NormalizeRolesFunction{}

// NormalizeRolesFunction implements the normalize_roles function.
type NormalizeRolesFunction struct{}

// Metadata returns the function name and signature.
func (f NormalizeRolesFunction) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "normalize_roles"
}

// Definition returns the function schema including parameters and return types.
func (f NormalizeRolesFunction) Definition(_ context.Context, req function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:     "Normalize role fields in teams to sets",
		Description: "For each team in the teams map, normalizes fields matching role keys to sets. String values become single-element sets, lists become sets, existing sets are preserved, and null/empty values become empty sets. All other fields remain unchanged.",
		MarkdownDescription: "For each team in the teams map, normalizes fields matching role keys to sets.\n\n" +
			"- String values become single-element sets\n" +
			"- Lists become sets (duplicates removed)\n" +
			"- Existing sets are preserved\n" +
			"- Null/empty values become empty sets\n" +
			"- Fields not matching role keys remain unchanged",
		Parameters: []function.Parameter{
			function.DynamicParameter{
				Name:                "teams",
				Description:         "Map of team objects containing role fields and other data. Role fields matching keys in the roles parameter will be normalized to sets.",
				MarkdownDescription: "Map of team objects containing role fields and other data. Role fields matching keys in the roles parameter will be normalized to sets.",
			},
			function.DynamicParameter{
				Name:                "roles",
				Description:         "Map where keys define which fields in teams should be normalized to sets. Values in this map are ignored, only the keys matter.",
				MarkdownDescription: "Map where keys define which fields in teams should be normalized to sets. Values in this map are ignored, only the keys matter.",
			},
		},
		Return: function.DynamicReturn{},
	}
}

// Run implements the function logic.
func (f NormalizeRolesFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var teams types.Dynamic
	var roles types.Dynamic

	// Extract parameters with validation
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &teams, &roles))
	if resp.Error != nil {
		return
	}

	// Validate required parameters
	if teams.IsNull() || teams.IsUnknown() {
		resp.Error = function.NewFuncError("teams parameter cannot be null or unknown")
		return
	}
	if roles.IsNull() || roles.IsUnknown() {
		resp.Error = function.NewFuncError("roles parameter cannot be null or unknown")
		return
	}

	// Extract teams map from the dynamic value
	teamsMap, err := helpers.ExtractMapFromDynamic(ctx, teams)
	if err != nil {
		resp.Error = function.NewFuncError(fmt.Sprintf("Failed to extract teams map: %s", err.Error()))
		return
	}

	// Extract roles map from the dynamic value
	rolesMap, err := helpers.ExtractMapFromDynamic(ctx, roles)
	if err != nil {
		resp.Error = function.NewFuncError(fmt.Sprintf("Failed to extract roles map: %s", err.Error()))
		return
	}

	// Normalize roles in teams
	result, err := f.normalizeRoles(ctx, teamsMap, rolesMap)
	if err != nil {
		resp.Error = function.NewFuncError(fmt.Sprintf("Failed to normalize roles: %s", err.Error()))
		return
	}

	// Convert result back to Terraform types as a single object
	attrTypes := make(map[string]attr.Type)
	attrValues := make(map[string]attr.Value)

	for key, val := range result {
		terraformVal, err := helpers.GoValueToTerraform(ctx, val)
		if err != nil {
			resp.Error = function.NewFuncError(fmt.Sprintf("Failed to convert result to Terraform types for key %s: %s", key, err.Error()))
			return
		}
		attrValues[key] = terraformVal
		attrTypes[key] = terraformVal.Type(ctx)
	}

	// Create a single object containing all results
	resultObject := types.ObjectValueMust(attrTypes, attrValues)
	result2 := types.DynamicValue(resultObject)
	resp.Error = resp.Result.Set(ctx, result2)
}

// normalizeRoles implements the core normalization algorithm.
func (f NormalizeRolesFunction) normalizeRoles(ctx context.Context, teamsMap map[string]attr.Value, rolesMap map[string]attr.Value) (map[string]any, error) {
	// Get role keys for faster lookup
	roleKeys := make(map[string]bool)
	for key := range rolesMap {
		roleKeys[key] = true
	}

	result := make(map[string]any)

	// Process each team
	for teamKey, teamValue := range teamsMap {
		// Convert team to Go map for processing
		teamGoVal, err := helpers.TerraformValueToGo(ctx, teamValue)
		if err != nil {
			return nil, fmt.Errorf("failed to convert team %s to Go value: %w", teamKey, err)
		}

		teamObj, ok := teamGoVal.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("team %s must be an object/map, got %T", teamKey, teamGoVal)
		}

		// Process each field in the team
		normalizedTeam := make(map[string]any)
		for fieldName, fieldValue := range teamObj {
			if roleKeys[fieldName] {
				// This field matches a role key - normalize to set
				normalizedValue, err := f.normalizeToSet(fieldValue)
				if err != nil {
					return nil, fmt.Errorf("failed to normalize field %s in team %s: %w", fieldName, teamKey, err)
				}
				normalizedTeam[fieldName] = normalizedValue
			} else {
				// This field doesn't match any role key - keep unchanged
				normalizedTeam[fieldName] = fieldValue
			}
		}

		result[teamKey] = normalizedTeam
	}

	return result, nil
}

// normalizeToSet converts a value to a set (slice of unique strings in sorted order).
func (f NormalizeRolesFunction) normalizeToSet(value any) ([]any, error) {
	if value == nil {
		return []any{}, nil
	}

	switch v := value.(type) {
	case string:
		if v == "" {
			return []any{}, nil
		}
		return []any{v}, nil
	case []any:
		// Convert list to set
		seen := make(map[string]bool)
		var result []any
		for _, item := range v {
			// Skip nil values within lists (treat like empty strings)
			if item == nil {
				continue
			}

			if str, ok := item.(string); ok {
				if !seen[str] && str != "" {
					seen[str] = true
					result = append(result, str)
				}
			} else {
				return nil, fmt.Errorf("list contains non-string value: %T", item)
			}
		}
		// Sort the result for consistent ordering
		stringSlice := make([]string, len(result))
		for i, item := range result {
			if str, ok := item.(string); ok {
				stringSlice[i] = str
			}
		}
		sort.Strings(stringSlice)

		// Convert back to []any
		sortedResult := make([]any, len(stringSlice))
		for i, str := range stringSlice {
			sortedResult[i] = str
		}
		return sortedResult, nil
	default:
		return nil, fmt.Errorf("unsupported type for normalization: %T", value)
	}
}

// NewNormalizeRolesFunction creates a new instance of the normalize_roles function.
func NewNormalizeRolesFunction() function.Function {
	return &NormalizeRolesFunction{}
}
