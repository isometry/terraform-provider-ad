// Package helpers provides common utility functions for Terraform type conversions
// and manipulations that can be reused across resources, data sources, and functions.
package helpers

import (
	"context"
	"fmt"
	"maps"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// TerraformValueToGo converts various Terraform attr.Value types to Go interface{} values.
// It recursively handles complex types like lists, maps, objects, and sets.
// Returns nil for null values and an error for unknown values.
func TerraformValueToGo(ctx context.Context, value attr.Value) (any, error) {
	if value.IsNull() {
		return nil, nil
	}
	if value.IsUnknown() {
		return nil, fmt.Errorf("cannot process unknown values")
	}

	switch v := value.(type) {
	case types.String:
		return v.ValueString(), nil
	case types.Int64:
		return v.ValueInt64(), nil
	case types.Float64:
		return v.ValueFloat64(), nil
	case types.Bool:
		return v.ValueBool(), nil
	case types.Number:
		// Convert big.Float to float64 for easier handling
		bigFloat := v.ValueBigFloat()
		if bigFloat == nil {
			return nil, fmt.Errorf("number value is nil")
		}
		floatVal, _ := bigFloat.Float64()
		return floatVal, nil
	case types.List:
		elements := v.Elements()
		result := make([]any, len(elements))
		for i, elem := range elements {
			goVal, err := TerraformValueToGo(ctx, elem)
			if err != nil {
				return nil, err
			}
			result[i] = goVal
		}
		return result, nil
	case types.Map:
		elements := v.Elements()
		result := make(map[string]any)
		for key, elem := range elements {
			goVal, err := TerraformValueToGo(ctx, elem)
			if err != nil {
				return nil, err
			}
			result[key] = goVal
		}
		return result, nil
	case types.Object:
		attributes := v.Attributes()
		result := make(map[string]any)
		for attrName, attrVal := range attributes {
			goVal, err := TerraformValueToGo(ctx, attrVal)
			if err != nil {
				return nil, err
			}
			result[attrName] = goVal
		}
		return result, nil
	case types.Set:
		elements := v.Elements()
		result := make([]any, len(elements))
		for i, elem := range elements {
			goVal, err := TerraformValueToGo(ctx, elem)
			if err != nil {
				return nil, err
			}
			result[i] = goVal
		}
		return result, nil
	case types.Tuple:
		elements := v.Elements()
		result := make([]any, len(elements))
		for i, elem := range elements {
			goVal, err := TerraformValueToGo(ctx, elem)
			if err != nil {
				return nil, err
			}
			result[i] = goVal
		}
		return result, nil
	case types.Dynamic:
		return TerraformValueToGo(ctx, v.UnderlyingValue())
	default:
		return nil, fmt.Errorf("unsupported type: %T", value)
	}
}

// DynamicValueToMap converts a Terraform dynamic value to a Go map[string]interface{}.
// The dynamic value must contain either an object or map type underneath.
// Returns an error if the value is null, unknown, or not a map/object type.
func DynamicValueToMap(ctx context.Context, value attr.Value) (map[string]any, error) {
	if value.IsNull() || value.IsUnknown() {
		return nil, fmt.Errorf("value cannot be null or unknown")
	}

	dynamicVal, ok := value.(types.Dynamic)
	if !ok {
		return nil, fmt.Errorf("expected dynamic value, got %T", value)
	}

	underlyingVal := dynamicVal.UnderlyingValue()

	switch v := underlyingVal.(type) {
	case types.Object:
		// Handle object type (existing logic)
		result := make(map[string]any)
		for attrName, attrVal := range v.Attributes() {
			goVal, err := TerraformValueToGo(ctx, attrVal)
			if err != nil {
				return nil, fmt.Errorf("failed to convert attribute %s: %w", attrName, err)
			}
			result[attrName] = goVal
		}
		return result, nil

	case types.Map:
		// Handle map type (new logic)
		result := make(map[string]any)
		for key, mapVal := range v.Elements() {
			goVal, err := TerraformValueToGo(ctx, mapVal)
			if err != nil {
				return nil, fmt.Errorf("failed to convert map element %s: %w", key, err)
			}
			result[key] = goVal
		}
		return result, nil

	default:
		return nil, fmt.Errorf("expected object or map value, got %T", underlyingVal)
	}
}

// ExtractMapFromDynamic extracts a map[string]attr.Value from a dynamic value.
// It handles both map and object types by converting them to a unified map representation.
// Returns an error if the underlying value is neither a map nor an object.
func ExtractMapFromDynamic(ctx context.Context, value types.Dynamic) (map[string]attr.Value, error) {
	underlyingVal := value.UnderlyingValue()

	// Handle map type
	if mapVal, ok := underlyingVal.(types.Map); ok {
		return mapVal.Elements(), nil
	}

	// Handle object type - convert to map-like structure
	if objVal, ok := underlyingVal.(types.Object); ok {
		attributes := objVal.Attributes()
		result := make(map[string]attr.Value)
		maps.Copy(result, attributes)
		return result, nil
	}

	return nil, fmt.Errorf("expected map or object type, got %T", underlyingVal)
}

// GoValueToTerraform converts Go interface{} values back to Terraform attr.Value types.
// It recursively handles complex types like maps, slices, and nested structures.
// Returns an error for unsupported types.
func GoValueToTerraform(ctx context.Context, value any) (attr.Value, error) {
	if value == nil {
		return types.StringNull(), nil
	}

	switch v := value.(type) {
	case string:
		return types.StringValue(v), nil
	case int:
		return types.Int64Value(int64(v)), nil
	case int64:
		return types.Int64Value(v), nil
	case float64:
		return types.Float64Value(v), nil
	case bool:
		return types.BoolValue(v), nil
	case map[string]any:
		// Convert map to object (not map) to handle heterogeneous field types
		// This is needed because YAML data often has mixed field types (strings, arrays, etc.)
		attrTypes := make(map[string]attr.Type)
		attrValues := make(map[string]attr.Value)

		for key, val := range v {
			terraformVal, err := GoValueToTerraform(ctx, val)
			if err != nil {
				return nil, fmt.Errorf("failed to convert map element %s: %w", key, err)
			}
			attrValues[key] = terraformVal
			attrTypes[key] = terraformVal.Type(ctx)
		}

		// Create object instead of map to handle heterogeneous types
		return types.ObjectValueMust(attrTypes, attrValues), nil
	case []any:
		// Convert slice to tuple (not list) to handle heterogeneous element types
		// This is needed because child objects may have different schemas
		elements := make([]attr.Value, len(v))
		elementTypes := make([]attr.Type, len(v))

		for i, val := range v {
			terraformVal, err := GoValueToTerraform(ctx, val)
			if err != nil {
				return nil, fmt.Errorf("failed to convert list element %d: %w", i, err)
			}
			elements[i] = terraformVal
			elementTypes[i] = terraformVal.Type(ctx)
		}

		// Use Tuple to handle heterogeneous element types
		return types.TupleValueMust(elementTypes, elements), nil
	default:
		return nil, fmt.Errorf("unsupported Go type for conversion: %T", value)
	}
}

// =============================================================================
// Terraform Type Value Extraction (Terraform → Go)
// =============================================================================

// GetString returns the string value from a Terraform types.String.
// Returns empty string if the value is null or unknown.
func GetString(v types.String) string {
	if v.IsNull() || v.IsUnknown() {
		return ""
	}
	return v.ValueString()
}

// =============================================================================
// Pointer Helpers (for LDAP requests where nil = don't modify)
// =============================================================================

// StringPtr returns a pointer to the string value, or nil if null/unknown.
// Use this for LDAP update requests where nil means "don't modify this field".
func StringPtr(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	val := v.ValueString()
	return &val
}

// BoolPtr returns a pointer to the bool value, or nil if null/unknown.
// Use this for LDAP update requests where nil means "don't modify this field".
func BoolPtr(v types.Bool) *bool {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	val := v.ValueBool()
	return &val
}

// Int64Ptr returns a pointer to the int64 value, or nil if null/unknown.
// Use this for LDAP update requests where nil means "don't modify this field".
func Int64Ptr(v types.Int64) *int64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	val := v.ValueInt64()
	return &val
}

// =============================================================================
// Construction Helpers (Go → Terraform)
// =============================================================================

// StringOrNull returns types.StringValue if the string is non-empty,
// otherwise returns types.StringNull().
// Use this for optional string attributes where empty means "not set in AD".
func StringOrNull(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// Timestamp formats a time.Time as an RFC3339 string for Terraform state.
func Timestamp(t time.Time) types.String {
	return types.StringValue(t.Format(time.RFC3339))
}

// TimestampOrNull formats an optional time.Time as an RFC3339 string,
// or returns types.StringNull() if the pointer is nil.
func TimestampOrNull(t *time.Time) types.String {
	if t == nil {
		return types.StringNull()
	}
	return types.StringValue(t.Format(time.RFC3339))
}

// =============================================================================
// Change Detection Helpers (for update operations)
// =============================================================================

// StringChanged checks if a string attribute changed between plan and state.
// If changed, sets *target to the new value (empty string for clearing).
// Returns true if the attribute changed.
func StringChanged(plan, state types.String, target **string) bool {
	if plan.Equal(state) {
		return false
	}

	// Handle clearing (plan is null but state had a value)
	if plan.IsNull() && !state.IsNull() {
		empty := ""
		*target = &empty
		return true
	}

	// Handle setting (plan has a value)
	if !plan.IsNull() {
		val := plan.ValueString()
		*target = &val
		return true
	}

	return false
}

// BoolChanged checks if a bool attribute changed between plan and state.
// If changed, sets *target to the new value.
// Returns true if the attribute changed.
func BoolChanged(plan, state types.Bool, target **bool) bool {
	if plan.Equal(state) {
		return false
	}

	if !plan.IsNull() && !plan.IsUnknown() {
		val := plan.ValueBool()
		*target = &val
		return true
	}

	return false
}

// =============================================================================
// DN Normalization Helpers
// =============================================================================

// NormalizeDN normalizes a Distinguished Name to have consistent case.
// If normalization fails, logs a warning and returns the original DN.
// This provides a logged fallback pattern used throughout the provider.
func NormalizeDN(ctx context.Context, dn string) string {
	normalized, err := ldapclient.NormalizeDNCase(dn)
	if err != nil {
		tflog.Warn(ctx, "Failed to normalize DN case", map[string]any{
			"original_dn": dn,
			"error":       err.Error(),
		})
		return dn
	}
	return normalized
}

// DNListOrNull converts a slice of DNs to a Terraform List with normalization.
// Returns an empty list (not null) if the slice is empty.
// Each DN is normalized using NormalizeDN with logged fallback.
func DNListOrNull(ctx context.Context, dns []string, diags *diag.Diagnostics) types.List {
	if len(dns) == 0 {
		emptyList, memberDiags := types.ListValue(types.StringType, []attr.Value{})
		diags.Append(memberDiags...)
		if memberDiags.HasError() {
			return types.ListNull(types.StringType)
		}
		return emptyList
	}

	elements := make([]attr.Value, len(dns))
	for i, dn := range dns {
		normalizedDN := NormalizeDN(ctx, dn)
		elements[i] = types.StringValue(normalizedDN)
	}

	dnList, listDiags := types.ListValue(types.StringType, elements)
	diags.Append(listDiags...)
	if listDiags.HasError() {
		return types.ListNull(types.StringType)
	}
	return dnList
}

// DNSetOrNull converts a slice of DNs to a Terraform Set with normalization.
// Returns an empty set (not null) if the slice is empty.
// Each DN is normalized using NormalizeDN with logged fallback.
func DNSetOrNull(ctx context.Context, dns []string, diags *diag.Diagnostics) types.Set {
	if len(dns) == 0 {
		emptySet, setDiags := types.SetValue(types.StringType, []attr.Value{})
		diags.Append(setDiags...)
		if setDiags.HasError() {
			return types.SetNull(types.StringType)
		}
		return emptySet
	}

	elements := make([]attr.Value, len(dns))
	for i, dn := range dns {
		normalizedDN := NormalizeDN(ctx, dn)
		elements[i] = types.StringValue(normalizedDN)
	}

	dnSet, setDiags := types.SetValue(types.StringType, elements)
	diags.Append(setDiags...)
	if setDiags.HasError() {
		return types.SetNull(types.StringType)
	}
	return dnSet
}
