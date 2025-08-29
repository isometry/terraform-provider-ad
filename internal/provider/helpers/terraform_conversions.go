// Package helpers provides common utility functions for Terraform type conversions
// and manipulations that can be reused across resources, data sources, and functions.
package helpers

import (
	"context"
	"fmt"
	"maps"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
