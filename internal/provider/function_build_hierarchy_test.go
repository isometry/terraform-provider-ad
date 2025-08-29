package provider_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isometry/terraform-provider-ad/internal/provider"
	"github.com/isometry/terraform-provider-ad/internal/provider/helpers"
)

// Helper function to execute the build_hierarchy function with Go values.
func executeFunction(t *testing.T, input map[string]any, config map[string]any) (map[string]any, error) {
	ctx := context.Background()
	f := &provider.BuildHierarchyFunction{}

	// Convert input to Terraform types
	inputVal, err := helpers.GoValueToTerraform(ctx, input)
	require.NoError(t, err)
	inputDynamic := types.DynamicValue(inputVal)

	// Convert config to Terraform types
	var configDynamic types.Dynamic
	if config == nil {
		configDynamic = types.DynamicNull()
	} else {
		configVal, err := helpers.GoValueToTerraform(ctx, config)
		require.NoError(t, err)
		configDynamic = types.DynamicValue(configVal)
	}

	// Call the function
	var req function.RunRequest
	resp := function.RunResponse{
		Result: function.NewResultData(types.DynamicUnknown()),
	}
	req.Arguments = function.NewArgumentsData([]attr.Value{inputDynamic, configDynamic})

	f.Run(ctx, req, &resp)

	if resp.Error != nil {
		return nil, resp.Error
	}

	// Extract result
	resultValue := resp.Result.Value()
	resultDynamic, ok := resultValue.(types.Dynamic)
	if !ok {
		return nil, assert.AnError
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

func TestBuildHierarchyFunction_Metadata(t *testing.T) {
	ctx := context.Background()
	f := &provider.BuildHierarchyFunction{}

	var req function.MetadataRequest
	var resp function.MetadataResponse

	f.Metadata(ctx, req, &resp)

	assert.Equal(t, "build_hierarchy", resp.Name)
}

func TestBuildHierarchyFunction_Definition(t *testing.T) {
	ctx := context.Background()
	f := &provider.BuildHierarchyFunction{}

	var req function.DefinitionRequest
	var resp function.DefinitionResponse

	f.Definition(ctx, req, &resp)

	assert.NotEmpty(t, resp.Definition.Summary)
	assert.Len(t, resp.Definition.Parameters, 2)

	// Verify parameter names and types
	assert.Equal(t, "input", resp.Definition.Parameters[0].GetName())
	assert.Equal(t, "config", resp.Definition.Parameters[1].GetName())
}

func TestBuildHierarchy_SimpleHierarchy(t *testing.T) {
	input := map[string]any{
		"root": map[string]any{
			"id":   "root",
			"name": "Root Node",
		},
		"child1": map[string]any{
			"id":     "child1",
			"name":   "Child 1",
			"parent": "root",
		},
		"child2": map[string]any{
			"id":     "child2",
			"name":   "Child 2",
			"parent": "root",
		},
	}

	result, err := executeFunction(t, input, nil)
	require.NoError(t, err)

	// Only root should exist at top level
	require.Len(t, result, 1)
	rootNode, ok := result["root"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "root", rootNode["id"])

	// Root should have children
	children, ok := rootNode["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, children, 2)

	// Verify child1 and child2 exist in children
	child1, ok := children["child1"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "child1", child1["id"])
	require.Equal(t, "Child 1", child1["name"])

	child2, ok := children["child2"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "child2", child2["id"])
	require.Equal(t, "Child 2", child2["name"])

	// Verify children don't exist at top level
	_, existsAtTop := result["child1"]
	assert.False(t, existsAtTop)
	_, existsAtTop = result["child2"]
	assert.False(t, existsAtTop)
}

func TestBuildHierarchy_MultiLevel(t *testing.T) {
	input := map[string]any{
		"level1": map[string]any{
			"id": "level1",
		},
		"level2": map[string]any{
			"id":     "level2",
			"parent": "level1",
		},
		"level3": map[string]any{
			"id":     "level3",
			"parent": "level2",
		},
	}

	result, err := executeFunction(t, input, nil)
	require.NoError(t, err)

	// Only level1 at top
	require.Len(t, result, 1)
	level1, ok := result["level1"].(map[string]any)
	require.True(t, ok)

	// level2 under level1
	children, ok := level1["children"].(map[string]any)
	require.True(t, ok)
	level2, ok := children["level2"].(map[string]any)
	require.True(t, ok)

	// level3 under level2
	grandchildren, ok := level2["children"].(map[string]any)
	require.True(t, ok)
	level3, ok := grandchildren["level3"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "level3", level3["id"])
}

func TestBuildHierarchy_MultipleRoots(t *testing.T) {
	input := map[string]any{
		"root1": map[string]any{
			"id": "root1",
		},
		"root2": map[string]any{
			"id": "root2",
		},
		"child1": map[string]any{
			"id":     "child1",
			"parent": "root1",
		},
		"child2": map[string]any{
			"id":     "child2",
			"parent": "root2",
		},
	}

	result, err := executeFunction(t, input, nil)
	require.NoError(t, err)

	// Both roots at top level
	require.Len(t, result, 2)

	root1, ok := result["root1"].(map[string]any)
	require.True(t, ok)
	children1, ok := root1["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, children1, 1)
	child1, ok := children1["child1"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "child1", child1["id"])

	root2, ok := result["root2"].(map[string]any)
	require.True(t, ok)
	children2, ok := root2["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, children2, 1)
	child2, ok := children2["child2"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "child2", child2["id"])
}

func TestBuildHierarchy_CircularReference(t *testing.T) {
	input := map[string]any{
		"node1": map[string]any{
			"id":     "node1",
			"parent": "node2",
		},
		"node2": map[string]any{
			"id":     "node2",
			"parent": "node1",
		},
	}

	_, err := executeFunction(t, input, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "circular reference detected")
}

func TestBuildHierarchy_MaxDepthExceeded(t *testing.T) {
	input := map[string]any{
		"level1": map[string]any{"id": "level1"},
		"level2": map[string]any{"id": "level2", "parent": "level1"},
		"level3": map[string]any{"id": "level3", "parent": "level2"},
		"level4": map[string]any{"id": "level4", "parent": "level3"},
	}

	config := map[string]any{
		"max_depth": 2,
	}

	_, err := executeFunction(t, input, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum depth")
}

func TestBuildHierarchy_EmptyInput(t *testing.T) {
	input := map[string]any{}

	result, err := executeFunction(t, input, nil)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestBuildHierarchy_CustomFieldNames(t *testing.T) {
	input := map[string]any{
		"manager": map[string]any{
			"id": "manager",
		},
		"employee": map[string]any{
			"id":   "employee",
			"boss": "manager",
		},
	}

	config := map[string]any{
		"parent_field":   "boss",
		"children_field": "subordinates",
	}

	result, err := executeFunction(t, input, config)
	require.NoError(t, err)

	require.Len(t, result, 1)
	manager, ok := result["manager"].(map[string]any)
	require.True(t, ok)
	subordinates, ok := manager["subordinates"].(map[string]any)
	require.True(t, ok)
	require.Len(t, subordinates, 1)
	employee, ok := subordinates["employee"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "employee", employee["id"])
}

func TestBuildHierarchy_ExplicitRootBoolean(t *testing.T) {
	input := map[string]any{
		"top": map[string]any{
			"id":   "top",
			"root": true, // Explicit root
		},
		"child": map[string]any{
			"id":     "child",
			"parent": "top",
		},
	}

	result, err := executeFunction(t, input, nil)
	require.NoError(t, err)

	require.Len(t, result, 1)
	top, ok := result["top"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "top", top["id"])
	require.Equal(t, true, top["root"]) // Root field preserved

	children, ok := top["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, children, 1)
	child, ok := children["child"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "child", child["id"])
}

func TestBuildHierarchy_ImplicitRootCreation(t *testing.T) {
	input := map[string]any{
		"child": map[string]any{
			"id":   "child",
			"root": "implicit_root", // Reference non-existent root
		},
	}

	result, err := executeFunction(t, input, nil)
	require.NoError(t, err)

	require.Len(t, result, 1)
	// Implicit root should be created
	implicitRoot, ok := result["implicit_root"].(map[string]any)
	require.True(t, ok)

	children, ok := implicitRoot["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, children, 1)
	child, ok := children["child"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "child", child["id"])
}

func TestBuildHierarchy_DefaultRootFallback(t *testing.T) {
	input := map[string]any{
		"orphan": map[string]any{
			"id": "orphan", // No parent, no root
		},
	}

	config := map[string]any{
		"default_root": "fallback_root",
	}

	result, err := executeFunction(t, input, config)
	require.NoError(t, err)

	require.Len(t, result, 1)
	// Default root should be created
	fallbackRoot, ok := result["fallback_root"].(map[string]any)
	require.True(t, ok)

	children, ok := fallbackRoot["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, children, 1)
	orphan, ok := children["orphan"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "orphan", orphan["id"])
}

func TestBuildHierarchy_BothParentAndRootError(t *testing.T) {
	input := map[string]any{
		"invalid": map[string]any{
			"id":     "invalid",
			"parent": "some_parent",
			"root":   "some_root", // Can't have both
		},
	}

	_, err := executeFunction(t, input, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot have both parent and root fields")
}

func TestBuildHierarchy_RootStringReference(t *testing.T) {
	input := map[string]any{
		"existing_root": map[string]any{
			"id": "existing_root",
		},
		"child": map[string]any{
			"id":   "child",
			"root": "existing_root", // Reference existing object
		},
	}

	result, err := executeFunction(t, input, nil)
	require.NoError(t, err)

	require.Len(t, result, 1)
	existingRoot, ok := result["existing_root"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "existing_root", existingRoot["id"])

	children, ok := existingRoot["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, children, 1)
	child, ok := children["child"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "child", child["id"])
}

func TestBuildHierarchy_MixedRootScenarios(t *testing.T) {
	input := map[string]any{
		"explicit_root": map[string]any{
			"id":   "explicit_root",
			"root": true, // Explicit root
		},
		"child1": map[string]any{
			"id":     "child1",
			"parent": "explicit_root", // Parent relationship
		},
		"child2": map[string]any{
			"id":   "child2",
			"root": "explicit_root", // Root reference
		},
		"orphan": map[string]any{
			"id": "orphan", // Will use default_root
		},
		"implicit_child": map[string]any{
			"id":   "implicit_child",
			"root": "implicit_root", // Creates implicit root
		},
	}

	config := map[string]any{
		"default_root": "default",
	}

	result, err := executeFunction(t, input, config)
	require.NoError(t, err)

	require.Len(t, result, 3) // explicit_root, default, implicit_root

	// Check explicit root
	explicitRoot, ok := result["explicit_root"].(map[string]any)
	require.True(t, ok)
	children, ok := explicitRoot["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, children, 2) // child1 and child2

	// Check default root
	defaultRoot, ok := result["default"].(map[string]any)
	require.True(t, ok)
	defaultChildren, ok := defaultRoot["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, defaultChildren, 1) // orphan

	// Check implicit root
	implicitRoot, ok := result["implicit_root"].(map[string]any)
	require.True(t, ok)
	implicitChildren, ok := implicitRoot["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, implicitChildren, 1) // implicit_child
}

func TestBuildHierarchy_CustomRootField(t *testing.T) {
	input := map[string]any{
		"top": map[string]any{
			"id":      "top",
			"is_root": true, // Uses custom root field
		},
		"child": map[string]any{
			"id":      "child",
			"is_root": "top", // References root using custom field
		},
	}

	config := map[string]any{
		"root_field": "is_root",
	}

	result, err := executeFunction(t, input, config)
	require.NoError(t, err)

	require.Len(t, result, 1)
	top, ok := result["top"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "top", top["id"])

	children, ok := top["children"].(map[string]any)
	require.True(t, ok)
	require.Len(t, children, 1)
	child, ok := children["child"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "child", child["id"])
}

func TestBuildHierarchy_EmptyRootValues(t *testing.T) {
	input := map[string]any{
		"obj1": map[string]any{
			"id":   "obj1",
			"root": "", // Empty string
		},
		"obj2": map[string]any{
			"id":   "obj2",
			"root": false, // Boolean false
		},
		"obj3": map[string]any{
			"id": "obj3", // No root field
		},
	}

	result, err := executeFunction(t, input, nil)
	require.NoError(t, err)

	// All should be at top level since no valid roots
	require.Len(t, result, 3)
	require.Contains(t, result, "obj1")
	require.Contains(t, result, "obj2")
	require.Contains(t, result, "obj3")
}
