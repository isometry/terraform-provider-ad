package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sort"

	"github.com/creasty/defaults"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/isometry/terraform-provider-ad/internal/provider/helpers"
)

var _ function.Function = &BuildHierarchyFunction{}

// BuildHierarchyConfig represents the configuration options for the build_hierarchy function.
// It uses struct tags for default values and JSON marshaling for future extensibility.
type BuildHierarchyConfig struct {
	// DefaultRoot specifies the default root value for objects without explicit root or parent.
	// If empty, objects without parent/root relationships are treated as root objects.
	DefaultRoot *string `json:"default_root,omitempty" default:""`

	// ParentField specifies the field name used to identify parent relationships in input objects.
	ParentField string `json:"parent_field,omitempty" default:"parent"`

	// RootField specifies the field name used to identify root relationships in input objects.
	// Supports boolean values (root: true to mark explicit roots) and string values
	// (root: "name" to reference a root, creating it implicitly if needed).
	RootField string `json:"root_field,omitempty" default:"root"`

	// ChildrenField specifies the field name used for the children collection in output objects.
	ChildrenField string `json:"children_field,omitempty" default:"children"`

	// MaxDepth limits the maximum depth of the hierarchy tree to prevent infinite recursion.
	// Must be greater than 0.
	MaxDepth int64 `json:"max_depth,omitempty" default:"5"`
}

// BuildHierarchyFunction implements the build_hierarchy function.
type BuildHierarchyFunction struct{}

// Metadata returns the function name and signature.
func (f BuildHierarchyFunction) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "build_hierarchy"
}

// Definition returns the function schema including parameters and return types.
func (f BuildHierarchyFunction) Definition(_ context.Context, req function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:     "Build hierarchical tree structure from objects",
		Description: "Organizes objects into a hierarchical tree structure based on parent-child or root relationships. Returns restructured objects with children grouped under their parents/roots. The function preserves all original object attributes and adds hierarchical structure. Objects that have children will gain a children field containing a map of their child objects with keys preserved. Root field supports boolean values (true to mark explicit roots) and string values (to reference roots, creating them implicitly if needed). Validation prevents objects from having both parent and root fields. Configuration map fields (all optional): default_root (string) - Default root for orphaned objects; parent_field (string) - Field name for parent reference (default: parent); root_field (string) - Field name for root reference/marking (default: root); children_field (string) - Field name for children collection (default: children); max_depth (number) - Maximum tree depth (default: 5).",
		MarkdownDescription: "Organizes objects into a hierarchical tree structure based on parent-child or root relationships. Returns restructured objects with children grouped under their parents/roots.\n\n" +
			"The function preserves all original object attributes and adds hierarchical structure. Objects that have children will gain a children field containing a map of their child objects with keys preserved.\n\n" +
			"**Root Field Semantics:**\n" +
			"- `root: true` (boolean): Explicitly marks the object as a root\n" +
			"- `root: \"name\"` (string): References a root (creates it implicitly if it doesn't exist)\n" +
			"- Objects cannot have both `parent` and `root` fields (validation error)\n\n" +
			"**Configuration map fields (all optional):**\n" +
			"- `default_root` (string): Default root for objects without parent or root relationships\n" +
			"- `parent_field` (string): Field name for parent reference in objects (default: \"parent\")\n" +
			"- `root_field` (string): Field name for root reference/marking in objects (default: \"root\")\n" +
			"- `children_field` (string): Field name for children collection in output objects (default: \"children\")\n" +
			"- `max_depth` (number): Maximum allowed tree depth (default: 5)",
		Parameters: []function.Parameter{
			function.DynamicParameter{
				Name:                "input",
				Description:         "Map with string keys and object values to organize into hierarchy. Each object can contain parent reference fields (linking to other object keys) or root fields (boolean true to mark as root, or string to reference/create roots).",
				MarkdownDescription: "Map with string keys and object values to organize into hierarchy. Each object can contain parent reference fields (linking to other object keys) or root fields (boolean `true` to mark as root, or string to reference/create roots).",
			},
			function.DynamicParameter{
				Name:        "config",
				Description: "Optional configuration map controlling hierarchy building behavior. Can be null/empty to use defaults. Supported keys: default_root (string) - assigns root value to orphaned objects; parent_field (string) - field name for parent references (default: parent); root_field (string) - field name for root references/marking (default: root); children_field (string) - field name for children collection (default: children); max_depth (number) - maximum tree depth (default: 5).",
				MarkdownDescription: "Optional configuration map controlling hierarchy building behavior. Can be null/empty to use defaults. Supports field name customization and depth limiting.\n\n" +
					"**Supported configuration keys:**\n" +
					"- `default_root` (string): Assigns this root value to objects that have no parent or explicit root relationship\n" +
					"- `parent_field` (string): Field name to look for parent references in input objects (default: \"parent\")\n" +
					"- `root_field` (string): Field name for root references/marking in objects (default: \"root\")\n" +
					"  - Boolean `true`: Explicitly marks object as root\n" +
					"  - String value: References a root (creates implicitly if needed)\n" +
					"- `children_field` (string): Field name for children collection in output objects (default: \"children\")\n" +
					"- `max_depth` (number): Maximum allowed tree depth to prevent infinite recursion (default: 5)",
				AllowNullValue: true,
			},
		},
		Return: function.DynamicReturn{},
	}
}

// Run implements the function logic.
func (f BuildHierarchyFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var input types.Dynamic
	var config types.Dynamic

	// Extract parameters with validation
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &input, &config))
	if resp.Error != nil {
		return
	}

	// Validate required parameter
	if input.IsNull() || input.IsUnknown() {
		resp.Error = function.NewFuncError("input parameter cannot be null")
		return
	}

	// Extract the input map from the dynamic value
	inputMap, err := helpers.ExtractMapFromDynamic(ctx, input)
	if err != nil {
		resp.Error = function.NewFuncError(fmt.Sprintf("Failed to extract input map: %s", err.Error()))
		return
	}

	// Parse configuration using the structured approach
	hierarchyConfig, err := f.ParseBuildHierarchyConfig(ctx, config)
	if err != nil {
		resp.Error = function.NewFuncError(fmt.Sprintf("Invalid configuration: %s", err.Error()))
		return
	}

	if len(inputMap) == 0 {
		// Return empty object for empty input
		emptyObject := types.ObjectValueMust(map[string]attr.Type{}, map[string]attr.Value{})
		result := types.DynamicValue(emptyObject)
		resp.Error = resp.Result.Set(ctx, result)
		return
	}

	// Build hierarchy using the structured configuration
	hierarchyMap, err := f.BuildHierarchy(ctx, inputMap, hierarchyConfig)
	if err != nil {
		resp.Error = function.NewFuncError(fmt.Sprintf("Failed to build hierarchy: %s", err.Error()))
		return
	}
	// Convert result back to Terraform types as a single object (not map)
	// This avoids the homogeneity requirement that maps have
	attrTypes := make(map[string]attr.Type)
	attrValues := make(map[string]attr.Value)

	for key, val := range hierarchyMap {
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
	result := types.DynamicValue(resultObject)
	resp.Error = resp.Result.Set(ctx, result)
}

// BuildHierarchy implements the core hierarchy building algorithm.
func (f BuildHierarchyFunction) BuildHierarchy(ctx context.Context, objectsMap map[string]attr.Value, config *BuildHierarchyConfig) (map[string]any, error) {
	// Phase 1: Analyze all objects and build relationships
	workingObjects := make(map[string]map[string]any)
	parentMap := make(map[string]string)     // child -> parent
	childrenMap := make(map[string][]string) // parent -> [children]
	explicitRoots := make(map[string]bool)   // objects with root: true
	implicitRoots := make(map[string]bool)   // referenced but non-existent roots

	defaultRoot := config.GetDefaultRoot()

	for key, value := range objectsMap {
		// Convert the value to Go interface{} which handles all types (Dynamic, Object, Map)
		goVal, err := helpers.TerraformValueToGo(ctx, value)
		if err != nil {
			return nil, fmt.Errorf("failed to convert object %s: %w", key, err)
		}

		// Ensure it's a map type
		obj, ok := goVal.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("object %s must be a map/object type, got %T", key, goVal)
		}
		workingObjects[key] = obj

		// Check parent field
		var hasParent bool
		var parentStr string
		if parentVal, exists := obj[config.ParentField]; exists && parentVal != nil {
			if s, ok := parentVal.(string); ok && s != "" {
				hasParent = true
				parentStr = s
			}
		}

		// Check root field (can be bool or string)
		var hasRoot bool
		var rootStr string
		var isExplicitRoot bool

		if rootVal, exists := obj[config.RootField]; exists && rootVal != nil {
			switch v := rootVal.(type) {
			case bool:
				if v {
					isExplicitRoot = true
					hasRoot = true
				}
				// false is treated as no root specified
			case string:
				if v != "" {
					hasRoot = true
					rootStr = v
				}
				// empty string treated as no root specified
				// nil/other types treated as no root specified
			}
		}

		// Validation: can't have both parent and root
		if hasParent && hasRoot {
			return nil, fmt.Errorf("object %s cannot have both %s and %s fields", key, config.ParentField, config.RootField)
		}

		// Build relationships
		if isExplicitRoot {
			// Object is explicitly marked as a root
			explicitRoots[key] = true
			// No parent relationship needed
		} else if hasParent {
			// Object has a parent
			parentMap[key] = parentStr
			childrenMap[parentStr] = append(childrenMap[parentStr], key)
		} else if hasRoot && rootStr != "" {
			// Object should be under specified root
			parentMap[key] = rootStr
			childrenMap[rootStr] = append(childrenMap[rootStr], key)

			// Track if we need to create this root
			if _, exists := workingObjects[rootStr]; !exists {
				implicitRoots[rootStr] = true
			}
		} else if defaultRoot != "" && !isExplicitRoot {
			// No parent/root specified, use default_root
			parentMap[key] = defaultRoot
			childrenMap[defaultRoot] = append(childrenMap[defaultRoot], key)

			// Track if we need to create default root
			if _, exists := workingObjects[defaultRoot]; !exists {
				implicitRoots[defaultRoot] = true
			}
		}
		// else: object has no parent and will be a root
	}

	// Phase 2: Create implicit roots (referenced but don't exist)
	for rootKey := range implicitRoots {
		if _, exists := workingObjects[rootKey]; !exists {
			// Create empty root object
			workingObjects[rootKey] = make(map[string]any)
		}
	}

	// Phase 3: Detect cycles
	if err := f.detectCycles(parentMap); err != nil {
		return nil, err
	}

	// Phase 4: Build result - only actual roots at top level
	result := make(map[string]any)
	for key, obj := range workingObjects {
		// An object is a root if:
		// 1. It has no parent in parentMap, OR
		// 2. It's explicitly marked as root (root: true)
		_, hasParent := parentMap[key]
		isRoot := !hasParent || explicitRoots[key]

		if isRoot {
			node, err := f.buildNodeTree(key, obj, workingObjects, childrenMap, config, 0)
			if err != nil {
				return nil, err
			}
			result[key] = node
		}
	}

	return result, nil
}

// buildNodeTree recursively builds a complete node tree including all descendants.
func (f BuildHierarchyFunction) buildNodeTree(key string, obj map[string]any, allObjects map[string]map[string]any, childrenMap map[string][]string, config *BuildHierarchyConfig, depth int) (map[string]any, error) {
	if int64(depth) > config.MaxDepth {
		return nil, fmt.Errorf("maximum depth %d exceeded at depth %d", config.MaxDepth, depth)
	}

	// Create a copy of the node
	node := make(map[string]any)
	maps.Copy(node, obj)

	// Add children if they exist
	if childKeys := childrenMap[key]; len(childKeys) > 0 {
		// Sort for consistent ordering
		sort.Strings(childKeys)

		children := make(map[string]any)
		for _, childKey := range childKeys {
			if childObj, exists := allObjects[childKey]; exists {
				childNode, err := f.buildNodeTree(childKey, childObj, allObjects, childrenMap, config, depth+1)
				if err != nil {
					return nil, err
				}
				children[childKey] = childNode
			}
		}

		if len(children) > 0 {
			node[config.ChildrenField] = children
		}
	}

	return node, nil
}

// detectCycles detects circular references in parent-child relationships.
func (f BuildHierarchyFunction) detectCycles(parentMap map[string]string) error {
	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)

	var dfs func(string) error
	dfs = func(node string) error {
		if recursionStack[node] {
			return fmt.Errorf("circular reference detected involving object: %s", node)
		}
		if visited[node] {
			return nil
		}

		visited[node] = true
		recursionStack[node] = true

		if parent, hasParent := parentMap[node]; hasParent {
			if err := dfs(parent); err != nil {
				return err
			}
		}

		recursionStack[node] = false
		return nil
	}

	for node := range parentMap {
		if !visited[node] {
			if err := dfs(node); err != nil {
				return err
			}
		}
	}

	return nil
}

// ParseBuildHierarchyConfig converts a Terraform Dynamic config value to a BuildHierarchyConfig struct.
// It applies default values using the creasty/defaults library and handles null/empty config gracefully.
//
// Parameters:
//   - ctx: Context for the operation
//   - configValue: Terraform Dynamic value containing the configuration map/object
//
// Returns:
//   - *BuildHierarchyConfig: Parsed configuration with defaults applied
//   - error: Any error encountered during parsing or validation
func (f BuildHierarchyFunction) ParseBuildHierarchyConfig(ctx context.Context, configValue types.Dynamic) (*BuildHierarchyConfig, error) {
	config := &BuildHierarchyConfig{}

	// Apply defaults first
	if err := defaults.Set(config); err != nil {
		return nil, fmt.Errorf("failed to set default values: %w", err)
	}

	// Handle null or unknown config - return defaults
	if configValue.IsNull() || configValue.IsUnknown() {
		return config, nil
	}

	// Extract configuration values from the dynamic value
	configMap, err := f.extractConfigFromDynamic(ctx, configValue)
	if err != nil {
		return nil, fmt.Errorf("failed to extract config map: %w", err)
	}

	// Apply configuration values, preserving defaults for missing values
	if val, exists := configMap["default_root"]; exists && val != nil {
		if str, ok := val.(string); ok {
			config.DefaultRoot = &str
		} else {
			return nil, fmt.Errorf("default_root must be a string, got %T", val)
		}
	}

	if val, exists := configMap["parent_field"]; exists && val != nil {
		if str, ok := val.(string); ok {
			if str == "" {
				return nil, fmt.Errorf("parent_field cannot be empty")
			}
			config.ParentField = str
		} else {
			return nil, fmt.Errorf("parent_field must be a string, got %T", val)
		}
	}

	if val, exists := configMap["root_field"]; exists && val != nil {
		if str, ok := val.(string); ok {
			if str == "" {
				return nil, fmt.Errorf("root_field cannot be empty")
			}
			config.RootField = str
		} else {
			return nil, fmt.Errorf("root_field must be a string, got %T", val)
		}
	}

	if val, exists := configMap["children_field"]; exists && val != nil {
		if str, ok := val.(string); ok {
			if str == "" {
				return nil, fmt.Errorf("children_field cannot be empty")
			}
			config.ChildrenField = str
		} else {
			return nil, fmt.Errorf("children_field must be a string, got %T", val)
		}
	}

	if val, exists := configMap["max_depth"]; exists && val != nil {
		switch v := val.(type) {
		case int64:
			config.MaxDepth = v
		case float64:
			config.MaxDepth = int64(v)
		default:
			return nil, fmt.Errorf("max_depth must be a number, got %T", val)
		}
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// Validate validates the configuration values and returns an error if any are invalid.
func (c *BuildHierarchyConfig) Validate() error {
	if c.MaxDepth < 1 {
		return fmt.Errorf("max_depth must be greater than 0, got %d", c.MaxDepth)
	}

	if c.ParentField == "" {
		return fmt.Errorf("parent_field cannot be empty")
	}

	if c.RootField == "" {
		return fmt.Errorf("root_field cannot be empty")
	}

	if c.ChildrenField == "" {
		return fmt.Errorf("children_field cannot be empty")
	}

	return nil
}

// GetDefaultRoot returns the default root value, handling nil pointer gracefully.
func (c *BuildHierarchyConfig) GetDefaultRoot() string {
	if c.DefaultRoot == nil {
		return ""
	}
	return *c.DefaultRoot
}

// ToTerraformMap converts the configuration back to a map suitable for Terraform operations.
// This can be useful for testing, debugging, or state operations.
func (c *BuildHierarchyConfig) ToTerraformMap() map[string]any {
	result := map[string]any{
		"parent_field":   c.ParentField,
		"root_field":     c.RootField,
		"children_field": c.ChildrenField,
		"max_depth":      c.MaxDepth,
	}

	if c.DefaultRoot != nil && *c.DefaultRoot != "" {
		result["default_root"] = *c.DefaultRoot
	}

	return result
}

// ToJSON converts the configuration to JSON format for debugging or logging purposes.
func (c *BuildHierarchyConfig) ToJSON() (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config to JSON: %w", err)
	}
	return string(data), nil
}

// extractConfigFromDynamic extracts configuration map from a dynamic value.
// This is a helper function that handles both map and object types.
func (f BuildHierarchyFunction) extractConfigFromDynamic(ctx context.Context, value types.Dynamic) (map[string]any, error) {
	underlyingVal := value.UnderlyingValue()

	var configAttrs map[string]attr.Value

	// Handle map type
	if mapVal, ok := underlyingVal.(types.Map); ok {
		configAttrs = mapVal.Elements()
	} else if objVal, ok := underlyingVal.(types.Object); ok {
		// Handle object type
		configAttrs = objVal.Attributes()
	} else {
		return nil, fmt.Errorf("expected map or object type for config, got %T", underlyingVal)
	}

	result := make(map[string]any)
	for key, val := range configAttrs {
		goVal, err := helpers.TerraformValueToGo(ctx, val)
		if err != nil {
			return nil, fmt.Errorf("failed to convert config field %s: %w", key, err)
		}
		result[key] = goVal
	}

	return result, nil
}

// NewBuildHierarchyFunction creates a new instance of the build_hierarchy function.
func NewBuildHierarchyFunction() function.Function {
	return &BuildHierarchyFunction{}
}
