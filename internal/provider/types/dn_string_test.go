package types

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDNStringType_String verifies the human-readable name of the type.
func TestDNStringType_String(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "DNStringType", DNStringType{}.String())
}

// TestDNStringType_ValueType verifies the Value type returned is a DNStringValue.
func TestDNStringType_ValueType(t *testing.T) {
	t.Parallel()

	v := DNStringType{}.ValueType(context.Background())
	_, ok := v.(DNStringValue)
	assert.True(t, ok, "expected *DNStringValue, got %T", v)
}

// TestDNStringType_Equal verifies the type only equals itself and not a plain StringType.
func TestDNStringType_Equal(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		lhs      DNStringType
		rhs      attr.Type
		expected bool
	}{
		"equal_self":                {lhs: DNStringType{}, rhs: DNStringType{}, expected: true},
		"not_equal_basetype_string": {lhs: DNStringType{}, rhs: basetypes.StringType{}, expected: false},
		"not_equal_nil":             {lhs: DNStringType{}, rhs: nil, expected: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.lhs.Equal(tc.rhs))
		})
	}
}

// TestDNStringType_ValueFromString verifies wrapping a StringValue produces a DNStringValue
// that preserves the original string content.
func TestDNStringType_ValueFromString(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	in := basetypes.NewStringValue("CN=test,DC=example,DC=com")

	got, diags := DNStringType{}.ValueFromString(ctx, in)
	require.False(t, diags.HasError(), "unexpected diagnostics: %s", diags)

	dnv, ok := got.(DNStringValue)
	require.True(t, ok, "expected DNStringValue, got %T", got)
	assert.Equal(t, "CN=test,DC=example,DC=com", dnv.ValueString())
}

// TestDNStringType_ValueFromTerraform round-trips a string through the framework value layer.
func TestDNStringType_ValueFromTerraform(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tfVal := tftypes.NewValue(tftypes.String, "CN=test,DC=example,DC=com")

	got, err := DNStringType{}.ValueFromTerraform(ctx, tfVal)
	require.NoError(t, err)

	dnv, ok := got.(DNStringValue)
	require.True(t, ok, "expected DNStringValue, got %T", got)
	assert.Equal(t, "CN=test,DC=example,DC=com", dnv.ValueString())
	assert.False(t, dnv.IsNull())
	assert.False(t, dnv.IsUnknown())
}

// TestDNStringType_ValueFromTerraform_Null verifies null round-trips correctly.
func TestDNStringType_ValueFromTerraform_Null(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tfVal := tftypes.NewValue(tftypes.String, nil)

	got, err := DNStringType{}.ValueFromTerraform(ctx, tfVal)
	require.NoError(t, err)

	dnv, ok := got.(DNStringValue)
	require.True(t, ok, "expected DNStringValue, got %T", got)
	assert.True(t, dnv.IsNull())
}

// TestDNStringType_ValueFromTerraform_Unknown verifies unknown round-trips correctly.
func TestDNStringType_ValueFromTerraform_Unknown(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tfVal := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)

	got, err := DNStringType{}.ValueFromTerraform(ctx, tfVal)
	require.NoError(t, err)

	dnv, ok := got.(DNStringValue)
	require.True(t, ok, "expected DNStringValue, got %T", got)
	assert.True(t, dnv.IsUnknown())
}

// TestDNStringValue_Type verifies the Type() method returns a DNStringType.
func TestDNStringValue_Type(t *testing.T) {
	t.Parallel()

	v := DNString("CN=x,DC=y")
	typ := v.Type(context.Background())
	_, ok := typ.(DNStringType)
	assert.True(t, ok, "expected DNStringType, got %T", typ)
}

// TestDNStringValue_Equal verifies strict equality behavior (not semantic).
func TestDNStringValue_Equal(t *testing.T) {
	t.Parallel()

	a := DNString("CN=test,DC=example,DC=com")
	b := DNString("CN=test,DC=example,DC=com")
	c := DNString("cn=test,dc=example,dc=com")

	assert.True(t, a.Equal(b), "identical DNStringValues must be Equal")
	// Equal is string-exact: case differences are NOT covered by Equal.
	assert.False(t, a.Equal(c), "Equal should be byte-exact; semantic equality is separate")

	// Cross-type comparison fails.
	assert.False(t, a.Equal(basetypes.NewStringValue("CN=test,DC=example,DC=com")))
}

// TestDNStringValue_StringSemanticEquals exercises the core drift-prevention contract.
func TestDNStringValue_StringSemanticEquals(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := map[string]struct {
		old           DNStringValue
		new           DNStringValue
		expectedEqual bool
		expectErrDiag bool
	}{
		"identical": {
			old:           DNString("CN=test,DC=example,DC=com"),
			new:           DNString("CN=test,DC=example,DC=com"),
			expectedEqual: true,
		},
		"case_diff_attr_types_only": {
			old:           DNString("CN=Test,DC=example,DC=com"),
			new:           DNString("cn=Test,dc=example,dc=com"),
			expectedEqual: true,
		},
		"case_diff_but_value_case_preserved_should_differ": {
			// Note: the normalizer uppercases attribute TYPES but leaves VALUES as-is.
			// So two DNs whose values differ in case should NOT be semantically equal.
			old:           DNString("CN=Test,DC=example,DC=com"),
			new:           DNString("CN=test,DC=example,DC=com"),
			expectedEqual: false,
		},
		"structural_difference": {
			old:           DNString("CN=Test,OU=Users,DC=example,DC=com"),
			new:           DNString("CN=Test,OU=Admins,DC=example,DC=com"),
			expectedEqual: false,
		},
		"whitespace_around_equals_equals_compact": {
			old:           DNString("CN=John,OU=Users,DC=example,DC=com"),
			new:           DNString("cn = John, ou = Users, dc = example, dc = com"),
			expectedEqual: true,
		},
		"escaped_comma_case_insensitive_types": {
			old:           DNString("CN=Smith\\, John,OU=People,DC=x"),
			new:           DNString("cn=Smith\\, John,ou=People,dc=x"),
			expectedEqual: true,
		},
		"escaped_comma_structural_difference": {
			old:           DNString("CN=Smith\\, John,OU=People,DC=x"),
			new:           DNString("CN=Smith\\, Jane,OU=People,DC=x"),
			expectedEqual: false,
		},
		"both_empty": {
			old:           DNString(""),
			new:           DNString(""),
			expectedEqual: true,
		},
		"one_empty_one_set": {
			old:           DNString(""),
			new:           DNString("CN=x,DC=y"),
			expectedEqual: false,
		},
		"non_dn_fallback_case_insensitive_equal": {
			// When NormalizeDNCase fails, the implementation falls back to strings.EqualFold.
			old:           DNString("not a dn"),
			new:           DNString("NOT A DN"),
			expectedEqual: true,
		},
		"non_dn_fallback_not_equal": {
			old:           DNString("not a dn"),
			new:           DNString("also not a dn"),
			expectedEqual: false,
		},
		"null_vs_null_equal": {
			old:           DNStringNull(),
			new:           DNStringNull(),
			expectedEqual: true,
		},
		"unknown_vs_unknown_equal": {
			old:           DNStringUnknown(),
			new:           DNStringUnknown(),
			expectedEqual: true,
		},
		"null_vs_known_not_equal": {
			old:           DNStringNull(),
			new:           DNString("CN=test,DC=x"),
			expectedEqual: false,
		},
		"unknown_vs_known_not_equal": {
			old:           DNStringUnknown(),
			new:           DNString("CN=test,DC=x"),
			expectedEqual: false,
		},
		"null_vs_unknown_not_equal": {
			old:           DNStringNull(),
			new:           DNStringUnknown(),
			expectedEqual: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, diags := tc.old.StringSemanticEquals(ctx, tc.new)
			if tc.expectErrDiag {
				assert.True(t, diags.HasError(), "expected error diagnostic, got none")
			} else {
				assert.False(t, diags.HasError(), "unexpected error diagnostics: %s", diags)
			}
			assert.Equal(t, tc.expectedEqual, got)
		})
	}
}

// TestDNStringValue_StringSemanticEquals_WrongType verifies an error diagnostic is
// emitted when the "new" value is not a DNStringValue.
func TestDNStringValue_StringSemanticEquals_WrongType(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	v := DNString("CN=x,DC=y")
	other := basetypes.NewStringValue("CN=x,DC=y")

	eq, diags := v.StringSemanticEquals(ctx, other)
	assert.False(t, eq)
	assert.True(t, diags.HasError(), "expected error diagnostic when passed a plain StringValue")
}

// TestDNStringValue_StringSemanticEquals_Symmetry asserts the relation is symmetric
// for common inputs (it should be, since the underlying normalizer is deterministic).
func TestDNStringValue_StringSemanticEquals_Symmetry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	a := DNString("CN=Alice,OU=People,DC=example,DC=com")
	b := DNString("cn=Alice,ou=People,dc=example,dc=com")

	fwd, diags := a.StringSemanticEquals(ctx, b)
	require.False(t, diags.HasError())
	rev, diags := b.StringSemanticEquals(ctx, a)
	require.False(t, diags.HasError())

	assert.True(t, fwd)
	assert.True(t, rev)
}

// TestDNString_Helpers verifies the constructors produce the expected states.
func TestDNString_Helpers(t *testing.T) {
	t.Parallel()

	v := DNString("CN=x,DC=y")
	assert.False(t, v.IsNull())
	assert.False(t, v.IsUnknown())
	assert.Equal(t, "CN=x,DC=y", v.ValueString())

	n := DNStringNull()
	assert.True(t, n.IsNull())
	assert.False(t, n.IsUnknown())

	u := DNStringUnknown()
	assert.False(t, u.IsNull())
	assert.True(t, u.IsUnknown())
}

// TestDNStringValue_RoundTrip round-trips a value through the Terraform type layer
// and verifies semantic equality is preserved.
func TestDNStringValue_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	original := DNString("CN=Alice,OU=People,DC=example,DC=com")

	tfVal, err := original.ToTerraformValue(ctx)
	require.NoError(t, err)

	got, err := DNStringType{}.ValueFromTerraform(ctx, tfVal)
	require.NoError(t, err)

	dnv, ok := got.(DNStringValue)
	require.True(t, ok, "expected DNStringValue, got %T", got)

	assert.Equal(t, original.ValueString(), dnv.ValueString())

	eq, diags := original.StringSemanticEquals(ctx, dnv)
	require.False(t, diags.HasError())
	assert.True(t, eq, "round-tripped value must be semantically equal to the original")
}
