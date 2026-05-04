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

// mustDNStringSet builds a DNStringSetValue from a slice, asserting no diagnostics.
func mustDNStringSet(t *testing.T, elements []string) DNStringSetValue {
	t.Helper()
	v, diags := DNStringSet(context.Background(), elements)
	require.False(t, diags.HasError(), "unexpected diagnostics building test set: %s", diags)
	return v
}

// TestDNStringSetType_String verifies the human-readable name.
func TestDNStringSetType_String(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "DNStringSetType", DNStringSetType{}.String())
}

// TestDNStringSetType_ValueType verifies the Value type returned.
func TestDNStringSetType_ValueType(t *testing.T) {
	t.Parallel()
	v := DNStringSetType{}.ValueType(context.Background())
	_, ok := v.(DNStringSetValue)
	assert.True(t, ok, "expected DNStringSetValue, got %T", v)
}

// TestDNStringSetType_Equal verifies the type only equals itself.
func TestDNStringSetType_Equal(t *testing.T) {
	t.Parallel()

	lhs := NewDNStringSetType()

	tests := map[string]struct {
		rhs      attr.Type
		expected bool
	}{
		"equal_self": {
			rhs:      NewDNStringSetType(),
			expected: true,
		},
		"not_equal_basetypes_set_of_string": {
			rhs:      basetypes.SetType{ElemType: basetypes.StringType{}},
			expected: false,
		},
		"not_equal_nil": {
			rhs:      nil,
			expected: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, lhs.Equal(tc.rhs))
		})
	}
}

// TestDNStringSetType_ValueFromSet verifies wrapping a SetValue produces a DNStringSetValue.
func TestDNStringSetType_ValueFromSet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	in, diags := basetypes.NewSetValue(basetypes.StringType{}, []attr.Value{
		basetypes.NewStringValue("CN=a,DC=x"),
		basetypes.NewStringValue("CN=b,DC=x"),
	})
	require.False(t, diags.HasError())

	got, diags := NewDNStringSetType().ValueFromSet(ctx, in)
	require.False(t, diags.HasError())

	sv, ok := got.(DNStringSetValue)
	require.True(t, ok, "expected DNStringSetValue, got %T", got)
	assert.Equal(t, 2, len(sv.Elements()))
}

// TestDNStringSetType_ValueFromTerraform round-trips through the Terraform value layer.
func TestDNStringSetType_ValueFromTerraform(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tfVal := tftypes.NewValue(
		tftypes.Set{ElementType: tftypes.String},
		[]tftypes.Value{
			tftypes.NewValue(tftypes.String, "CN=a,DC=x"),
			tftypes.NewValue(tftypes.String, "CN=b,DC=x"),
		},
	)

	got, err := NewDNStringSetType().ValueFromTerraform(ctx, tfVal)
	require.NoError(t, err)

	sv, ok := got.(DNStringSetValue)
	require.True(t, ok, "expected DNStringSetValue, got %T", got)
	assert.False(t, sv.IsNull())
	assert.False(t, sv.IsUnknown())
	assert.Equal(t, 2, len(sv.Elements()))
}

// TestDNStringSetType_ValueFromTerraform_Null verifies null set round-trips.
func TestDNStringSetType_ValueFromTerraform_Null(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tfVal := tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil)

	got, err := NewDNStringSetType().ValueFromTerraform(ctx, tfVal)
	require.NoError(t, err)

	sv, ok := got.(DNStringSetValue)
	require.True(t, ok, "expected DNStringSetValue, got %T", got)
	assert.True(t, sv.IsNull())
}

// TestDNStringSetType_ValueFromTerraform_Unknown verifies unknown set round-trips.
func TestDNStringSetType_ValueFromTerraform_Unknown(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tfVal := tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, tftypes.UnknownValue)

	got, err := NewDNStringSetType().ValueFromTerraform(ctx, tfVal)
	require.NoError(t, err)

	sv, ok := got.(DNStringSetValue)
	require.True(t, ok, "expected DNStringSetValue, got %T", got)
	assert.True(t, sv.IsUnknown())
}

// TestDNStringSetValue_Type verifies the Type() method returns a DNStringSetType.
func TestDNStringSetValue_Type(t *testing.T) {
	t.Parallel()

	v := mustDNStringSet(t, []string{"CN=a,DC=x"})
	typ := v.Type(context.Background())
	_, ok := typ.(DNStringSetType)
	assert.True(t, ok, "expected DNStringSetType, got %T", typ)
}

// TestDNStringSetValue_Equal verifies byte-exact equality behavior.
func TestDNStringSetValue_Equal(t *testing.T) {
	t.Parallel()

	a := mustDNStringSet(t, []string{"CN=a,DC=x", "CN=b,DC=x"})
	b := mustDNStringSet(t, []string{"CN=a,DC=x", "CN=b,DC=x"})
	c := mustDNStringSet(t, []string{"cn=a,dc=x", "cn=b,dc=x"})

	assert.True(t, a.Equal(b), "identical sets must be Equal")
	// Equal is byte-exact (set-based, but element-by-element exact string compare):
	// semantic case equality is separate.
	assert.False(t, a.Equal(c), "Equal should be byte-exact on elements; semantic equality is separate")
}

// TestDNStringSetValue_SetSemanticEquals covers the core drift-prevention contract
// for sets of DNs.
func TestDNStringSetValue_SetSemanticEquals(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := map[string]struct {
		old           DNStringSetValue
		new           DNStringSetValue
		expectedEqual bool
	}{
		"identical": {
			old:           mustDNStringSet(t, []string{"CN=A,DC=x", "CN=B,DC=x"}),
			new:           mustDNStringSet(t, []string{"CN=A,DC=x", "CN=B,DC=x"}),
			expectedEqual: true,
		},
		"same_dns_different_attr_type_case": {
			old:           mustDNStringSet(t, []string{"CN=A,DC=x"}),
			new:           mustDNStringSet(t, []string{"cn=A,dc=x"}),
			expectedEqual: true,
		},
		"different_cardinality": {
			old:           mustDNStringSet(t, []string{"CN=A,DC=x"}),
			new:           mustDNStringSet(t, []string{"CN=A,DC=x", "CN=B,DC=x"}),
			expectedEqual: false,
		},
		"order_independent": {
			old:           mustDNStringSet(t, []string{"CN=A,DC=x", "CN=B,DC=x"}),
			new:           mustDNStringSet(t, []string{"CN=B,DC=x", "CN=A,DC=x"}),
			expectedEqual: true,
		},
		"mixed_case_across_set_order_independent": {
			// Only attribute TYPE case varies; values (A, B) are preserved.
			// This is the real drift pattern AD causes: same values, different type case.
			old:           mustDNStringSet(t, []string{"CN=A,DC=x", "CN=B,DC=x"}),
			new:           mustDNStringSet(t, []string{"cn=B,dc=x", "cn=A,dc=x"}),
			expectedEqual: true,
		},
		"structural_difference": {
			old:           mustDNStringSet(t, []string{"CN=A,OU=Users,DC=x"}),
			new:           mustDNStringSet(t, []string{"CN=A,OU=Admins,DC=x"}),
			expectedEqual: false,
		},
		"value_case_difference_not_equal": {
			// Normalizer preserves value case; attribute values differing in case
			// should NOT be semantically equal.
			old:           mustDNStringSet(t, []string{"CN=Alice,DC=x"}),
			new:           mustDNStringSet(t, []string{"CN=alice,DC=x"}),
			expectedEqual: false,
		},
		"escaped_values_case_insensitive_types": {
			old:           mustDNStringSet(t, []string{"CN=Smith\\, John,OU=People,DC=x"}),
			new:           mustDNStringSet(t, []string{"cn=Smith\\, John,ou=People,dc=x"}),
			expectedEqual: true,
		},
		"both_empty_sets_equal": {
			old:           mustDNStringSet(t, []string{}),
			new:           mustDNStringSet(t, []string{}),
			expectedEqual: true,
		},
		"one_empty_one_populated_not_equal": {
			old:           mustDNStringSet(t, []string{}),
			new:           mustDNStringSet(t, []string{"CN=A,DC=x"}),
			expectedEqual: false,
		},
		"non_dn_fallback_case_insensitive_equal": {
			// When NormalizeDNCaseBatch fails, implementation falls back to
			// case-insensitive string set comparison.
			old:           mustDNStringSet(t, []string{"not a dn", "also not"}),
			new:           mustDNStringSet(t, []string{"NOT A DN", "ALSO NOT"}),
			expectedEqual: true,
		},
		"non_dn_fallback_different_content_not_equal": {
			old:           mustDNStringSet(t, []string{"not a dn"}),
			new:           mustDNStringSet(t, []string{"different junk"}),
			expectedEqual: false,
		},
		"null_vs_null_equal": {
			old:           DNStringSetNull(context.Background()),
			new:           DNStringSetNull(context.Background()),
			expectedEqual: true,
		},
		"unknown_vs_unknown_equal": {
			old:           DNStringSetUnknown(context.Background()),
			new:           DNStringSetUnknown(context.Background()),
			expectedEqual: true,
		},
		"null_vs_known_not_equal": {
			old:           DNStringSetNull(context.Background()),
			new:           mustDNStringSet(t, []string{"CN=A,DC=x"}),
			expectedEqual: false,
		},
		"unknown_vs_known_not_equal": {
			old:           DNStringSetUnknown(context.Background()),
			new:           mustDNStringSet(t, []string{"CN=A,DC=x"}),
			expectedEqual: false,
		},
		"null_vs_unknown_not_equal": {
			old:           DNStringSetNull(context.Background()),
			new:           DNStringSetUnknown(context.Background()),
			expectedEqual: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, diags := tc.old.SetSemanticEquals(ctx, tc.new)
			assert.False(t, diags.HasError(), "unexpected error diagnostics: %s", diags)
			assert.Equal(t, tc.expectedEqual, got)
		})
	}
}

// TestDNStringSetValue_SetSemanticEquals_WrongType verifies an error diagnostic is
// emitted when the "new" value is not a DNStringSetValue.
func TestDNStringSetValue_SetSemanticEquals_WrongType(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	v := mustDNStringSet(t, []string{"CN=A,DC=x"})
	other, diags := basetypes.NewSetValue(basetypes.StringType{}, []attr.Value{
		basetypes.NewStringValue("CN=A,DC=x"),
	})
	require.False(t, diags.HasError())

	eq, edDiags := v.SetSemanticEquals(ctx, other)
	assert.False(t, eq)
	assert.True(t, edDiags.HasError(), "expected error diagnostic when passed a plain SetValue")
}

// TestDNStringSetValue_SetSemanticEquals_Symmetry verifies the relation is symmetric
// for common inputs.
func TestDNStringSetValue_SetSemanticEquals_Symmetry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	a := mustDNStringSet(t, []string{"CN=Alice,DC=x", "CN=Bob,DC=x"})
	b := mustDNStringSet(t, []string{"cn=Bob,dc=x", "cn=Alice,dc=x"})

	fwd, diags := a.SetSemanticEquals(ctx, b)
	require.False(t, diags.HasError())
	rev, diags := b.SetSemanticEquals(ctx, a)
	require.False(t, diags.HasError())

	assert.True(t, fwd)
	assert.True(t, rev)
}

// TestDNStringSet_Helpers verifies the constructor functions produce the expected states.
func TestDNStringSet_Helpers(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	v := mustDNStringSet(t, []string{"CN=a,DC=x", "CN=b,DC=x"})
	assert.False(t, v.IsNull())
	assert.False(t, v.IsUnknown())
	assert.Equal(t, 2, len(v.Elements()))

	n := DNStringSetNull(ctx)
	assert.True(t, n.IsNull())
	assert.False(t, n.IsUnknown())

	u := DNStringSetUnknown(ctx)
	assert.False(t, u.IsNull())
	assert.True(t, u.IsUnknown())
}

// TestDNStringSetValue_RoundTrip round-trips a set through the Terraform value layer
// and verifies semantic equality is preserved.
func TestDNStringSetValue_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	original := mustDNStringSet(t, []string{"CN=Alice,DC=x", "CN=Bob,DC=x"})

	tfVal, err := original.ToTerraformValue(ctx)
	require.NoError(t, err)

	got, err := NewDNStringSetType().ValueFromTerraform(ctx, tfVal)
	require.NoError(t, err)

	sv, ok := got.(DNStringSetValue)
	require.True(t, ok, "expected DNStringSetValue, got %T", got)

	eq, diags := original.SetSemanticEquals(ctx, sv)
	require.False(t, diags.HasError())
	assert.True(t, eq, "round-tripped set must be semantically equal to the original")
}
