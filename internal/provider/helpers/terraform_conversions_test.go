// Package helpers_test exercises terraform_conversions.go. These are pure
// unit tests and do NOT require TF_ACC.
package helpers_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isometry/terraform-provider-ad/internal/provider/helpers"
)

// ---------- small helpers --------------------------------------------------

func mustObject(t *testing.T, attrTypes map[string]attr.Type, attrs map[string]attr.Value) types.Object {
	t.Helper()
	obj, d := types.ObjectValue(attrTypes, attrs)
	require.False(t, d.HasError(), "building object value: %v", d)
	return obj
}

func mustList(t *testing.T, elemType attr.Type, elements []attr.Value) types.List {
	t.Helper()
	l, d := types.ListValue(elemType, elements)
	require.False(t, d.HasError(), "building list value: %v", d)
	return l
}

func mustMap(t *testing.T, elemType attr.Type, elements map[string]attr.Value) types.Map {
	t.Helper()
	m, d := types.MapValue(elemType, elements)
	require.False(t, d.HasError(), "building map value: %v", d)
	return m
}

func mustSet(t *testing.T, elemType attr.Type, elements []attr.Value) types.Set {
	t.Helper()
	s, d := types.SetValue(elemType, elements)
	require.False(t, d.HasError(), "building set value: %v", d)
	return s
}

// ===========================================================================
// TerraformValueToGo
// ===========================================================================

func TestTerraformValueToGo(t *testing.T) {
	ctx := context.Background()

	type tc struct {
		name    string
		input   attr.Value
		want    any
		wantErr bool
	}

	// Note: we assert deep equality for nested structures.
	cases := []tc{
		// --- null / unknown ------------------------------------------------
		{name: "null string", input: types.StringNull(), want: nil},
		{name: "null int64", input: types.Int64Null(), want: nil},
		{name: "null bool", input: types.BoolNull(), want: nil},
		{name: "null float64", input: types.Float64Null(), want: nil},
		{name: "null list", input: types.ListNull(types.StringType), want: nil},
		{name: "null map", input: types.MapNull(types.StringType), want: nil},
		{name: "null set", input: types.SetNull(types.StringType), want: nil},
		{name: "null object", input: types.ObjectNull(map[string]attr.Type{"a": types.StringType}), want: nil},
		{name: "null dynamic", input: types.DynamicNull(), want: nil},

		{name: "unknown string", input: types.StringUnknown(), wantErr: true},
		{name: "unknown int64", input: types.Int64Unknown(), wantErr: true},
		{name: "unknown list", input: types.ListUnknown(types.StringType), wantErr: true},
		{name: "unknown dynamic", input: types.DynamicUnknown(), wantErr: true},

		// --- scalars -------------------------------------------------------
		{name: "string happy", input: types.StringValue("hello"), want: "hello"},
		{name: "empty string", input: types.StringValue(""), want: ""},
		{name: "int64 happy", input: types.Int64Value(42), want: int64(42)},
		{name: "int64 negative", input: types.Int64Value(-7), want: int64(-7)},
		{name: "float64 happy", input: types.Float64Value(3.14), want: 3.14},
		{name: "bool true", input: types.BoolValue(true), want: true},
		{name: "bool false", input: types.BoolValue(false), want: false},

		// --- types.Number --------------------------------------------------
		{name: "number from big.Float", input: types.NumberValue(big.NewFloat(1.5)), want: 1.5},

		// --- list / set / tuple --------------------------------------------
		{
			name: "list of strings",
			input: mustList(t, types.StringType, []attr.Value{
				types.StringValue("a"),
				types.StringValue("b"),
			}),
			want: []any{"a", "b"},
		},
		{
			name:  "empty list",
			input: mustList(t, types.StringType, []attr.Value{}),
			want:  []any{},
		},
		{
			name: "set of ints",
			input: mustSet(t, types.Int64Type, []attr.Value{
				types.Int64Value(1),
				types.Int64Value(2),
			}),
			want: []any{int64(1), int64(2)},
		},
		{
			name: "tuple with mixed types",
			input: types.TupleValueMust(
				[]attr.Type{types.StringType, types.Int64Type, types.BoolType},
				[]attr.Value{types.StringValue("x"), types.Int64Value(3), types.BoolValue(true)},
			),
			want: []any{"x", int64(3), true},
		},

		// --- map / object --------------------------------------------------
		{
			name: "map of strings",
			input: mustMap(t, types.StringType, map[string]attr.Value{
				"k1": types.StringValue("v1"),
				"k2": types.StringValue("v2"),
			}),
			want: map[string]any{"k1": "v1", "k2": "v2"},
		},
		{
			name:  "empty map",
			input: mustMap(t, types.StringType, map[string]attr.Value{}),
			want:  map[string]any{},
		},
		{
			name: "object with mixed attributes",
			input: mustObject(t,
				map[string]attr.Type{
					"name":  types.StringType,
					"count": types.Int64Type,
					"on":    types.BoolType,
				},
				map[string]attr.Value{
					"name":  types.StringValue("foo"),
					"count": types.Int64Value(9),
					"on":    types.BoolValue(true),
				},
			),
			want: map[string]any{"name": "foo", "count": int64(9), "on": true},
		},

		// --- nested --------------------------------------------------------
		{
			name: "list of objects",
			input: types.TupleValueMust(
				[]attr.Type{
					types.ObjectType{AttrTypes: map[string]attr.Type{"n": types.StringType}},
					types.ObjectType{AttrTypes: map[string]attr.Type{"n": types.StringType}},
				},
				[]attr.Value{
					mustObject(t, map[string]attr.Type{"n": types.StringType}, map[string]attr.Value{"n": types.StringValue("one")}),
					mustObject(t, map[string]attr.Type{"n": types.StringType}, map[string]attr.Value{"n": types.StringValue("two")}),
				},
			),
			want: []any{map[string]any{"n": "one"}, map[string]any{"n": "two"}},
		},
		{
			name: "map of lists",
			input: mustMap(t,
				types.ListType{ElemType: types.Int64Type},
				map[string]attr.Value{
					"xs": mustList(t, types.Int64Type, []attr.Value{types.Int64Value(1), types.Int64Value(2)}),
				},
			),
			want: map[string]any{"xs": []any{int64(1), int64(2)}},
		},
		{
			name:  "dynamic wrapping string",
			input: types.DynamicValue(types.StringValue("wrapped")),
			want:  "wrapped",
		},
		{
			name: "dynamic wrapping object",
			input: types.DynamicValue(mustObject(t,
				map[string]attr.Type{"k": types.StringType},
				map[string]attr.Value{"k": types.StringValue("v")},
			)),
			want: map[string]any{"k": "v"},
		},

		// --- propagation of unknown through container ----------------------
		{
			name: "list containing unknown errors",
			input: mustList(t, types.StringType, []attr.Value{
				types.StringValue("ok"),
				types.StringUnknown(),
			}),
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := helpers.TerraformValueToGo(ctx, c.input)
			if c.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

// ===========================================================================
// ExtractMapFromDynamic
// ===========================================================================

func TestExtractMapFromDynamic(t *testing.T) {
	ctx := context.Background()

	t.Run("wrapping map", func(t *testing.T) {
		m := mustMap(t, types.StringType, map[string]attr.Value{
			"a": types.StringValue("1"),
			"b": types.StringValue("2"),
		})
		got, err := helpers.ExtractMapFromDynamic(ctx, types.DynamicValue(m))
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, types.StringValue("1"), got["a"])
		assert.Equal(t, types.StringValue("2"), got["b"])
	})

	t.Run("wrapping object", func(t *testing.T) {
		obj := mustObject(t,
			map[string]attr.Type{"x": types.Int64Type, "y": types.StringType},
			map[string]attr.Value{"x": types.Int64Value(7), "y": types.StringValue("yo")},
		)
		got, err := helpers.ExtractMapFromDynamic(ctx, types.DynamicValue(obj))
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, types.Int64Value(7), got["x"])
		assert.Equal(t, types.StringValue("yo"), got["y"])
	})

	t.Run("wrapping list errors", func(t *testing.T) {
		l := mustList(t, types.StringType, []attr.Value{types.StringValue("a")})
		_, err := helpers.ExtractMapFromDynamic(ctx, types.DynamicValue(l))
		require.Error(t, err)
	})

	t.Run("wrapping string errors", func(t *testing.T) {
		_, err := helpers.ExtractMapFromDynamic(ctx, types.DynamicValue(types.StringValue("z")))
		require.Error(t, err)
	})
}

// ===========================================================================
// GoValueToTerraform
// ===========================================================================

func TestGoValueToTerraform(t *testing.T) {
	ctx := context.Background()

	t.Run("scalars", func(t *testing.T) {
		cases := []struct {
			name string
			in   any
			want attr.Value
		}{
			{"nil → StringNull", nil, types.StringNull()},
			{"string", "foo", types.StringValue("foo")},
			{"int", 5, types.Int64Value(5)},
			{"int64", int64(-3), types.Int64Value(-3)},
			{"float64", 2.5, types.Float64Value(2.5)},
			{"bool true", true, types.BoolValue(true)},
			{"bool false", false, types.BoolValue(false)},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got, err := helpers.GoValueToTerraform(ctx, c.in)
				require.NoError(t, err)
				assert.Equal(t, c.want, got)
			})
		}
	})

	t.Run("slice becomes tuple", func(t *testing.T) {
		got, err := helpers.GoValueToTerraform(ctx, []any{"a", int64(1), true})
		require.NoError(t, err)
		tup, ok := got.(types.Tuple)
		require.True(t, ok, "expected Tuple, got %T", got)
		require.Len(t, tup.Elements(), 3)
		assert.Equal(t, types.StringValue("a"), tup.Elements()[0])
		assert.Equal(t, types.Int64Value(1), tup.Elements()[1])
		assert.Equal(t, types.BoolValue(true), tup.Elements()[2])
	})

	t.Run("empty slice becomes empty tuple", func(t *testing.T) {
		got, err := helpers.GoValueToTerraform(ctx, []any{})
		require.NoError(t, err)
		tup, ok := got.(types.Tuple)
		require.True(t, ok)
		assert.Empty(t, tup.Elements())
	})

	t.Run("map becomes object", func(t *testing.T) {
		got, err := helpers.GoValueToTerraform(ctx, map[string]any{
			"name": "svc",
			"port": int64(443),
		})
		require.NoError(t, err)
		obj, ok := got.(types.Object)
		require.True(t, ok, "expected Object, got %T", got)
		attrs := obj.Attributes()
		assert.Equal(t, types.StringValue("svc"), attrs["name"])
		assert.Equal(t, types.Int64Value(443), attrs["port"])
	})

	t.Run("empty map becomes empty object", func(t *testing.T) {
		got, err := helpers.GoValueToTerraform(ctx, map[string]any{})
		require.NoError(t, err)
		obj, ok := got.(types.Object)
		require.True(t, ok)
		assert.Empty(t, obj.Attributes())
	})

	t.Run("nested structures", func(t *testing.T) {
		input := map[string]any{
			"users": []any{
				map[string]any{"name": "alice", "admin": true},
				map[string]any{"name": "bob", "admin": false},
			},
			"count": int64(2),
		}
		got, err := helpers.GoValueToTerraform(ctx, input)
		require.NoError(t, err)

		// Round-trip back to Go to assert deep equality.
		roundTripped, err := helpers.TerraformValueToGo(ctx, got)
		require.NoError(t, err)
		assert.Equal(t, input, roundTripped)
	})

	t.Run("unsupported type errors", func(t *testing.T) {
		_, err := helpers.GoValueToTerraform(ctx, struct{ X int }{X: 1})
		require.Error(t, err)
	})

	t.Run("unsupported scalar int32 errors", func(t *testing.T) {
		// int32 is not in the switch, so must return error.
		_, err := helpers.GoValueToTerraform(ctx, int32(5))
		require.Error(t, err)
	})

	t.Run("slice containing unsupported type errors", func(t *testing.T) {
		_, err := helpers.GoValueToTerraform(ctx, []any{"ok", int32(1)})
		require.Error(t, err)
	})

	t.Run("map containing unsupported type errors", func(t *testing.T) {
		_, err := helpers.GoValueToTerraform(ctx, map[string]any{"k": struct{}{}})
		require.Error(t, err)
	})
}

// ===========================================================================
// GetString
// ===========================================================================

func TestGetString(t *testing.T) {
	cases := []struct {
		name string
		in   types.String
		want string
	}{
		{"value", types.StringValue("hi"), "hi"},
		{"empty string value", types.StringValue(""), ""},
		{"null", types.StringNull(), ""},
		{"unknown", types.StringUnknown(), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, helpers.GetString(c.in))
		})
	}
}

// ===========================================================================
// StringOrNull
// ===========================================================================

func TestStringOrNull(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want types.String
	}{
		{"non-empty", "hello", types.StringValue("hello")},
		{"empty", "", types.StringNull()},
		{"whitespace kept as value", " ", types.StringValue(" ")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, helpers.StringOrNull(c.in))
		})
	}
}

// ===========================================================================
// Timestamp / TimestampOrNull
// ===========================================================================

func TestTimestamp(t *testing.T) {
	when := time.Date(2026, 4, 19, 10, 30, 0, 0, time.UTC)
	got := helpers.Timestamp(when)
	assert.Equal(t, types.StringValue("2026-04-19T10:30:00Z"), got)
}

func TestTimestampOrNull(t *testing.T) {
	t.Run("nil pointer returns null", func(t *testing.T) {
		assert.Equal(t, types.StringNull(), helpers.TimestampOrNull(nil))
	})

	t.Run("non-nil pointer returns RFC3339 string", func(t *testing.T) {
		when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		assert.Equal(t, types.StringValue("2026-01-02T03:04:05Z"), helpers.TimestampOrNull(&when))
	})

	t.Run("zero time still formats", func(t *testing.T) {
		zero := time.Time{}
		got := helpers.TimestampOrNull(&zero)
		require.False(t, got.IsNull())
		assert.Equal(t, "0001-01-01T00:00:00Z", got.ValueString())
	})
}

// ===========================================================================
// StringChanged
// ===========================================================================

func TestStringChanged(t *testing.T) {
	t.Run("equal values report no change", func(t *testing.T) {
		var target *string
		changed := helpers.StringChanged(types.StringValue("x"), types.StringValue("x"), &target)
		assert.False(t, changed)
		assert.Nil(t, target)
	})

	t.Run("both null report no change", func(t *testing.T) {
		var target *string
		changed := helpers.StringChanged(types.StringNull(), types.StringNull(), &target)
		assert.False(t, changed)
		assert.Nil(t, target)
	})

	t.Run("plan null, state set → clears target", func(t *testing.T) {
		var target *string
		changed := helpers.StringChanged(types.StringNull(), types.StringValue("old"), &target)
		assert.True(t, changed)
		require.NotNil(t, target)
		assert.Equal(t, "", *target)
	})

	t.Run("plan set, state null → sets target", func(t *testing.T) {
		var target *string
		changed := helpers.StringChanged(types.StringValue("new"), types.StringNull(), &target)
		assert.True(t, changed)
		require.NotNil(t, target)
		assert.Equal(t, "new", *target)
	})

	t.Run("plan changed value → sets target", func(t *testing.T) {
		var target *string
		changed := helpers.StringChanged(types.StringValue("new"), types.StringValue("old"), &target)
		assert.True(t, changed)
		require.NotNil(t, target)
		assert.Equal(t, "new", *target)
	})

	t.Run("plan empty string (explicit clear) is a change", func(t *testing.T) {
		var target *string
		changed := helpers.StringChanged(types.StringValue(""), types.StringValue("old"), &target)
		assert.True(t, changed)
		require.NotNil(t, target)
		assert.Equal(t, "", *target)
	})
}

// ===========================================================================
// BoolChanged
// ===========================================================================

func TestBoolChanged(t *testing.T) {
	t.Run("equal values report no change", func(t *testing.T) {
		var target *bool
		changed := helpers.BoolChanged(types.BoolValue(true), types.BoolValue(true), &target)
		assert.False(t, changed)
		assert.Nil(t, target)
	})

	t.Run("both null report no change", func(t *testing.T) {
		var target *bool
		changed := helpers.BoolChanged(types.BoolNull(), types.BoolNull(), &target)
		assert.False(t, changed)
		assert.Nil(t, target)
	})

	t.Run("plan true, state false → sets target to true", func(t *testing.T) {
		var target *bool
		changed := helpers.BoolChanged(types.BoolValue(true), types.BoolValue(false), &target)
		assert.True(t, changed)
		require.NotNil(t, target)
		assert.True(t, *target)
	})

	t.Run("plan false, state null → sets target to false", func(t *testing.T) {
		var target *bool
		changed := helpers.BoolChanged(types.BoolValue(false), types.BoolNull(), &target)
		assert.True(t, changed)
		require.NotNil(t, target)
		assert.False(t, *target)
	})

	t.Run("plan null, state set → clears to false", func(t *testing.T) {
		// Symmetric with StringChanged: null plan against a set state signals clearing.
		// Target is written to &false so the LDAP update layer reverts the attribute.
		var target *bool
		changed := helpers.BoolChanged(types.BoolNull(), types.BoolValue(true), &target)
		assert.True(t, changed)
		require.NotNil(t, target)
		assert.False(t, *target)
	})

	t.Run("plan unknown → not changed", func(t *testing.T) {
		var target *bool
		changed := helpers.BoolChanged(types.BoolUnknown(), types.BoolValue(false), &target)
		assert.False(t, changed)
		assert.Nil(t, target)
	})
}

// ===========================================================================
// NormalizeDN
// ===========================================================================

func TestNormalizeDN(t *testing.T) {
	ctx := context.Background()

	t.Run("lowercase attribute types get uppercased", func(t *testing.T) {
		got := helpers.NormalizeDN(ctx, "cn=john,ou=users,dc=example,dc=com")
		assert.Equal(t, "CN=john,OU=users,DC=example,DC=com", got)
	})

	t.Run("already-normalized is idempotent", func(t *testing.T) {
		in := "CN=john,OU=users,DC=example,DC=com"
		assert.Equal(t, in, helpers.NormalizeDN(ctx, in))
	})

	t.Run("empty string returns empty string", func(t *testing.T) {
		assert.Equal(t, "", helpers.NormalizeDN(ctx, ""))
	})

	t.Run("invalid DN returns original via logged fallback", func(t *testing.T) {
		bogus := "this is not a dn"
		assert.Equal(t, bogus, helpers.NormalizeDN(ctx, bogus))
	})
}

// ===========================================================================
// DNListOrNull
// ===========================================================================

func TestDNListOrNull(t *testing.T) {
	ctx := context.Background()

	t.Run("nil slice returns empty list, not null", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.DNListOrNull(ctx, nil, &diags)
		assert.False(t, got.IsNull())
		assert.Equal(t, 0, len(got.Elements()))
		assert.False(t, diags.HasError())
	})

	t.Run("empty slice returns empty list", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.DNListOrNull(ctx, []string{}, &diags)
		assert.False(t, got.IsNull())
		assert.Equal(t, 0, len(got.Elements()))
	})

	t.Run("populated slice normalizes each DN", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.DNListOrNull(ctx,
			[]string{"cn=alice,ou=users,dc=example,dc=com", "cn=bob,dc=example,dc=com"},
			&diags,
		)
		require.False(t, diags.HasError())
		require.False(t, got.IsNull())
		require.Len(t, got.Elements(), 2)
		assert.Equal(t, types.StringValue("CN=alice,OU=users,DC=example,DC=com"), got.Elements()[0])
		assert.Equal(t, types.StringValue("CN=bob,DC=example,DC=com"), got.Elements()[1])
	})

	t.Run("element type is string", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.DNListOrNull(ctx, []string{"cn=x,dc=y"}, &diags)
		assert.Equal(t, types.StringType, got.ElementType(ctx))
	})

	t.Run("invalid DN preserved via normalizer fallback", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.DNListOrNull(ctx, []string{"not a dn"}, &diags)
		require.False(t, diags.HasError())
		require.Len(t, got.Elements(), 1)
		s, ok := got.Elements()[0].(basetypes.StringValue)
		require.True(t, ok)
		assert.Equal(t, "not a dn", s.ValueString())
	})
}

// ===========================================================================
// StringList
// ===========================================================================

func TestStringList(t *testing.T) {
	t.Run("nil slice returns empty list", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.StringList(nil, &diags)
		assert.False(t, got.IsNull())
		assert.Empty(t, got.Elements())
		assert.False(t, diags.HasError())
	})

	t.Run("empty slice returns empty list", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.StringList([]string{}, &diags)
		assert.False(t, got.IsNull())
		assert.Empty(t, got.Elements())
	})

	t.Run("populated slice", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.StringList([]string{"a", "b", "c"}, &diags)
		require.False(t, diags.HasError())
		require.Len(t, got.Elements(), 3)
		assert.Equal(t, types.StringValue("a"), got.Elements()[0])
		assert.Equal(t, types.StringValue("b"), got.Elements()[1])
		assert.Equal(t, types.StringValue("c"), got.Elements()[2])
	})
}

// ===========================================================================
// Int64List
// ===========================================================================

func TestInt64List(t *testing.T) {
	t.Run("nil slice returns empty list", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.Int64List(nil, &diags)
		assert.False(t, got.IsNull())
		assert.Empty(t, got.Elements())
		assert.False(t, diags.HasError())
	})

	t.Run("empty slice returns empty list", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.Int64List([]int64{}, &diags)
		assert.False(t, got.IsNull())
		assert.Empty(t, got.Elements())
	})

	t.Run("populated slice", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.Int64List([]int64{1, -2, 3}, &diags)
		require.False(t, diags.HasError())
		require.Len(t, got.Elements(), 3)
		assert.Equal(t, types.Int64Value(1), got.Elements()[0])
		assert.Equal(t, types.Int64Value(-2), got.Elements()[1])
		assert.Equal(t, types.Int64Value(3), got.Elements()[2])
	})
}

// ===========================================================================
// DNSetOrNull
// ===========================================================================

func TestDNSetOrNull(t *testing.T) {
	ctx := context.Background()

	t.Run("nil slice returns empty set, not null", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.DNSetOrNull(ctx, nil, &diags)
		assert.False(t, got.IsNull())
		assert.Empty(t, got.Elements())
		assert.False(t, diags.HasError())
	})

	t.Run("empty slice returns empty set", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.DNSetOrNull(ctx, []string{}, &diags)
		assert.False(t, got.IsNull())
		assert.Empty(t, got.Elements())
	})

	t.Run("populated slice normalizes each DN", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.DNSetOrNull(ctx,
			[]string{"cn=alice,dc=example,dc=com", "cn=bob,dc=example,dc=com"},
			&diags,
		)
		require.False(t, diags.HasError())
		require.False(t, got.IsNull())
		require.Len(t, got.Elements(), 2)

		// Sets are unordered; collect values and compare.
		values := make([]string, 0, len(got.Elements()))
		for _, elem := range got.Elements() {
			s, ok := elem.(basetypes.StringValue)
			require.True(t, ok)
			values = append(values, s.ValueString())
		}
		assert.ElementsMatch(t,
			[]string{"CN=alice,DC=example,DC=com", "CN=bob,DC=example,DC=com"},
			values,
		)
	})

	t.Run("element type is string", func(t *testing.T) {
		var diags diag.Diagnostics
		got := helpers.DNSetOrNull(ctx, []string{"cn=x,dc=y"}, &diags)
		assert.Equal(t, types.StringType, got.ElementType(ctx))
	})
}
