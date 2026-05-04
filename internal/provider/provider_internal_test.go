package provider

import (
	"context"
	"math"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	provschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	ldapclient "github.com/isometry/terraform-provider-ad/internal/ldap"
)

// --- getInt64Bounded -------------------------------------------------------

func TestGetInt64Bounded_InRangeFromEnv(t *testing.T) {
	t.Setenv("AD_MAX_IDLE_TIME", "120")

	p := &ActiveDirectoryProvider{}
	var diags diag.Diagnostics

	got := p.getInt64Bounded(types.Int64Null(), "AD_MAX_IDLE_TIME", "max_idle_time",
		300, 1, math.MaxInt32, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected error diagnostics: %v", diags)
	}
	if got != 120 {
		t.Fatalf("got %d, want 120", got)
	}
}

func TestGetInt64Bounded_AboveMax_AddsError(t *testing.T) {
	envVal := strconv.FormatInt(int64(math.MaxInt32)+1, 10)
	t.Setenv("AD_MAX_IDLE_TIME", envVal)

	p := &ActiveDirectoryProvider{}
	var diags diag.Diagnostics

	got := p.getInt64Bounded(types.Int64Null(), "AD_MAX_IDLE_TIME", "max_idle_time",
		300, 1, math.MaxInt32, &diags)

	if !diags.HasError() {
		t.Fatalf("expected error diagnostic, got none")
	}
	if got != 300 {
		t.Fatalf("got %d, want defaultValue 300", got)
	}
}

func TestGetInt64Bounded_BelowMin_AddsError(t *testing.T) {
	t.Setenv("AD_MAX_IDLE_TIME", "0")

	p := &ActiveDirectoryProvider{}
	var diags diag.Diagnostics

	got := p.getInt64Bounded(types.Int64Null(), "AD_MAX_IDLE_TIME", "max_idle_time",
		300, 1, math.MaxInt32, &diags)

	if !diags.HasError() {
		t.Fatalf("expected error diagnostic, got none")
	}
	if got != 300 {
		t.Fatalf("got %d, want defaultValue 300", got)
	}
}

func TestGetInt64Bounded_DefaultWhenUnset(t *testing.T) {
	t.Setenv("AD_MAX_IDLE_TIME", "")

	p := &ActiveDirectoryProvider{}
	var diags diag.Diagnostics

	got := p.getInt64Bounded(types.Int64Null(), "AD_MAX_IDLE_TIME", "max_idle_time",
		300, 1, math.MaxInt32, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected error diagnostics: %v", diags)
	}
	if got != 300 {
		t.Fatalf("got %d, want 300", got)
	}
}

func TestGetInt64Bounded_SchemaOverridesEnv(t *testing.T) {
	t.Setenv("AD_MAX_IDLE_TIME", "120")

	p := &ActiveDirectoryProvider{}
	var diags diag.Diagnostics

	got := p.getInt64Bounded(types.Int64Value(60), "AD_MAX_IDLE_TIME", "max_idle_time",
		300, 1, math.MaxInt32, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected error diagnostics: %v", diags)
	}
	if got != 60 {
		t.Fatalf("got %d, want 60 (schema wins over env)", got)
	}
}

// --- getIntBounded ---------------------------------------------------------

func TestGetIntBounded_InRange(t *testing.T) {
	t.Setenv("AD_MAX_CONNECTIONS", "42")

	p := &ActiveDirectoryProvider{}
	var diags diag.Diagnostics

	got := p.getIntBounded(types.Int64Null(), "AD_MAX_CONNECTIONS", "max_connections",
		10, 1, int64(ldapclient.MaxConnectionPoolLimit), &diags)

	if diags.HasError() {
		t.Fatalf("unexpected error diagnostics: %v", diags)
	}
	if got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
}

func TestGetIntBounded_AboveMax_AddsError(t *testing.T) {
	t.Setenv("AD_MAX_CONNECTIONS", "150")

	p := &ActiveDirectoryProvider{}
	var diags diag.Diagnostics

	got := p.getIntBounded(types.Int64Null(), "AD_MAX_CONNECTIONS", "max_connections",
		10, 1, int64(ldapclient.MaxConnectionPoolLimit), &diags)

	if !diags.HasError() {
		t.Fatalf("expected error diagnostic, got none")
	}
	if got != 10 {
		t.Fatalf("got %d, want defaultValue 10", got)
	}
}

func TestGetIntBounded_BelowMin_AddsError(t *testing.T) {
	t.Setenv("AD_MAX_CONNECTIONS", "0")

	p := &ActiveDirectoryProvider{}
	var diags diag.Diagnostics

	got := p.getIntBounded(types.Int64Null(), "AD_MAX_CONNECTIONS", "max_connections",
		10, 1, int64(ldapclient.MaxConnectionPoolLimit), &diags)

	if !diags.HasError() {
		t.Fatalf("expected error diagnostic, got none")
	}
	if got != 10 {
		t.Fatalf("got %d, want defaultValue 10", got)
	}
}

// --- Schema validator wiring -----------------------------------------------

// TestSchema_Int64ValidatorsWired confirms each numeric provider attribute has
// a validator wired up that accepts a representative in-range value and
// rejects a representative out-of-range value. Catches mistakes like swapped
// constants or missing Validators stanzas without re-testing int64validator
// itself (which is library-tested upstream).
func TestSchema_Int64ValidatorsWired(t *testing.T) {
	ctx := context.Background()
	p := &ActiveDirectoryProvider{}

	var resp provider.SchemaResponse
	p.Schema(ctx, provider.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error from Schema(): %v", resp.Diagnostics)
	}

	cases := []struct {
		name       string
		inRange    int64
		outOfRange int64
	}{
		{"max_connections", 50, int64(ldapclient.MaxConnectionPoolLimit) + 1},
		{"max_idle_time", 60, int64(math.MaxInt32) + 1},
		{"connect_timeout", 10, int64(math.MaxInt32) + 1},
		{"max_retries", 3, int64(math.MaxInt32) + 1},
		{"initial_backoff", 250, int64(math.MaxInt32) + 1},
		{"max_backoff", 30, int64(math.MaxInt32) + 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attr, ok := resp.Schema.Attributes[tc.name].(provschema.Int64Attribute)
			if !ok {
				t.Fatalf("attribute %q is not Int64Attribute", tc.name)
			}
			if len(attr.Validators) == 0 {
				t.Fatalf("attribute %q has no validators", tc.name)
			}

			runValidators := func(v int64) diag.Diagnostics {
				req := validator.Int64Request{
					Path:        path.Root(tc.name),
					ConfigValue: types.Int64Value(v),
				}
				var d diag.Diagnostics
				for _, vd := range attr.Validators {
					var r validator.Int64Response
					vd.ValidateInt64(ctx, req, &r)
					d.Append(r.Diagnostics...)
				}
				return d
			}

			if diags := runValidators(tc.inRange); diags.HasError() {
				t.Errorf("in-range value %d for %s rejected: %v", tc.inRange, tc.name, diags)
			}
			if diags := runValidators(tc.outOfRange); !diags.HasError() {
				t.Errorf("out-of-range value %d for %s accepted; expected rejection", tc.outOfRange, tc.name)
			}
		})
	}
}

// TestSchema_Int64ValidatorsBoundsLowerEdge confirms the lower bound for each
// numeric attribute is exactly the documented value (catches off-by-one
// wiring mistakes).
func TestSchema_Int64ValidatorsBoundsLowerEdge(t *testing.T) {
	ctx := context.Background()
	p := &ActiveDirectoryProvider{}

	var resp provider.SchemaResponse
	p.Schema(ctx, provider.SchemaRequest{}, &resp)

	cases := []struct {
		name          string
		acceptedAtMin int64 // documented minimum, must be accepted
		rejectedBelow int64 // one below minimum, must be rejected
	}{
		{"max_connections", minMaxConnections, minMaxConnections - 1},
		{"max_idle_time", minMaxIdleTime, minMaxIdleTime - 1},
		{"connect_timeout", minConnectTimeout, minConnectTimeout - 1},
		{"max_retries", minMaxRetries, minMaxRetries - 1},
		{"initial_backoff", minInitialBackoff, minInitialBackoff - 1},
		{"max_backoff", minMaxBackoff, minMaxBackoff - 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attr, ok := resp.Schema.Attributes[tc.name].(provschema.Int64Attribute)
			if !ok {
				t.Fatalf("attribute %q is not Int64Attribute", tc.name)
			}

			runValidators := func(v int64) diag.Diagnostics {
				req := validator.Int64Request{
					Path:        path.Root(tc.name),
					ConfigValue: types.Int64Value(v),
				}
				var d diag.Diagnostics
				for _, vd := range attr.Validators {
					var r validator.Int64Response
					vd.ValidateInt64(ctx, req, &r)
					d.Append(r.Diagnostics...)
				}
				return d
			}

			if diags := runValidators(tc.acceptedAtMin); diags.HasError() {
				t.Errorf("minimum %d for %s rejected: %v", tc.acceptedAtMin, tc.name, diags)
			}
			if diags := runValidators(tc.rejectedBelow); !diags.HasError() {
				t.Errorf("value %d (below minimum) for %s accepted", tc.rejectedBelow, tc.name)
			}
		})
	}
}

// --- compile-time sanity check on validator construction -------------------

// Ensures int64validator import is used at test-file scope for clarity even
// when other tests don't reference it. Removing a validator from the schema
// would not break this assertion, but the wiring tests above would catch it.
var _ = int64validator.Between(0, 1)
