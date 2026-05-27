package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestEvaluatePasswordRotation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		planVersion    types.Int64
		stateVersion   types.Int64
		configPassword types.String
		want           rotationOutcome
	}{
		"update_version_unchanged_no_op": {
			planVersion:    types.Int64Value(1),
			stateVersion:   types.Int64Value(1),
			configPassword: types.StringValue("hunter2"),
			want:           rotationOutcomeNone,
		},
		"update_version_unchanged_no_op_null_password": {
			planVersion:    types.Int64Value(1),
			stateVersion:   types.Int64Value(1),
			configPassword: types.StringNull(),
			want:           rotationOutcomeNone,
		},
		"update_plan_version_unknown_defers": {
			planVersion:    types.Int64Unknown(),
			stateVersion:   types.Int64Value(1),
			configPassword: types.StringValue("hunter2"),
			want:           rotationOutcomeDefer,
		},
		"update_rotation_with_password_ready": {
			planVersion:    types.Int64Value(2),
			stateVersion:   types.Int64Value(1),
			configPassword: types.StringValue("hunter2"),
			want:           rotationOutcomeReady,
		},
		"update_rotation_with_null_password_errors": {
			planVersion:    types.Int64Value(2),
			stateVersion:   types.Int64Value(1),
			configPassword: types.StringNull(),
			want:           rotationOutcomeMissingPassword,
		},
		"update_rotation_with_empty_password_errors": {
			planVersion:    types.Int64Value(2),
			stateVersion:   types.Int64Value(1),
			configPassword: types.StringValue(""),
			want:           rotationOutcomeMissingPassword,
		},
		"update_rotation_with_unknown_password_defers": {
			planVersion:    types.Int64Value(2),
			stateVersion:   types.Int64Value(1),
			configPassword: types.StringUnknown(),
			want:           rotationOutcomeDefer,
		},
		// null→non-null transition counts as a rotation.
		"update_null_to_one_with_null_password_errors": {
			planVersion:    types.Int64Value(1),
			stateVersion:   types.Int64Null(),
			configPassword: types.StringNull(),
			want:           rotationOutcomeMissingPassword,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := evaluatePasswordRotation(tc.planVersion, tc.stateVersion, tc.configPassword)
			if got != tc.want {
				t.Errorf("evaluatePasswordRotation = %d, want %d", got, tc.want)
			}
		})
	}
}

// AD's unicodePwd modify side-effect bumps pwdLastSet to "now", silently
// clearing the must-change flag. The post-reset refresh must surface
// ChangePasswordAtLogon=false so buildUpdateRequest detects the diff against
// plan.ChangePasswordAtLogon=true and re-issues pwdLastSet=0.
func TestBuildUpdateRequest_ChangePasswordAtLogonAfterRefresh(t *testing.T) {
	t.Parallel()

	r := &UserResource{}

	t.Run("plan_true_refreshed_state_false_writes_must_change", func(t *testing.T) {
		t.Parallel()

		plan := newUserModelForUpdateDiff()
		plan.ChangePasswordAtLogon = types.BoolValue(true)

		refreshedState := newUserModelForUpdateDiff()
		refreshedState.ChangePasswordAtLogon = types.BoolValue(false)

		req := r.buildUpdateRequest(&plan, &refreshedState)
		if req == nil || req.ChangePasswordAtLogon == nil {
			t.Fatalf("expected non-nil update request with ChangePasswordAtLogon set; got %+v", req)
		}
		if !*req.ChangePasswordAtLogon {
			t.Errorf("expected ChangePasswordAtLogon=true, got false")
		}
	})

	t.Run("plan_false_refreshed_state_false_no_change", func(t *testing.T) {
		t.Parallel()

		plan := newUserModelForUpdateDiff()
		plan.ChangePasswordAtLogon = types.BoolValue(false)

		refreshedState := newUserModelForUpdateDiff()
		refreshedState.ChangePasswordAtLogon = types.BoolValue(false)

		req := r.buildUpdateRequest(&plan, &refreshedState)
		if req != nil {
			t.Fatalf("expected nil update request when plan and state agree, got %+v", req)
		}
	})
}

// newUserModelForUpdateDiff returns a UserResourceModel where every attribute
// is equal between plan and refreshed state, so buildUpdateRequest's diff is
// exercised on the single attribute each test mutates.
func newUserModelForUpdateDiff() UserResourceModel {
	return UserResourceModel{
		PrincipalName:          types.StringValue("alice@example.com"),
		SAMAccountName:         types.StringValue("alice"),
		Enabled:                types.BoolValue(true),
		PasswordNeverExpires:   types.BoolValue(false),
		SmartCardLogonRequired: types.BoolValue(false),
		TrustedForDelegation:   types.BoolValue(false),
		ChangePasswordAtLogon:  types.BoolValue(false),
	}
}

// After a passwordReset, server-computed attributes (pwdLastSet, whenChanged)
// change but buildUpdateRequest does not diff them, so a request that matches
// refreshed state on tracked attrs must yield a nil request.
func TestBuildUpdateRequest_NilWhenPlanMatchesRefreshedState(t *testing.T) {
	t.Parallel()

	r := &UserResource{}

	plan := newUserModelForUpdateDiff()
	refreshedState := newUserModelForUpdateDiff()

	req := r.buildUpdateRequest(&plan, &refreshedState)
	if req != nil {
		t.Fatalf("expected nil update request when plan and refreshed state agree on tracked attrs, got %+v", req)
	}
}
