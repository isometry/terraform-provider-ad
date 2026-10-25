package ldap

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// rollbackCreate makes a best-effort delete of an object whose Add succeeded
// but whose follow-up step failed (Terraform saves no state on a failed
// Create, so the object would otherwise be orphaned). It always returns the
// original error, wrapped, noting whether cleanup worked.
func rollbackCreate(ctx context.Context, c Client, dn, operation string, origErr error) error {
	if delErr := c.Delete(ctx, dn); delErr != nil {
		tflog.SubsystemWarn(ctx, "ldap", "Failed to clean up partially created object", map[string]any{
			"dn":    dn,
			"error": delErr.Error(),
		})
		return WrapError(operation, fmt.Errorf("%w (cleanup of %s failed: %v)", origErr, dn, delErr))
	}
	return WrapError(operation, fmt.Errorf("%w (partially created %s was deleted)", origErr, dn))
}

// rollbackCreateOU is rollbackCreate for OUs after protection may have been
// applied: the deny-delete ACE would make the Delete fail, so remove it first.
// Removal is a no-op if the ACE is absent.
func (om *OUManager) rollbackCreateOU(ouDN, operation string, origErr error) error {
	if err := om.SetOUProtection(ouDN, false); err != nil {
		tflog.SubsystemWarn(om.ctx, "ldap", "Failed to remove protection during create cleanup", map[string]any{
			"dn":    ouDN,
			"error": err.Error(),
		})
	}
	return rollbackCreate(om.ctx, om.client, ouDN, operation, origErr)
}
