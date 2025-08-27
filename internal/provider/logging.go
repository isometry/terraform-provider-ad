package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// initializeLogging initializes the provider subsystem for consistent logging.
// This should be called at the beginning of each data source Read method
// and resource Create/Read/Update/Delete methods.
func initializeLogging(ctx context.Context) context.Context {
	// Initialize provider subsystem using Terraform standard environment variable
	// Pattern: TF_LOG_PROVIDER_AD_<SUBSYSTEM>
	return tflog.NewSubsystem(ctx, "provider",
		tflog.WithLevelFromEnv("TF_LOG_PROVIDER_AD_PROVIDER"))
}
