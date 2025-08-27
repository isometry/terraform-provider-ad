package ldap

import (
	"context"
	"maps"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Logger interface for LDAP operations.
type Logger interface {
	Debug(msg string, fields map[string]any)
	Info(msg string, fields map[string]any)
	Warn(msg string, fields map[string]any)
	Error(msg string, fields map[string]any)
	Trace(msg string, fields map[string]any)
}

// TFLogger wraps tflog for use in LDAP package.
type TFLogger struct {
	ctx       context.Context
	subsystem string
}

// NewTFLogger creates a new logger for LDAP operations.
func NewTFLogger(ctx context.Context, subsystem string) *TFLogger {
	return &TFLogger{
		ctx:       ctx,
		subsystem: subsystem,
	}
}

func (l *TFLogger) Debug(msg string, fields map[string]any) {
	tflog.SubsystemDebug(l.ctx, l.subsystem, msg, fields)
}

func (l *TFLogger) Info(msg string, fields map[string]any) {
	tflog.SubsystemInfo(l.ctx, l.subsystem, msg, fields)
}

func (l *TFLogger) Warn(msg string, fields map[string]any) {
	tflog.SubsystemWarn(l.ctx, l.subsystem, msg, fields)
}

func (l *TFLogger) Error(msg string, fields map[string]any) {
	tflog.SubsystemError(l.ctx, l.subsystem, msg, fields)
}

func (l *TFLogger) Trace(msg string, fields map[string]any) {
	tflog.SubsystemTrace(l.ctx, l.subsystem, msg, fields)
}

// LogOperation is a helper function to log an operation with timing.
func LogOperation(ctx context.Context, subsystem, operation string, fields map[string]any, fn func() error) error {
	start := time.Now()

	// Add operation to fields
	if fields == nil {
		fields = make(map[string]any)
	}
	fields["operation"] = operation

	tflog.SubsystemDebug(ctx, subsystem, "Starting operation", fields)

	err := fn()

	// Add timing and result to fields
	fields["duration_ms"] = time.Since(start).Milliseconds()

	if err != nil {
		fields["error"] = err.Error()
		tflog.SubsystemError(ctx, subsystem, "Operation failed", fields)
	} else {
		tflog.SubsystemDebug(ctx, subsystem, "Operation completed successfully", fields)
	}

	return err
}

// LogPerformance logs performance metrics for an operation.
func LogPerformance(ctx context.Context, subsystem, operation string, duration time.Duration, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any)
	}

	fields["operation"] = operation
	fields["duration_ms"] = duration.Milliseconds()

	// Log performance warnings for slow operations
	if duration > 5*time.Second {
		tflog.SubsystemWarn(ctx, subsystem, "Slow operation detected", fields)
	} else if duration > 1*time.Second {
		tflog.SubsystemInfo(ctx, subsystem, "Operation performance", fields)
	} else {
		tflog.SubsystemDebug(ctx, subsystem, "Operation performance", fields)
	}
}

// LogLDAPError logs LDAP-specific error information.
func LogLDAPError(ctx context.Context, subsystem string, operation string, err error, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any)
	}

	fields["operation"] = operation
	fields["error"] = err.Error()

	// Add LDAP-specific error information if available
	if ldapErr, ok := err.(*ldap.Error); ok {
		fields["ldap_result_code"] = ldapErr.ResultCode
		if ldapErr.MatchedDN != "" {
			fields["ldap_matched_dn"] = ldapErr.MatchedDN
		}
		if ldapErr.Err != nil {
			fields["ldap_diagnostic_message"] = ldapErr.Err.Error()
		}
	}

	tflog.SubsystemError(ctx, subsystem, "LDAP operation failed", fields)
}

// LogConnectionEvent logs connection-related events.
func LogConnectionEvent(ctx context.Context, event string, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any)
	}

	fields["event"] = event

	switch event {
	case "connection_established", "connection_reused", "authentication_success":
		tflog.SubsystemInfo(ctx, "ldap", "Connection event", fields)
	case "connection_failed", "authentication_failed", "connection_lost":
		tflog.SubsystemError(ctx, "ldap", "Connection event", fields)
	case "connection_attempt", "authentication_attempt":
		tflog.SubsystemDebug(ctx, "ldap", "Connection event", fields)
	default:
		tflog.SubsystemDebug(ctx, "ldap", "Connection event", fields)
	}
}

// LogKerberosEvent logs Kerberos-specific events.
func LogKerberosEvent(ctx context.Context, event string, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any)
	}

	fields["event"] = event

	switch event {
	case "ticket_acquired", "keytab_loaded", "credentials_cached":
		tflog.SubsystemInfo(ctx, "kerberos", "Kerberos event", fields)
	case "ticket_acquisition_failed", "keytab_load_failed", "authentication_failed":
		tflog.SubsystemError(ctx, "kerberos", "Kerberos event", fields)
	case "ticket_renewal", "cache_cleanup", "principal_resolved":
		tflog.SubsystemDebug(ctx, "kerberos", "Kerberos event", fields)
	default:
		tflog.SubsystemTrace(ctx, "kerberos", "Kerberos event", fields)
	}
}

// LogPoolEvent logs connection pool events.
func LogPoolEvent(ctx context.Context, event string, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any)
	}

	fields["event"] = event

	switch event {
	case "pool_initialized", "connection_acquired", "connection_released":
		tflog.SubsystemDebug(ctx, "pool", "Pool event", fields)
	case "pool_exhausted", "connection_failed", "health_check_failed":
		tflog.SubsystemWarn(ctx, "pool", "Pool event", fields)
	case "pool_creation_failed", "all_connections_failed":
		tflog.SubsystemError(ctx, "pool", "Pool event", fields)
	default:
		tflog.SubsystemTrace(ctx, "pool", "Pool event", fields)
	}
}

// SanitizeFields removes sensitive information from log fields.
func SanitizeFields(fields map[string]any) map[string]any {
	sanitized := make(map[string]any)

	sensitiveKeys := map[string]bool{
		"password":    true,
		"passwd":      true,
		"secret":      true,
		"token":       true,
		"key":         true,
		"private_key": true,
		"credential":  true,
		"credentials": true,
	}

	for k, v := range fields {
		// Check if this is a sensitive field
		if sensitiveKeys[k] {
			sanitized[k] = "[REDACTED]"
		} else {
			// Check if the value contains sensitive patterns
			if str, ok := v.(string); ok && containsSensitivePattern(str) {
				sanitized[k] = "[REDACTED]"
			} else {
				sanitized[k] = v
			}
		}
	}

	return sanitized
}

// containsSensitivePattern checks if a string contains patterns that might be sensitive.
func containsSensitivePattern(s string) bool {
	// Check for common sensitive patterns (very basic - could be enhanced)
	patterns := []string{
		"password=",
		"passwd=",
		"secret=",
		"token=",
		"key=",
	}

	lower := strings.ToLower(s)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// LogResourceOperation provides standardized entry/exit logging for Terraform resource operations.
func LogResourceOperation(ctx context.Context, resource, operation string, fields map[string]any) func(error) {
	start := time.Now()

	if fields == nil {
		fields = make(map[string]any)
	}

	// Create entry fields
	entryFields := make(map[string]any)
	maps.Copy(entryFields, fields)
	entryFields["resource"] = resource
	entryFields["operation"] = operation

	tflog.SubsystemDebug(ctx, "provider", "Starting resource operation", entryFields)

	return func(err error) {
		// Create exit fields
		exitFields := make(map[string]any)
		maps.Copy(exitFields, fields)
		exitFields["resource"] = resource
		exitFields["operation"] = operation
		exitFields["duration_ms"] = time.Since(start).Milliseconds()
		exitFields["has_error"] = err != nil

		if err != nil {
			exitFields["error"] = err.Error()
			tflog.SubsystemError(ctx, "provider", "Resource operation failed", exitFields)
		} else {
			tflog.SubsystemDebug(ctx, "provider", "Resource operation completed", exitFields)
		}
	}
}

// LogDataSourceOperation provides standardized entry/exit logging for Terraform data source operations.
func LogDataSourceOperation(ctx context.Context, dataSource, operation string, fields map[string]any) func(error) {
	start := time.Now()

	if fields == nil {
		fields = make(map[string]any)
	}

	// Create entry fields
	entryFields := make(map[string]any)
	maps.Copy(entryFields, fields)
	entryFields["data_source"] = dataSource
	entryFields["operation"] = operation

	tflog.SubsystemDebug(ctx, "provider", "Starting data source operation", entryFields)

	return func(err error) {
		// Create exit fields
		exitFields := make(map[string]any)
		maps.Copy(exitFields, fields)
		exitFields["data_source"] = dataSource
		exitFields["operation"] = operation
		exitFields["duration_ms"] = time.Since(start).Milliseconds()
		exitFields["has_error"] = err != nil

		if err != nil {
			exitFields["error"] = err.Error()
			tflog.SubsystemError(ctx, "provider", "Data source operation failed", exitFields)
		} else {
			tflog.SubsystemDebug(ctx, "provider", "Data source operation completed", exitFields)
		}
	}
}
