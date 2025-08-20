package ldap

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ErrorCategory represents different categories of LDAP errors.
type ErrorCategory string

const (
	ErrorCategoryConnection     ErrorCategory = "connection"
	ErrorCategoryAuthentication ErrorCategory = "authentication"
	ErrorCategoryPermission     ErrorCategory = "permission"
	ErrorCategoryNotFound       ErrorCategory = "not_found"
	ErrorCategoryConflict       ErrorCategory = "conflict"
	ErrorCategoryValidation     ErrorCategory = "validation"
	ErrorCategoryServer         ErrorCategory = "server"
	ErrorCategoryUnknown        ErrorCategory = "unknown"
)

// LDAPError provides enhanced error information for LDAP operations.
type LDAPError struct {
	Operation string        // The operation that failed
	Category  ErrorCategory // Error category
	LDAPCode  uint16        // LDAP result code
	Message   string        // Human-readable message
	ServerMsg string        // Server-provided message
	DN        string        // DN involved in the operation (if applicable)
	Retryable bool          // Whether the error is retryable
	Cause     error         // Underlying error
}

func (e *LDAPError) Error() string {
	var parts []string

	if e.LDAPCode > 0 {
		parts = append(parts, fmt.Sprintf("LDAP %s failed (code %d)", e.Operation, e.LDAPCode))
	} else {
		parts = append(parts, fmt.Sprintf("LDAP %s failed", e.Operation))
	}

	if e.Message != "" {
		parts = append(parts, e.Message)
	}

	if e.ServerMsg != "" && e.ServerMsg != e.Message {
		parts = append(parts, fmt.Sprintf("server: %s", e.ServerMsg))
	}

	if e.DN != "" {
		parts = append(parts, fmt.Sprintf("DN: %s", e.DN))
	}

	return strings.Join(parts, " - ")
}

func (e *LDAPError) IsRetryable() bool {
	return e.Retryable
}

func (e *LDAPError) Unwrap() error {
	return e.Cause
}

// GetCategory returns the error category.
func (e *LDAPError) GetCategory() ErrorCategory {
	return e.Category
}

// GetLDAPCode returns the LDAP result code.
func (e *LDAPError) GetLDAPCode() uint16 {
	return e.LDAPCode
}

// NewLDAPError creates a new LDAP error.
func NewLDAPError(operation string, err error) *LDAPError {
	if err == nil {
		return nil
	}

	ldapErr := &LDAPError{
		Operation: operation,
		Cause:     err,
	}

	// Extract LDAP-specific information
	if ldapResultErr, ok := err.(*ldap.Error); ok {
		ldapErr.LDAPCode = ldapResultErr.ResultCode
		ldapErr.ServerMsg = ldapResultErr.Err.Error()
		ldapErr.Category = categorizeError(ldapResultErr.ResultCode)
		ldapErr.Retryable = isLDAPCodeRetryable(ldapResultErr.ResultCode)
		ldapErr.Message = getLDAPCodeMessage(ldapResultErr.ResultCode)
	} else {
		// Non-LDAP error, categorize by error message
		ldapErr.Category = categorizeGenericError(err)
		ldapErr.Retryable = isGenericErrorRetryable(err)
		ldapErr.Message = err.Error()
	}

	return ldapErr
}

// categorizeError categorizes an error based on LDAP result code.
func categorizeError(code uint16) ErrorCategory {
	switch code {
	case ldap.LDAPResultSuccess:
		return ErrorCategoryUnknown // Should not happen for errors

	// Authentication errors
	case ldap.LDAPResultInvalidCredentials,
		ldap.LDAPResultInappropriateAuthentication,
		ldap.LDAPResultStrongAuthRequired:
		return ErrorCategoryAuthentication

	// Permission errors
	case ldap.LDAPResultInsufficientAccessRights,
		ldap.LDAPResultUnwillingToPerform:
		return ErrorCategoryPermission

	// Not found errors
	case ldap.LDAPResultNoSuchObject,
		ldap.LDAPResultNoSuchAttribute,
		ldap.LDAPResultUndefinedAttributeType:
		return ErrorCategoryNotFound

	// Conflict errors
	case ldap.LDAPResultEntryAlreadyExists,
		ldap.LDAPResultAttributeOrValueExists,
		ldap.LDAPResultObjectClassViolation,
		ldap.LDAPResultNotAllowedOnNonLeaf:
		return ErrorCategoryConflict

	// Validation errors
	case ldap.LDAPResultInvalidAttributeSyntax,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultInvalidDNSyntax,
		ldap.LDAPResultNamingViolation:
		return ErrorCategoryValidation

	// Server/connection errors
	case ldap.LDAPResultServerDown,
		ldap.LDAPResultUnavailable,
		ldap.LDAPResultBusy,
		ldap.LDAPResultTimeLimitExceeded,
		ldap.LDAPResultAdminLimitExceeded:
		return ErrorCategoryServer

	// Connection errors
	case ldap.LDAPResultConnectError,
		ldap.LDAPResultProtocolError:
		return ErrorCategoryConnection

	default:
		return ErrorCategoryUnknown
	}
}

// categorizeGenericError categorizes non-LDAP errors.
func categorizeGenericError(err error) ErrorCategory {
	errStr := strings.ToLower(err.Error())

	if strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "network") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") {
		return ErrorCategoryConnection
	}

	if strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "credentials") ||
		strings.Contains(errStr, "password") {
		return ErrorCategoryAuthentication
	}

	if strings.Contains(errStr, "permission") ||
		strings.Contains(errStr, "access") ||
		strings.Contains(errStr, "denied") {
		return ErrorCategoryPermission
	}

	return ErrorCategoryUnknown
}

// isLDAPCodeRetryable determines if an LDAP error code indicates a retryable condition.
func isLDAPCodeRetryable(code uint16) bool {
	switch code {
	case ldap.LDAPResultBusy,
		ldap.LDAPResultUnavailable,
		ldap.LDAPResultServerDown,
		ldap.LDAPResultTimeLimitExceeded,
		ldap.LDAPResultConnectError:
		return true
	default:
		return false
	}
}

// isGenericErrorRetryable determines if a generic error is retryable.
func isGenericErrorRetryable(err error) bool {
	errStr := strings.ToLower(err.Error())

	// Network and connection errors are typically retryable
	retryablePatterns := []string{
		"connection",
		"timeout",
		"network",
		"broken pipe",
		"connection reset",
		"temporary failure",
		"server temporarily unavailable",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// getLDAPCodeMessage returns a human-readable message for an LDAP result code.
func getLDAPCodeMessage(code uint16) string {
	switch code {
	case ldap.LDAPResultSuccess:
		return "Operation completed successfully"
	case ldap.LDAPResultOperationsError:
		return "LDAP operations error"
	case ldap.LDAPResultProtocolError:
		return "LDAP protocol error"
	case ldap.LDAPResultTimeLimitExceeded:
		return "LDAP time limit exceeded"
	case ldap.LDAPResultSizeLimitExceeded:
		return "LDAP size limit exceeded"
	case ldap.LDAPResultCompareFalse:
		return "LDAP compare returned false"
	case ldap.LDAPResultCompareTrue:
		return "LDAP compare returned true"
	case ldap.LDAPResultAuthMethodNotSupported:
		return "Authentication method not supported"
	case ldap.LDAPResultStrongAuthRequired:
		return "Strong authentication required"
	case ldap.LDAPResultReferral:
		return "LDAP referral"
	case ldap.LDAPResultAdminLimitExceeded:
		return "Administrative limit exceeded"
	case ldap.LDAPResultUnavailableCriticalExtension:
		return "Critical extension unavailable"
	case ldap.LDAPResultConfidentialityRequired:
		return "Confidentiality required"
	case ldap.LDAPResultSaslBindInProgress:
		return "SASL bind in progress"
	case ldap.LDAPResultNoSuchAttribute:
		return "Requested attribute does not exist"
	case ldap.LDAPResultUndefinedAttributeType:
		return "Attribute type is not defined"
	case ldap.LDAPResultInappropriateMatching:
		return "Inappropriate matching rule"
	case ldap.LDAPResultConstraintViolation:
		return "Constraint violation"
	case ldap.LDAPResultAttributeOrValueExists:
		return "Attribute or value already exists"
	case ldap.LDAPResultInvalidAttributeSyntax:
		return "Invalid attribute syntax"
	case ldap.LDAPResultNoSuchObject:
		return "Requested object does not exist"
	case ldap.LDAPResultAliasProblem:
		return "Alias problem"
	case ldap.LDAPResultInvalidDNSyntax:
		return "Invalid DN syntax"
	case ldap.LDAPResultAliasDereferencingProblem:
		return "Alias dereferencing problem"
	case ldap.LDAPResultInappropriateAuthentication:
		return "Inappropriate authentication method"
	case ldap.LDAPResultInvalidCredentials:
		return "Invalid credentials"
	case ldap.LDAPResultInsufficientAccessRights:
		return "Insufficient access rights"
	case ldap.LDAPResultBusy:
		return "Server is busy"
	case ldap.LDAPResultUnavailable:
		return "Server is unavailable"
	case ldap.LDAPResultUnwillingToPerform:
		return "Server is unwilling to perform the operation"
	case ldap.LDAPResultLoopDetect:
		return "Loop detected"
	case ldap.LDAPResultNamingViolation:
		return "Naming violation"
	case ldap.LDAPResultObjectClassViolation:
		return "Object class violation"
	case ldap.LDAPResultNotAllowedOnNonLeaf:
		return "Operation not allowed on non-leaf entry"
	case ldap.LDAPResultNotAllowedOnRDN:
		return "Operation not allowed on RDN"
	case ldap.LDAPResultEntryAlreadyExists:
		return "Entry already exists"
	case ldap.LDAPResultObjectClassModsProhibited:
		return "Object class modifications prohibited"
	case ldap.LDAPResultAffectsMultipleDSAs:
		return "Operation affects multiple DSAs"
	case ldap.LDAPResultServerDown:
		return "Server is down"
	case ldap.LDAPResultLocalError:
		return "Local error occurred"
	case ldap.LDAPResultEncodingError:
		return "Encoding error"
	case ldap.LDAPResultDecodingError:
		return "Decoding error"
	case ldap.LDAPResultTimeout:
		return "Operation timed out"
	case ldap.LDAPResultAuthUnknown:
		return "Unknown authentication method"
	case ldap.LDAPResultFilterError:
		return "Invalid search filter"
	case ldap.LDAPResultUserCanceled:
		return "User canceled operation"
	case ldap.LDAPResultParamError:
		return "Parameter error"
	case ldap.LDAPResultNoMemory:
		return "Out of memory"
	case ldap.LDAPResultConnectError:
		return "Connection error"
	case ldap.LDAPResultNotSupported:
		return "Operation not supported"
	case ldap.LDAPResultControlNotFound:
		return "Control not found"
	case ldap.LDAPResultNoResultsReturned:
		return "No results returned"
	case ldap.LDAPResultMoreResultsToReturn:
		return "More results available"
	case ldap.LDAPResultClientLoop:
		return "Client loop detected"
	case ldap.LDAPResultReferralLimitExceeded:
		return "Referral limit exceeded"
	default:
		return fmt.Sprintf("Unknown LDAP error (code %d)", code)
	}
}

// WrapError wraps an error with operation context.
func WrapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	if ldapErr, ok := err.(*LDAPError); ok {
		// Already wrapped, just update operation if needed
		if ldapErr.Operation == "" {
			ldapErr.Operation = operation
		}
		return ldapErr
	}

	return NewLDAPError(operation, err)
}

// IsRetryableError checks if an error is retryable.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	if retryable, ok := err.(RetryableError); ok {
		return retryable.IsRetryable()
	}

	if ldapErr, ok := err.(*LDAPError); ok {
		return ldapErr.IsRetryable()
	}

	// Check for generic retryable conditions
	return isGenericErrorRetryable(err)
}

// GetErrorCategory returns the category of an error.
func GetErrorCategory(err error) ErrorCategory {
	if err == nil {
		return ErrorCategoryUnknown
	}

	if ldapErr, ok := err.(*LDAPError); ok {
		return ldapErr.GetCategory()
	}

	// Check for raw go-ldap library errors
	if ldapResultErr, ok := err.(*ldap.Error); ok {
		return categorizeError(ldapResultErr.ResultCode)
	}

	return categorizeGenericError(err)
}

// IsNotFoundError checks if an error indicates a "not found" condition.
func IsNotFoundError(err error) bool {
	return GetErrorCategory(err) == ErrorCategoryNotFound
}

// IsConflictError checks if an error indicates a conflict (already exists).
func IsConflictError(err error) bool {
	return GetErrorCategory(err) == ErrorCategoryConflict
}

// IsAuthenticationError checks if an error indicates an authentication problem.
func IsAuthenticationError(err error) bool {
	return GetErrorCategory(err) == ErrorCategoryAuthentication
}

// IsPermissionError checks if an error indicates a permission problem.
func IsPermissionError(err error) bool {
	return GetErrorCategory(err) == ErrorCategoryPermission
}
