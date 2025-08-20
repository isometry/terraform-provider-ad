package ldap

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestNewLDAPError(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		err       error
		wantNil   bool
	}{
		{
			name:      "nil error",
			operation: "search",
			err:       nil,
			wantNil:   true,
		},
		{
			name:      "ldap error",
			operation: "bind",
			err:       ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad password")),
			wantNil:   false,
		},
		{
			name:      "generic error",
			operation: "connect",
			err:       errors.New("connection refused"),
			wantNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewLDAPError(tt.operation, tt.err)

			if tt.wantNil && result != nil {
				t.Errorf("NewLDAPError() = %v, want nil", result)
			}

			if !tt.wantNil && result == nil {
				t.Error("NewLDAPError() = nil, want non-nil")
			}

			if result != nil {
				if result.Operation != tt.operation {
					t.Errorf("Operation = %s, want %s", result.Operation, tt.operation)
				}

				if result.Cause != tt.err {
					t.Errorf("Cause = %v, want %v", result.Cause, tt.err)
				}
			}
		})
	}
}

func TestLDAPError_Error(t *testing.T) {
	tests := []struct {
		name    string
		ldapErr *LDAPError
		want    string
	}{
		{
			name: "basic error",
			ldapErr: &LDAPError{
				Operation: "search",
				Message:   "operation failed",
			},
			want: "LDAP search failed - operation failed",
		},
		{
			name: "error with code",
			ldapErr: &LDAPError{
				Operation: "bind",
				LDAPCode:  ldap.LDAPResultInvalidCredentials,
				Message:   "authentication failed",
			},
			want: "LDAP bind failed (code 49) - authentication failed",
		},
		{
			name: "error with server message",
			ldapErr: &LDAPError{
				Operation: "add",
				Message:   "validation failed",
				ServerMsg: "attribute required",
			},
			want: "LDAP add failed - validation failed - server: attribute required",
		},
		{
			name: "error with DN",
			ldapErr: &LDAPError{
				Operation: "modify",
				Message:   "access denied",
				DN:        "cn=user,dc=example,dc=com",
			},
			want: "LDAP modify failed - access denied - DN: cn=user,dc=example,dc=com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ldapErr.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCategorizeError(t *testing.T) {
	tests := []struct {
		name string
		code uint16
		want ErrorCategory
	}{
		{
			name: "authentication error",
			code: ldap.LDAPResultInvalidCredentials,
			want: ErrorCategoryAuthentication,
		},
		{
			name: "permission error",
			code: ldap.LDAPResultInsufficientAccessRights,
			want: ErrorCategoryPermission,
		},
		{
			name: "not found error",
			code: ldap.LDAPResultNoSuchObject,
			want: ErrorCategoryNotFound,
		},
		{
			name: "conflict error",
			code: ldap.LDAPResultEntryAlreadyExists,
			want: ErrorCategoryConflict,
		},
		{
			name: "validation error",
			code: ldap.LDAPResultConstraintViolation,
			want: ErrorCategoryValidation,
		},
		{
			name: "server error",
			code: ldap.LDAPResultBusy,
			want: ErrorCategoryServer,
		},
		{
			name: "connection error",
			code: ldap.LDAPResultConnectError,
			want: ErrorCategoryConnection,
		},
		{
			name: "unknown error",
			code: 9999,
			want: ErrorCategoryUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := categorizeError(tt.code)
			if got != tt.want {
				t.Errorf("categorizeError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCategorizeGenericError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorCategory
	}{
		{
			name: "connection error",
			err:  errors.New("connection refused"),
			want: ErrorCategoryConnection,
		},
		{
			name: "timeout error",
			err:  errors.New("operation timeout"),
			want: ErrorCategoryConnection,
		},
		{
			name: "authentication error",
			err:  errors.New("invalid credentials"),
			want: ErrorCategoryAuthentication,
		},
		{
			name: "permission error",
			err:  errors.New("access denied"),
			want: ErrorCategoryPermission,
		},
		{
			name: "unknown error",
			err:  errors.New("something went wrong"),
			want: ErrorCategoryUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := categorizeGenericError(tt.err)
			if got != tt.want {
				t.Errorf("categorizeGenericError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsLDAPCodeRetryable(t *testing.T) {
	tests := []struct {
		name string
		code uint16
		want bool
	}{
		{
			name: "busy - retryable",
			code: ldap.LDAPResultBusy,
			want: true,
		},
		{
			name: "unavailable - retryable",
			code: ldap.LDAPResultUnavailable,
			want: true,
		},
		{
			name: "server down - retryable",
			code: ldap.LDAPResultServerDown,
			want: true,
		},
		{
			name: "invalid credentials - not retryable",
			code: ldap.LDAPResultInvalidCredentials,
			want: false,
		},
		{
			name: "no such object - not retryable",
			code: ldap.LDAPResultNoSuchObject,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLDAPCodeRetryable(tt.code)
			if got != tt.want {
				t.Errorf("isLDAPCodeRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsGenericErrorRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "connection error - retryable",
			err:  errors.New("connection refused"),
			want: true,
		},
		{
			name: "timeout error - retryable",
			err:  errors.New("operation timeout"),
			want: true,
		},
		{
			name: "temporary failure - retryable",
			err:  errors.New("temporary failure"),
			want: true,
		},
		{
			name: "broken pipe - retryable",
			err:  errors.New("broken pipe"),
			want: true,
		},
		{
			name: "validation error - not retryable",
			err:  errors.New("invalid syntax"),
			want: false,
		},
		{
			name: "permission error - not retryable",
			err:  errors.New("access denied"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGenericErrorRetryable(tt.err)
			if got != tt.want {
				t.Errorf("isGenericErrorRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWrapError(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		err       error
		wantNil   bool
	}{
		{
			name:      "nil error",
			operation: "search",
			err:       nil,
			wantNil:   true,
		},
		{
			name:      "regular error",
			operation: "bind",
			err:       errors.New("authentication failed"),
			wantNil:   false,
		},
		{
			name:      "already wrapped error",
			operation: "search",
			err:       &LDAPError{Operation: "existing", Message: "test"},
			wantNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapError(tt.operation, tt.err)

			if tt.wantNil && result != nil {
				t.Errorf("WrapError() = %v, want nil", result)
			}

			if !tt.wantNil && result == nil {
				t.Error("WrapError() = nil, want non-nil")
			}

			if result != nil {
				if ldapErr, ok := result.(*LDAPError); ok {
					// For already wrapped errors, operation should be preserved
					if existingErr, ok := tt.err.(*LDAPError); ok {
						if existingErr.Operation != "" {
							if ldapErr.Operation != existingErr.Operation {
								t.Errorf("Operation preserved incorrectly")
							}
						} else {
							if ldapErr.Operation != tt.operation {
								t.Errorf("Operation = %s, want %s", ldapErr.Operation, tt.operation)
							}
						}
					} else {
						if ldapErr.Operation != tt.operation {
							t.Errorf("Operation = %s, want %s", ldapErr.Operation, tt.operation)
						}
					}
				}
			}
		})
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "retryable connection error",
			err:  NewConnectionError("connection failed", true, nil),
			want: true,
		},
		{
			name: "non-retryable connection error",
			err:  NewConnectionError("config error", false, nil),
			want: false,
		},
		{
			name: "retryable LDAP error",
			err:  NewLDAPError("search", ldap.NewError(ldap.LDAPResultBusy, errors.New("server busy"))),
			want: true,
		},
		{
			name: "non-retryable LDAP error",
			err:  NewLDAPError("bind", ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad password"))),
			want: false,
		},
		{
			name: "generic retryable error",
			err:  errors.New("connection timeout"),
			want: true,
		},
		{
			name: "generic non-retryable error",
			err:  errors.New("invalid syntax"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRetryableError(tt.err)
			if got != tt.want {
				t.Errorf("IsRetryableError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetErrorCategory(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorCategory
	}{
		{
			name: "nil error",
			err:  nil,
			want: ErrorCategoryUnknown,
		},
		{
			name: "LDAP error",
			err:  NewLDAPError("bind", ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad password"))),
			want: ErrorCategoryAuthentication,
		},
		{
			name: "generic error",
			err:  errors.New("connection refused"),
			want: ErrorCategoryConnection,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetErrorCategory(tt.err)
			if got != tt.want {
				t.Errorf("GetErrorCategory() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorHelperFunctions(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		isNotFound bool
		isConflict bool
		isAuth     bool
		isPerm     bool
	}{
		{
			name:       "not found error",
			err:        NewLDAPError("search", ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("object not found"))),
			isNotFound: true,
		},
		{
			name:       "conflict error",
			err:        NewLDAPError("add", ldap.NewError(ldap.LDAPResultEntryAlreadyExists, errors.New("entry exists"))),
			isConflict: true,
		},
		{
			name:   "authentication error",
			err:    NewLDAPError("bind", ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad password"))),
			isAuth: true,
		},
		{
			name:   "permission error",
			err:    NewLDAPError("modify", ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("access denied"))),
			isPerm: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsNotFoundError(tt.err) != tt.isNotFound {
				t.Errorf("IsNotFoundError() = %v, want %v", IsNotFoundError(tt.err), tt.isNotFound)
			}

			if IsConflictError(tt.err) != tt.isConflict {
				t.Errorf("IsConflictError() = %v, want %v", IsConflictError(tt.err), tt.isConflict)
			}

			if IsAuthenticationError(tt.err) != tt.isAuth {
				t.Errorf("IsAuthenticationError() = %v, want %v", IsAuthenticationError(tt.err), tt.isAuth)
			}

			if IsPermissionError(tt.err) != tt.isPerm {
				t.Errorf("IsPermissionError() = %v, want %v", IsPermissionError(tt.err), tt.isPerm)
			}
		})
	}
}

func TestGetLDAPCodeMessage(t *testing.T) {
	tests := []struct {
		name string
		code uint16
		want string
	}{
		{
			name: "success",
			code: ldap.LDAPResultSuccess,
			want: "Operation completed successfully",
		},
		{
			name: "invalid credentials",
			code: ldap.LDAPResultInvalidCredentials,
			want: "Invalid credentials",
		},
		{
			name: "no such object",
			code: ldap.LDAPResultNoSuchObject,
			want: "Requested object does not exist",
		},
		{
			name: "entry already exists",
			code: ldap.LDAPResultEntryAlreadyExists,
			want: "Entry already exists",
		},
		{
			name: "unknown code",
			code: 9999,
			want: "Unknown LDAP error (code 9999)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getLDAPCodeMessage(tt.code)
			if got != tt.want {
				t.Errorf("getLDAPCodeMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}
