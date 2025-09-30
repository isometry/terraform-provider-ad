# Code Style and Conventions

## Go Style
- **Formatter**: `gofmt -s -w -e .` (simplify, write, show errors)
- **Linter**: golangci-lint with extensive linter set (see .golangci.yml)
- **Enabled Linters**: copyloopvar, durationcheck, errcheck, forcetypeassert, godot, ineffassign, makezero, misspell, nilerr, predeclared, staticcheck, unconvert, unparam, unused, usetesting

## Naming Conventions
- **Package naming**: snake_case (e.g., `internal/ldap`, `internal/provider`)
- **Exported types**: PascalCase (e.g., `GroupResource`, `Client`)
- **Unexported types**: camelCase (e.g., `client`, `config`)
- **Constants**: PascalCase for exported, camelCase for internal
- **Interfaces**: Usually same as implementation but capitalized (e.g., `Client` interface, `client` struct)

## Code Organization
- **Internal packages**: All code in `internal/` (not importable externally)
- **LDAP logic**: `internal/ldap/` - all Active Directory/LDAP operations
- **Provider logic**: `internal/provider/` - all Terraform framework code
- **Utilities**: `internal/utils/` - shared utilities (logging)
- **Custom types**: `internal/provider/types/` - custom Terraform types
- **Validators**: `internal/provider/validators/` - custom validators
- **Plan modifiers**: `internal/provider/planmodifiers/` - custom plan modifiers

## Testing Patterns
- **Unit tests**: `*_test.go` files alongside implementation
- **Acceptance tests**: Prefix with `TestAcc*` (e.g., `TestAccGroupResource_basic`)
- **Test configuration**: Parallel execution (10 concurrent), timeouts (120s unit, 120m acceptance)

## Error Handling
- **Error wrapping**: Use `fmt.Errorf("description: %w", err)` for error chains
- **Context passing**: Always pass context for logging subsystem integration
- **Logging levels**: SubsystemDebug, SubsystemInfo, SubsystemError, SubsystemTrace

## Documentation
- **Comments**: All exported symbols must have doc comments
- **Schema descriptions**: MarkdownDescription field for all Terraform schema attributes
- **Examples**: Located in examples/ directory