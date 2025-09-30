# Task Completion Checklist

When completing any development task in this project, follow these steps:

## 1. Code Quality
- [ ] Run `make fmt` to format all Go code
- [ ] Run `make lint` to check for linting issues
- [ ] Fix all linting errors before committing
- [ ] Ensure all exported symbols have doc comments

## 2. Testing
- [ ] Write unit tests for new functionality (*_test.go files)
- [ ] Run `make test` and ensure all tests pass
- [ ] If modifying resources/data sources, write/update acceptance tests (TestAcc*)
- [ ] For acceptance tests, set `TF_ACC=1` and provide AD test environment
- [ ] Ensure test coverage is maintained or improved

## 3. Documentation
- [ ] Update schema descriptions (MarkdownDescription fields)
- [ ] Add examples to examples/ directory if adding new resources
- [ ] Run `make generate` to regenerate documentation
- [ ] Update CLAUDE.md if architecture changes
- [ ] Update DESIGN.md for significant design decisions

## 4. LDAP-Specific Considerations
- [ ] Use logging context (`utils.InitializeLogging(ctx)`)
- [ ] Wrap errors with context (`fmt.Errorf("description: %w", err)`)
- [ ] Use proper GUID handling (`ldap.ParseGUID()`, `ldap.FormatGUID()`)
- [ ] Normalize DNs for case-insensitive comparison
- [ ] Handle binary attributes (GUID, SID) correctly

## 5. Resource Implementation
- [ ] Use objectGUID as Terraform resource ID
- [ ] Implement all CRUD operations (Create, Read, Update, Delete)
- [ ] Implement ImportState for existing resources
- [ ] Add proper validators and plan modifiers
- [ ] Handle computed attributes correctly

## 6. Final Validation
- [ ] Run `make` (default target: fmt + lint + install + generate)
- [ ] Verify build succeeds: `go build -v ./...`
- [ ] Run full test suite: `make test`
- [ ] Check git status and review changes
- [ ] Ensure no temporary files or debug code remain