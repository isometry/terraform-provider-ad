# Suggested Commands

## Development Workflow

### Build and Install
```bash
make install        # Builds and installs to $GOPATH/bin
make build          # Build without installing
go build -v ./...   # Manual build
```

### Code Quality
```bash
make fmt            # Format Go code with gofmt
make lint           # Run golangci-lint with .golangci.yml config
make                # Default: fmt + lint + install + generate
```

### Testing
```bash
make test           # Unit tests with coverage (-cover -timeout=120s -parallel=10)
make testacc        # Acceptance tests (requires TF_ACC=1, timeout 120m)

# Specific test execution
go test -v ./internal/ldap -run TestGUIDParsing
go test -v ./internal/provider -run TestGroupResource
TF_ACC=1 go test -v ./internal/provider -run TestAccGroupResource_basic

# Coverage output
go test -v -cover -coverprofile=coverage.out ./internal/...
```

### Documentation
```bash
make generate       # Runs tfplugindocs from tools/ directory
cd tools; go generate ./...  # Manual doc generation
```

### Environment Variables
```bash
# Testing
export TF_ACC=1                              # Enable acceptance tests
export TF_LOG=DEBUG                          # Provider-wide debug logging
export TF_LOG_PROVIDER_AD_LDAP=TRACE        # LDAP subsystem trace logging

# Provider Configuration (for acceptance tests)
export AD_DOMAIN=example.com
export AD_USERNAME=terraform
export AD_PASSWORD=secret
export AD_LDAP_URL=ldaps://dc.example.com:636
export AD_BASE_DN=dc=example,dc=com
```

## Darwin/macOS Specific
- Standard Unix commands work: `ls`, `cd`, `grep`, `find`, `cat`, `head`, `tail`
- Package management: Use Homebrew for dependencies
- Go installation: `brew install go` or download from golang.org