# LinkFlow Execution Engine

## Build Commands

```bash
make build              # Build all services
make build-frontend     # Build individual service
make build-{service}    # Services: frontend, history, matching, worker, timer, visibility, edge, control-plane
```

## Test Commands

```bash
make test               # Run all tests with race detector
make test-cover         # Run tests with coverage report
make lint               # Run golangci-lint
```

## Development

```bash
make dev                # Run with hot reload (air)
make run-{service}      # Run individual service
make tools              # Install dev tools (buf, golangci-lint, air, mockgen)
```

## Proto Generation

```bash
make proto              # Generate protobuf code using buf
make generate           # Run go generate
```

## Docker

```bash
make docker             # Build all Docker images
make docker-{service}   # Build individual image
docker-compose up -d    # Start local dev environment
```

## Database

```bash
make migrate-up         # Run migrations up
make migrate-down       # Run migrations down
```

## Code Style Guidelines

- Follow standard Go conventions and idioms
- Use `gofmt` and `goimports` for formatting
- Error messages should be lowercase, no trailing punctuation
- Use context.Context as first parameter for functions that do I/O
- Prefer returning errors over panicking
- Use meaningful variable names; avoid single-letter names except for loop indices
- Group imports: stdlib, external, internal
- Write table-driven tests where appropriate
- Use interfaces for dependencies to enable testing

## Project Structure

```
go-engine/
├── cmd/                    # Service entry points
│   ├── control-plane/      # Cluster management service
│   ├── frontend/           # API gateway service
│   ├── history/            # Workflow history service
│   ├── matching/           # Task matching service
│   ├── worker/             # Workflow worker service
│   ├── timer/              # Timer management service
│   ├── visibility/         # Search and visibility service
│   └── edge/               # Edge proxy service
├── api/
│   └── proto/              # Protocol buffer definitions
│       └── linkflow/
├── internal/               # Private application code
│   ├── frontend/           # Frontend service implementation
│   ├── history/            # History service implementation
│   ├── matching/           # Matching service implementation
│   └── worker/             # Worker service implementation
├── deploy/
│   ├── docker/             # Docker configurations
│   ├── helm/               # Helm charts
│   └── k8s/                # Kubernetes manifests
├── scripts/                # Utility scripts
└── configs/                # Configuration files
```
