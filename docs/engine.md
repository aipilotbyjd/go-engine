# LinkFlow Execution Engine — Hyperscale Architecture
> **Version**: 1.0.0  
> **Status**: Architecture Specification  
> **Last Updated**: 2026-01-31
---
## Table of Contents
1. [Overview](#1-overview)
2. [Design Principles](#2-design-principles)
3. [System Architecture](#3-system-architecture)
4. [Project Structure](#4-project-structure)
5. [Core Services](#5-core-services)
6. [History Service](#6-history-service)
7. [Execution Engine](#7-execution-engine)
8. [Matching Service](#8-matching-service)
9. [Worker Service](#9-worker-service)
10. [Node SDK](#10-node-sdk)
11. [Expression Engine](#11-expression-engine)
12. [Storage Layer](#12-storage-layer)
13. [Security](#13-security)
14. [Observability](#14-observability)
15. [Resilience & Chaos](#15-resilience--chaos)
16. [Edge Execution](#16-edge-execution)
17. [Database Schema](#17-database-schema)
18. [Message Formats](#18-message-formats)
19. [API Specifications](#19-api-specifications)
20. [Deployment](#20-deployment)
21. [Performance Targets](#21-performance-targets)
22. [Implementation Phases](#22-implementation-phases)
---
## 1. Overview
### What is the Execution Engine?
The LinkFlow Execution Engine is a **Temporal-grade**, distributed workflow execution system written in Go. It handles the actual running of workflows defined in the Laravel API, providing:
- **Durable Execution**: Workflows survive any failure and can replay from history
- **Horizontal Scalability**: Handle millions of concurrent executions
- **Multi-Region**: Active-active deployment across geographic regions
- **Cell Isolation**: Complete blast radius containment per tenant
- **Edge Execution**: Run nodes close to data sources for low latency
### Architecture Overview
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GLOBAL CONTROL PLANE                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Router    │  │  Scheduler  │  │  Federation │  │   Config    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                         ▼
┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────────┐
│      CELL: US-EAST    │ │      CELL: EU-WEST    │ │      CELL: AP-SOUTH   │
│  ┌─────────────────┐  │ │  ┌─────────────────┐  │ │  ┌─────────────────┐  │
│  │    Frontend     │  │ │  │    Frontend     │  │ │  │    Frontend     │  │
│  │    Gateway      │  │ │  │    Gateway      │  │ │  │    Gateway      │  │
│  └────────┬────────┘  │ │  └────────┬────────┘  │ │  └────────┬────────┘  │
│           │           │ │           │           │ │           │           │
│  ┌────────┴────────┐  │ │  ┌────────┴────────┐  │ │  ┌────────┴────────┐  │
│  │    Matching     │  │ │  │    Matching     │  │ │  │    Matching     │  │
│  │    Service      │  │ │  │    Service      │  │ │  │    Service      │  │
│  └────────┬────────┘  │ │  └────────┬────────┘  │ │  └────────┬────────┘  │
│           │           │ │           │           │ │           │           │
│  ┌────────┴────────┐  │ │  ┌────────┴────────┐  │ │  ┌────────┴────────┐  │
│  │    History      │  │ │  │    History      │  │ │  │    History      │  │
│  │    Service      │  │ │  │    Service      │  │ │  │    Service      │  │
│  └────────┬────────┘  │ │  └────────┬────────┘  │ │  └────────┬────────┘  │
│           │           │ │           │           │ │           │           │
│  ┌────────┴────────┐  │ │  ┌────────┴────────┐  │ │  ┌────────┴────────┐  │
│  │    Worker       │  │ │  │    Worker       │  │ │  │    Worker       │  │
│  │    Service      │  │ │  │    Service      │  │ │  │    Service      │  │
│  └─────────────────┘  │ │  └─────────────────┘  │ │  └─────────────────┘  │
│                       │ │                       │ │                       │
│  ┌─────────────────┐  │ │  ┌─────────────────┐  │ │  ┌─────────────────┐  │
│  │   PostgreSQL    │  │ │  │   PostgreSQL    │  │ │  │   PostgreSQL    │  │
│  │   + Redis       │  │ │  │   + Redis       │  │ │  │   + Redis       │  │
│  └─────────────────┘  │ │  └─────────────────┘  │ │  └─────────────────┘  │
└───────────────────────┘ └───────────────────────┘ └───────────────────────┘
            │                         │                         │
            └─────────────────────────┼─────────────────────────┘
                                      │
                              ┌───────┴───────┐
                              │  CRDT Sync    │
                              │  (Eventual)   │
                              └───────────────┘
```
---
## 2. Design Principles
### Core Principles
| Principle | Description | Implementation |
|-----------|-------------|----------------|
| **Durable Execution** | Workflows survive any failure | Event sourcing with replay |
| **Exactly-Once** | No duplicate side effects | Idempotency keys everywhere |
| **Cell Isolation** | Blast radius containment | Separate infra per cell |
| **Zero-Trust** | No implicit trust | mTLS, encryption at rest |
| **Time-Travel** | Debug any point in history | Full event log retention |
| **Deterministic Replay** | Reproduce any execution | Controlled side effects |
| **Horizontal Scale** | Linear scalability | Sharding, partitioning |
| **Multi-Tenancy** | Secure resource sharing | Quotas, priorities, isolation |
### Comparison with Existing Systems
| Feature | LinkFlow | Temporal | AWS Step Functions |
|---------|----------|----------|-------------------|
| Self-hosted | ✅ | ✅ | ❌ |
| Multi-region | ✅ | ✅ | ✅ |
| Edge execution | ✅ | ❌ | ❌ |
| WASM sandbox | ✅ | ❌ | ❌ |
| Visual builder | ✅ | ❌ | ✅ |
| Event sourcing | ✅ | ✅ | Partial |
| Custom code | ✅ | ✅ | Limited |
---
## 3. System Architecture
### Service Decomposition
```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  Laravel API │  │   CLI Tool   │  │   Web UI     │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
                              │ gRPC / REST
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       GATEWAY LAYER                                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    Frontend Service                           │  │
│  │  • Request routing      • Rate limiting    • Authentication   │  │
│  │  • Load balancing       • Circuit breaking • Request logging  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   Matching    │     │   History     │     │   Worker      │
│   Service     │     │   Service     │     │   Service     │
│               │     │               │     │               │
│ • Task queues │     │ • Event store │     │ • Execution   │
│ • Polling     │     │ • Mutable     │     │ • Isolation   │
│ • Routing     │     │   state       │     │ • Retry       │
│ • Priorities  │     │ • Replay      │     │ • Timeout     │
└───────────────┘     └───────────────┘     └───────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      PERSISTENCE LAYER                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  PostgreSQL  │  │    Redis     │  │   S3/Blob    │              │
│  │  (Primary)   │  │   Cluster    │  │   Storage    │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```
### Data Flow
```
┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Laravel │───▶│ Frontend │───▶│ Matching │───▶│ History  │
│   API   │    │ Gateway  │    │ Service  │    │ Service  │
└─────────┘    └──────────┘    └──────────┘    └────┬─────┘
                                                     │
     ┌───────────────────────────────────────────────┘
     │
     ▼
┌──────────┐    ┌──────────┐    ┌──────────┐
│  Task    │───▶│  Worker  │───▶│  Node    │
│  Queue   │    │  Pool    │    │ Executor │
└──────────┘    └──────────┘    └────┬─────┘
                                      │
     ┌────────────────────────────────┘
     │
     ▼
┌──────────┐    ┌──────────┐    ┌──────────┐
│  Result  │───▶│ History  │───▶│  Next    │
│  Event   │    │  Update  │    │  Node    │
└──────────┘    └──────────┘    └──────────┘
```
---
## 4. Project Structure
```
linkflow-engine/
│
├── cmd/                                 # Service entry points
│   ├── control-plane/                   # Global control plane
│   │   └── main.go
│   ├── frontend/                        # API gateway
│   │   └── main.go
│   ├── history/                         # History service
│   │   └── main.go
│   ├── matching/                        # Matching service
│   │   └── main.go
│   ├── worker/                          # Worker service
│   │   └── main.go
│   ├── timer/                           # Timer service
│   │   └── main.go
│   ├── visibility/                      # Search/query service
│   │   └── main.go
│   └── edge/                            # Edge runtime
│       └── main.go
│
├── api/                                 # API definitions
│   ├── proto/                           # Protocol Buffers
│   │   ├── linkflow/
│   │   │   ├── api/v1/
│   │   │   │   ├── service.proto
│   │   │   │   ├── workflow.proto
│   │   │   │   ├── execution.proto
│   │   │   │   └── query.proto
│   │   │   ├── history/v1/
│   │   │   │   ├── service.proto
│   │   │   │   ├── events.proto
│   │   │   │   └── message.proto
│   │   │   ├── matching/v1/
│   │   │   │   ├── service.proto
│   │   │   │   └── task.proto
│   │   │   └── common/v1/
│   │   │       ├── message.proto
│   │   │       └── enums.proto
│   │   └── buf.yaml
│   └── openapi/
│       └── v1.yaml
│
├── internal/                            # Private packages
│   │
│   ├── frontend/                        # Frontend service
│   │   ├── service.go
│   │   ├── handler/
│   │   │   ├── workflow.go
│   │   │   ├── execution.go
│   │   │   └── query.go
│   │   ├── interceptor/
│   │   │   ├── auth.go
│   │   │   ├── ratelimit.go
│   │   │   └── logging.go
│   │   └── validator/
│   │       └── request.go
│   │
│   ├── history/                         # History service
│   │   ├── service.go
│   │   ├── engine/
│   │   │   ├── engine.go               # State machine engine
│   │   │   ├── state.go                # Mutable state
│   │   │   ├── decision.go             # Decision processing
│   │   │   └── transfer.go             # Task transfer
│   │   ├── events/
│   │   │   ├── builder.go              # Event builder
│   │   │   ├── validator.go            # Event validation
│   │   │   └── serializer.go           # Serialization
│   │   ├── store/
│   │   │   ├── execution.go            # Execution store
│   │   │   ├── history.go              # History store
│   │   │   ├── mutable.go              # Mutable state store
│   │   │   └── visibility.go           # Visibility store
│   │   ├── shard/
│   │   │   ├── controller.go           # Shard controller
│   │   │   ├── context.go              # Shard context
│   │   │   └── ownership.go            # Ownership management
│   │   ├── ndc/                         # N-DC replication
│   │   │   ├── replicator.go
│   │   │   ├── conflict.go
│   │   │   └── branch.go
│   │   └── archival/
│   │       ├── archiver.go
│   │       └── retriever.go
│   │
│   ├── matching/                        # Matching service
│   │   ├── service.go
│   │   ├── engine/
│   │   │   ├── engine.go
│   │   │   ├── task_queue.go           # Task queue manager
│   │   │   └── task_matcher.go         # Task matching logic
│   │   ├── handler/
│   │   │   ├── poll.go                 # Long polling
│   │   │   ├── add.go                  # Add tasks
│   │   │   └── complete.go             # Complete tasks
│   │   └── partition/
│   │       ├── manager.go
│   │       └── router.go
│   │
│   ├── worker/                          # Worker service
│   │   ├── service.go
│   │   ├── pool/
│   │   │   ├── manager.go              # Pool management
│   │   │   ├── dynamic.go              # Dynamic sizing
│   │   │   └── affinity.go             # Worker affinity
│   │   ├── executor/
│   │   │   ├── executor.go             # Task executor
│   │   │   ├── activity.go             # Activity execution
│   │   │   └── local.go                # Local activities
│   │   ├── isolation/
│   │   │   ├── sandbox.go              # Process sandbox
│   │   │   ├── wasm.go                 # WASM runtime
│   │   │   ├── container.go            # Container isolation
│   │   │   └── firecracker.go          # MicroVM
│   │   └── circuit/
│   │       ├── breaker.go
│   │       ├── bulkhead.go
│   │       └── timeout.go
│   │
│   ├── timer/                           # Timer service
│   │   ├── service.go
│   │   ├── queue/
│   │   │   ├── processor.go            # Timer processor
│   │   │   ├── scanner.go              # Timer scanner
│   │   │   └── executor.go             # Timer executor
│   │   └── store/
│   │       └── timer.go                # Timer storage
│   │
│   ├── nodes/                           # Node implementations
│   │   ├── registry/
│   │   │   ├── registry.go             # Node registry
│   │   │   ├── loader.go               # Dynamic loading
│   │   │   └── validator.go            # Schema validation
│   │   ├── interface.go                # Node interface
│   │   ├── context.go                  # Execution context
│   │   ├── result.go                   # Result types
│   │   │
│   │   ├── triggers/                    # Trigger nodes
│   │   │   ├── manual.go
│   │   │   ├── webhook.go
│   │   │   ├── schedule.go
│   │   │   └── event.go
│   │   │
│   │   ├── actions/                     # Action nodes
│   │   │   ├── http/
│   │   │   │   ├── request.go
│   │   │   │   ├── graphql.go
│   │   │   │   └── soap.go
│   │   │   ├── email/
│   │   │   │   ├── smtp.go
│   │   │   │   ├── sendgrid.go
│   │   │   │   └── ses.go
│   │   │   ├── messaging/
│   │   │   │   ├── slack.go
│   │   │   │   ├── discord.go
│   │   │   │   ├── telegram.go
│   │   │   │   └── teams.go
│   │   │   ├── database/
│   │   │   │   ├── postgres.go
│   │   │   │   ├── mysql.go
│   │   │   │   ├── mongodb.go
│   │   │   │   └── redis.go
│   │   │   ├── cloud/
│   │   │   │   ├── aws/
│   │   │   │   ├── gcp/
│   │   │   │   └── azure/
│   │   │   ├── ai/
│   │   │   │   ├── openai.go
│   │   │   │   ├── anthropic.go
│   │   │   │   └── huggingface.go
│   │   │   └── file/
│   │   │       ├── s3.go
│   │   │       ├── gcs.go
│   │   │       └── ftp.go
│   │   │
│   │   ├── logic/                       # Logic nodes
│   │   │   ├── condition.go            # If/else
│   │   │   ├── switch.go               # Switch/case
│   │   │   ├── loop.go                 # For each
│   │   │   ├── parallel.go             # Parallel execution
│   │   │   ├── wait.go                 # Wait for condition
│   │   │   └── merge.go                # Merge branches
│   │   │
│   │   └── transform/                   # Transform nodes
│   │       ├── set.go                  # Set variable
│   │       ├── code.go                 # Custom code
│   │       ├── template.go             # Template rendering
│   │       ├── json.go                 # JSON transform
│   │       └── xml.go                  # XML transform
│   │
│   ├── expression/                      # Expression engine
│   │   ├── engine/
│   │   │   ├── engine.go               # Main engine
│   │   │   ├── cel.go                  # CEL expressions
│   │   │   ├── jsonpath.go             # JSONPath
│   │   │   └── jmespath.go             # JMESPath
│   │   ├── parser/
│   │   │   ├── lexer.go
│   │   │   ├── parser.go
│   │   │   └── ast.go
│   │   ├── evaluator/
│   │   │   ├── evaluator.go
│   │   │   └── optimizer.go
│   │   ├── functions/
│   │   │   ├── stdlib.go               # Standard library
│   │   │   ├── string.go               # String functions
│   │   │   ├── math.go                 # Math functions
│   │   │   ├── date.go                 # Date functions
│   │   │   ├── json.go                 # JSON functions
│   │   │   ├── crypto.go               # Crypto functions
│   │   │   └── http.go                 # HTTP functions
│   │   └── sandbox/
│   │       ├── v8.go                   # V8 isolate
│   │       ├── quickjs.go              # QuickJS
│   │       └── wasm.go                 # WASM
│   │
│   ├── resolver/                        # Secret/variable resolution
│   │   ├── credential.go               # Credential decryption
│   │   ├── variable.go                 # Variable resolution
│   │   ├── secret/
│   │   │   ├── vault.go                # HashiCorp Vault
│   │   │   ├── aws_sm.go               # AWS Secrets Manager
│   │   │   └── gcp_sm.go               # GCP Secret Manager
│   │   └── cache.go                    # Resolution cache
│   │
│   ├── store/                           # Storage layer
│   │   ├── persistence/
│   │   │   ├── interface.go            # Storage interface
│   │   │   ├── postgres/
│   │   │   │   ├── store.go
│   │   │   │   ├── execution.go
│   │   │   │   ├── history.go
│   │   │   │   ├── visibility.go
│   │   │   │   └── queue.go
│   │   │   ├── cassandra/
│   │   │   │   └── store.go
│   │   │   └── tidb/
│   │   │       └── store.go
│   │   ├── cache/
│   │   │   ├── multilevel.go           # L1/L2/L3
│   │   │   ├── local.go                # In-process (ristretto)
│   │   │   └── distributed.go          # Redis cluster
│   │   ├── blob/
│   │   │   ├── interface.go
│   │   │   ├── s3.go
│   │   │   ├── gcs.go
│   │   │   └── azure.go
│   │   └── archival/
│   │       ├── archiver.go
│   │       ├── policy.go
│   │       └── retriever.go
│   │
│   ├── security/                        # Security layer
│   │   ├── authn/
│   │   │   ├── mtls.go                 # Mutual TLS
│   │   │   ├── jwt.go                  # JWT validation
│   │   │   └── oidc.go                 # OIDC
│   │   ├── authz/
│   │   │   ├── rbac.go                 # Role-based
│   │   │   ├── abac.go                 # Attribute-based
│   │   │   └── opa.go                  # OPA policies
│   │   ├── crypto/
│   │   │   ├── envelope.go             # Envelope encryption
│   │   │   ├── kms.go                  # KMS integration
│   │   │   ├── vault.go                # Vault transit
│   │   │   └── laravel.go              # Laravel-compatible
│   │   └── audit/
│   │       ├── logger.go
│   │       └── compliance.go
│   │
│   ├── observability/                   # Observability
│   │   ├── metrics/
│   │   │   ├── collector.go
│   │   │   ├── prometheus.go
│   │   │   └── otlp.go
│   │   ├── tracing/
│   │   │   ├── tracer.go
│   │   │   ├── propagation.go
│   │   │   └── sampling.go
│   │   ├── logging/
│   │   │   ├── structured.go
│   │   │   └── redaction.go
│   │   └── profiling/
│   │       ├── continuous.go
│   │       └── pprof.go
│   │
│   ├── resilience/                      # Resilience
│   │   ├── chaos/
│   │   │   ├── injector.go
│   │   │   └── scenarios.go
│   │   ├── healing/
│   │   │   ├── detector.go
│   │   │   └── remediation.go
│   │   └── draining/
│   │       ├── graceful.go
│   │       └── migration.go
│   │
│   └── edge/                            # Edge runtime
│       ├── runtime/
│       │   ├── engine.go
│       │   └── sync.go
│       └── wasm/
│           ├── runtime.go
│           └── modules.go
│
├── pkg/                                 # Public packages
│   ├── client/                          # Go SDK client
│   │   ├── client.go
│   │   ├── workflow.go
│   │   └── activity.go
│   ├── protocol/
│   │   ├── encoding.go
│   │   └── versioning.go
│   ├── clock/
│   │   ├── hybrid.go                   # Hybrid logical clock
│   │   └── vector.go                   # Vector clocks
│   ├── id/
│   │   ├── snowflake.go
│   │   └── uuid.go
│   ├── retry/
│   │   ├── policy.go
│   │   ├── backoff.go
│   │   └── jitter.go
│   ├── pool/
│   │   ├── object.go
│   │   ├── buffer.go
│   │   └── connection.go
│   └── compression/
│       ├── zstd.go
│       └── lz4.go
│
├── migrations/                          # Database migrations
│   ├── postgres/
│   │   ├── 0001_initial.up.sql
│   │   ├── 0001_initial.down.sql
│   │   └── ...
│   └── cassandra/
│       └── ...
│
├── configs/                             # Configuration
│   ├── base.yaml
│   ├── development.yaml
│   ├── staging.yaml
│   └── production.yaml
│
├── deploy/                              # Deployment
│   ├── docker/
│   │   ├── Dockerfile.frontend
│   │   ├── Dockerfile.history
│   │   ├── Dockerfile.matching
│   │   ├── Dockerfile.worker
│   │   └── docker-compose.yaml
│   ├── kubernetes/
│   │   ├── base/
│   │   ├── overlays/
│   │   └── operators/
│   ├── terraform/
│   │   ├── modules/
│   │   └── environments/
│   └── helm/
│       └── linkflow/
│
├── scripts/                             # Build/dev scripts
│   ├── build.sh
│   ├── test.sh
│   └── proto-gen.sh
│
├── tests/                               # Tests
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   ├── chaos/
│   └── performance/
│
├── docs/                                # Documentation
│   ├── architecture/
│   ├── api/
│   └── operations/
│
├── go.mod
├── go.sum
├── Makefile
└── README.md
```
---
## 5. Core Services
### 5.1 Frontend Service
The Frontend Service is the API gateway that handles all external requests.
**Responsibilities:**
- Request routing and load balancing
- Authentication and authorization
- Rate limiting and throttling
- Request validation
- Circuit breaking for downstream services
```go
// internal/frontend/service.go
package frontend
import (
    "context"
    
    apiv1 "github.com/linkflow/engine/api/proto/linkflow/api/v1"
)
type Service struct {
    historyClient  historyv1.HistoryServiceClient
    matchingClient matchingv1.MatchingServiceClient
    visibilityClient visibilityv1.VisibilityServiceClient
    
    rateLimiter    ratelimit.Limiter
    circuitBreaker circuit.Breaker
    metrics        *metrics.Collector
}
func NewService(cfg *Config) (*Service, error) {
    // Initialize clients with connection pooling
    historyConn, err := grpc.Dial(
        cfg.HistoryServiceAddress,
        grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
        grpc.WithDefaultCallOptions(
            grpc.MaxCallRecvMsgSize(maxMessageSize),
            grpc.MaxCallSendMsgSize(maxMessageSize),
        ),
        grpc.WithKeepaliveParams(keepalive.ClientParameters{
            Time:                10 * time.Second,
            Timeout:             3 * time.Second,
            PermitWithoutStream: true,
        }),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to connect to history service: %w", err)
    }
    
    return &Service{
        historyClient:  historyv1.NewHistoryServiceClient(historyConn),
        rateLimiter:    ratelimit.NewHierarchical(cfg.RateLimits),
        circuitBreaker: circuit.NewBreaker(cfg.CircuitBreaker),
        metrics:        metrics.NewCollector("frontend"),
    }, nil
}
// StartWorkflowExecution starts a new workflow execution
func (s *Service) StartWorkflowExecution(
    ctx context.Context,
    req *apiv1.StartWorkflowExecutionRequest,
) (*apiv1.StartWorkflowExecutionResponse, error) {
    // Rate limiting
    if err := s.rateLimiter.Allow(ctx, req.WorkspaceId); err != nil {
        return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
    }
    
    // Validate request
    if err := s.validateStartRequest(req); err != nil {
        return nil, status.Error(codes.InvalidArgument, err.Error())
    }
    
    // Generate execution ID
    executionID := id.NewExecutionID()
    
    // Record metrics
    s.metrics.ExecutionStarted(req.WorkspaceId, req.WorkflowId)
    
    // Forward to history service
    historyReq := &historyv1.StartWorkflowExecutionRequest{
        WorkspaceId:   req.WorkspaceId,
        WorkflowId:    req.WorkflowId,
        ExecutionId:   executionID,
        Input:         req.Input,
        IdempotencyKey: req.IdempotencyKey,
    }
    
    resp, err := s.historyClient.StartWorkflowExecution(ctx, historyReq)
    if err != nil {
        s.metrics.ExecutionStartFailed(req.WorkspaceId, req.WorkflowId)
        return nil, err
    }
    
    return &apiv1.StartWorkflowExecutionResponse{
        ExecutionId: resp.ExecutionId,
        RunId:       resp.RunId,
    }, nil
}
```
### 5.2 History Service
The History Service is the core of the execution engine, managing workflow state and history.
**Responsibilities:**
- Workflow state machine management
- Event history storage and replay
- Shard management and ownership
- Cross-region replication (NDC)
- Archival management
```go
// internal/history/service.go
package history
type Service struct {
    shardController *shard.Controller
    engine          *engine.Engine
    historyStore    store.HistoryStore
    executionStore  store.ExecutionStore
    
    eventSerializer serializer.Serializer
    metricsHandler  *metrics.Handler
}
func (s *Service) StartWorkflowExecution(
    ctx context.Context,
    req *historyv1.StartWorkflowExecutionRequest,
) (*historyv1.StartWorkflowExecutionResponse, error) {
    // Get shard for this execution
    shardID := s.shardController.GetShardID(req.WorkspaceId, req.ExecutionId)
    
    // Acquire shard lock
    shardCtx, err := s.shardController.AcquireShard(ctx, shardID)
    if err != nil {
        return nil, err
    }
    defer shardCtx.Release()
    
    // Check idempotency
    if existing, err := s.executionStore.GetByIdempotencyKey(
        ctx, req.WorkspaceId, req.IdempotencyKey,
    ); err == nil && existing != nil {
        return &historyv1.StartWorkflowExecutionResponse{
            ExecutionId: existing.ExecutionId,
            RunId:       existing.RunId,
            Started:     false, // Already existed
        }, nil
    }
    
    // Create execution state
    mutableState := engine.NewMutableState(req)
    
    // Build initial history events
    events := []*historyv1.HistoryEvent{
        s.buildWorkflowExecutionStartedEvent(req),
        s.buildDecisionTaskScheduledEvent(),
    }
    
    // Persist atomically
    if err := s.persistExecution(ctx, shardCtx, mutableState, events); err != nil {
        return nil, err
    }
    
    // Add decision task to matching service
    if err := s.addDecisionTask(ctx, mutableState); err != nil {
        // Execution persisted, task will be retried
        s.logger.Error("failed to add decision task", zap.Error(err))
    }
    
    return &historyv1.StartWorkflowExecutionResponse{
        ExecutionId: req.ExecutionId,
        RunId:       mutableState.RunId,
        Started:     true,
    }, nil
}
```
### 5.3 Matching Service
The Matching Service handles task queuing and worker matching.
**Responsibilities:**
- Task queue management
- Long polling for workers
- Task routing and prioritization
- Rate limiting per task queue
- Partition management
```go
// internal/matching/service.go
package matching
type Service struct {
    taskQueueManager *TaskQueueManager
    partitionManager *partition.Manager
    
    historyClient   historyv1.HistoryServiceClient
    metricsHandler  *metrics.Handler
}
// PollActivityTask handles long polling from workers
func (s *Service) PollActivityTask(
    ctx context.Context,
    req *matchingv1.PollActivityTaskRequest,
) (*matchingv1.PollActivityTaskResponse, error) {
    // Get partition for this task queue
    partitionID := s.partitionManager.GetPartition(
        req.WorkspaceId,
        req.TaskQueue,
        req.WorkerIdentity,
    )
    
    // Get or create task queue
    taskQueue := s.taskQueueManager.GetTaskQueue(
        req.WorkspaceId,
        req.TaskQueue,
        partitionID,
    )
    
    // Poll with timeout
    pollCtx, cancel := context.WithTimeout(ctx, req.PollTimeout.AsDuration())
    defer cancel()
    
    task, err := taskQueue.Poll(pollCtx, req.WorkerIdentity)
    if err != nil {
        if errors.Is(err, context.DeadlineExceeded) {
            // No task available, return empty response
            return &matchingv1.PollActivityTaskResponse{}, nil
        }
        return nil, err
    }
    
    // Record dispatch metrics
    s.metricsHandler.TaskDispatched(req.WorkspaceId, req.TaskQueue)
    
    return &matchingv1.PollActivityTaskResponse{
        TaskToken:      task.Token,
        ActivityId:     task.ActivityId,
        ActivityType:   task.ActivityType,
        Input:          task.Input,
        ScheduledTime:  task.ScheduledTime,
        StartedTime:    timestamppb.Now(),
        Attempt:        task.Attempt,
    }, nil
}
```
### 5.4 Worker Service
The Worker Service executes actual node activities.
**Responsibilities:**
- Node execution with isolation
- Retry and timeout handling
- Circuit breaking per integration
- Resource management
- Heartbeat management for long activities
```go
// internal/worker/service.go
package worker
type Service struct {
    poolManager     *pool.Manager
    nodeRegistry    *nodes.Registry
    credResolver    *resolver.CredentialResolver
    varResolver     *resolver.VariableResolver
    
    matchingClient  matchingv1.MatchingServiceClient
    historyClient   historyv1.HistoryServiceClient
    
    isolationMode   IsolationMode // process, container, wasm, firecracker
    metrics         *metrics.Collector
}
func (s *Service) Start(ctx context.Context) error {
    // Start worker pools for each node category
    pools := map[string]*pool.Config{
        "http":     {Workers: 50, Timeout: 30 * time.Second},
        "email":    {Workers: 20, Timeout: 60 * time.Second},
        "slack":    {Workers: 30, Timeout: 10 * time.Second},
        "database": {Workers: 10, Timeout: 120 * time.Second},
        "ai":       {Workers: 20, Timeout: 300 * time.Second},
        "code":     {Workers: 20, Timeout: 30 * time.Second},
    }
    
    g, ctx := errgroup.WithContext(ctx)
    
    for category, cfg := range pools {
        category, cfg := category, cfg
        g.Go(func() error {
            return s.runWorkerPool(ctx, category, cfg)
        })
    }
    
    return g.Wait()
}
func (s *Service) runWorkerPool(ctx context.Context, category string, cfg *pool.Config) error {
    for i := 0; i < cfg.Workers; i++ {
        go s.pollAndExecute(ctx, category, cfg.Timeout)
    }
    <-ctx.Done()
    return ctx.Err()
}
func (s *Service) pollAndExecute(ctx context.Context, category string, timeout time.Duration) {
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        
        // Poll for task
        task, err := s.matchingClient.PollActivityTask(ctx, &matchingv1.PollActivityTaskRequest{
            TaskQueue:      category,
            PollTimeout:    durationpb.New(30 * time.Second),
            WorkerIdentity: s.identity,
        })
        if err != nil || task.TaskToken == nil {
            continue
        }
        
        // Execute with timeout
        execCtx, cancel := context.WithTimeout(ctx, timeout)
        result, err := s.executeTask(execCtx, task)
        cancel()
        
        // Report result
        if err != nil {
            s.historyClient.RespondActivityTaskFailed(ctx, &historyv1.RespondActivityTaskFailedRequest{
                TaskToken: task.TaskToken,
                Failure:   convertError(err),
            })
        } else {
            s.historyClient.RespondActivityTaskCompleted(ctx, &historyv1.RespondActivityTaskCompletedRequest{
                TaskToken: task.TaskToken,
                Result:    result,
            })
        }
    }
}
func (s *Service) executeTask(ctx context.Context, task *matchingv1.PollActivityTaskResponse) ([]byte, error) {
    // Get node runner
    runner, err := s.nodeRegistry.GetRunner(task.ActivityType)
    if err != nil {
        return nil, fmt.Errorf("unknown node type: %s", task.ActivityType)
    }
    
    // Resolve credentials
    creds, err := s.credResolver.Resolve(ctx, task.CredentialIds)
    if err != nil {
        return nil, fmt.Errorf("failed to resolve credentials: %w", err)
    }
    
    // Build execution context
    nodeCtx := &nodes.Context{
        ExecutionID:  task.ExecutionId,
        NodeID:       task.ActivityId,
        Input:        task.Input,
        Credentials:  creds,
        Variables:    s.varResolver.GetAll(ctx, task.WorkspaceId),
        Attempt:      int(task.Attempt),
    }
    
    // Execute in sandbox if needed
    if s.requiresIsolation(task.ActivityType) {
        return s.executeIsolated(ctx, runner, nodeCtx)
    }
    
    return runner.Execute(ctx, nodeCtx)
}
```
---
## 6. History Service
### 6.1 Event Sourcing Model
All workflow state is derived from an append-only event log.
```go
// internal/history/events/types.go
package events
type EventType int32
const (
    EventTypeUnspecified EventType = iota
    
    // Workflow lifecycle
    EventTypeWorkflowExecutionStarted
    EventTypeWorkflowExecutionCompleted
    EventTypeWorkflowExecutionFailed
    EventTypeWorkflowExecutionTimedOut
    EventTypeWorkflowExecutionCanceled
    EventTypeWorkflowExecutionTerminated
    EventTypeWorkflowExecutionContinuedAsNew
    
    // Decision task lifecycle
    EventTypeDecisionTaskScheduled
    EventTypeDecisionTaskStarted
    EventTypeDecisionTaskCompleted
    EventTypeDecisionTaskTimedOut
    EventTypeDecisionTaskFailed
    
    // Activity lifecycle
    EventTypeActivityTaskScheduled
    EventTypeActivityTaskStarted
    EventTypeActivityTaskCompleted
    EventTypeActivityTaskFailed
    EventTypeActivityTaskTimedOut
    EventTypeActivityTaskCanceled
    
    // Timer lifecycle
    EventTypeTimerStarted
    EventTypeTimerFired
    EventTypeTimerCanceled
    
    // Child workflow lifecycle
    EventTypeChildWorkflowExecutionStarted
    EventTypeChildWorkflowExecutionCompleted
    EventTypeChildWorkflowExecutionFailed
    
    // Signals and queries
    EventTypeWorkflowExecutionSignaled
    EventTypeSignalExternalWorkflowExecutionInitiated
    
    // Markers
    EventTypeMarkerRecorded
)
type HistoryEvent struct {
    EventID    int64
    Timestamp  time.Time
    EventType  EventType
    Version    int64
    TaskID     int64
    Attributes interface{} // Type-specific attributes
}
// Activity scheduled attributes
type ActivityTaskScheduledEventAttributes struct {
    ActivityID             string
    ActivityType           string
    TaskQueue              string
    Input                  []byte
    ScheduleToCloseTimeout time.Duration
    ScheduleToStartTimeout time.Duration
    StartToCloseTimeout    time.Duration
    HeartbeatTimeout       time.Duration
    RetryPolicy            *RetryPolicy
    Header                 map[string][]byte
}
```
### 6.2 Mutable State
Mutable state is rebuilt from events and cached for performance.
```go
// internal/history/engine/state.go
package engine
type MutableState struct {
    // Execution info
    ExecutionInfo *ExecutionInfo
    ExecutionStats *ExecutionStats
    
    // Pending activities
    PendingActivityInfos map[int64]*ActivityInfo
    
    // Pending timers
    PendingTimerInfos map[string]*TimerInfo
    
    // Child workflows
    PendingChildExecutionInfos map[int64]*ChildExecutionInfo
    
    // Signals
    PendingSignalInfos map[int64]*SignalInfo
    
    // Buffered events (not yet persisted)
    BufferedEvents []*HistoryEvent
    
    // State tracking
    NextEventID       int64
    LastFirstEventID  int64
    LastProcessedEvent int64
    
    // Checksum for corruption detection
    Checksum uint64
}
func (ms *MutableState) ApplyEvent(event *HistoryEvent) error {
    switch event.EventType {
    case EventTypeActivityTaskScheduled:
        return ms.applyActivityScheduled(event)
    case EventTypeActivityTaskStarted:
        return ms.applyActivityStarted(event)
    case EventTypeActivityTaskCompleted:
        return ms.applyActivityCompleted(event)
    case EventTypeActivityTaskFailed:
        return ms.applyActivityFailed(event)
    // ... other event types
    }
    return nil
}
func (ms *MutableState) applyActivityScheduled(event *HistoryEvent) error {
    attrs := event.Attributes.(*ActivityTaskScheduledEventAttributes)
    
    ms.PendingActivityInfos[event.EventID] = &ActivityInfo{
        ScheduleID:     event.EventID,
        ActivityID:     attrs.ActivityID,
        ActivityType:   attrs.ActivityType,
        TaskQueue:      attrs.TaskQueue,
        Input:          attrs.Input,
        ScheduledTime:  event.Timestamp,
        Attempt:        1,
        RetryPolicy:    attrs.RetryPolicy,
        Status:         ActivityStatusScheduled,
    }
    
    return nil
}
```
### 6.3 Deterministic Replay
Replay workflow execution from history for debugging and recovery.
```go
// internal/history/replay/replayer.go
package replay
type Replayer struct {
    historyStore store.HistoryStore
    logger       *zap.Logger
}
type ReplayResult struct {
    MutableState *engine.MutableState
    Decisions    []*Decision
    Errors       []ReplayError
}
func (r *Replayer) Replay(
    ctx context.Context,
    executionID string,
    targetEventID int64,
) (*ReplayResult, error) {
    // Fetch history
    history, err := r.historyStore.ReadHistory(ctx, executionID, 1, targetEventID)
    if err != nil {
        return nil, fmt.Errorf("failed to read history: %w", err)
    }
    
    // Initialize mutable state
    ms := engine.NewMutableState(nil)
    result := &ReplayResult{
        MutableState: ms,
    }
    
    // Replay each event
    for _, event := range history.Events {
        if err := ms.ApplyEvent(event); err != nil {
            result.Errors = append(result.Errors, ReplayError{
                EventID: event.EventID,
                Error:   err,
            })
        }
        
        // Track decisions for comparison
        if event.EventType == EventTypeDecisionTaskCompleted {
            result.Decisions = append(result.Decisions, r.extractDecisions(event)...)
        }
    }
    
    return result, nil
}
// Shadow execution for testing changes
func (r *Replayer) ShadowReplay(
    ctx context.Context,
    executionID string,
    newWorkflowDef *Workflow,
) (*ShadowResult, error) {
    // Get original history
    original, err := r.Replay(ctx, executionID, math.MaxInt64)
    if err != nil {
        return nil, err
    }
    
    // Execute with new workflow definition
    shadow := engine.NewShadowEngine(newWorkflowDef)
    shadowResult, err := shadow.Execute(ctx, original.MutableState.ExecutionInfo.Input)
    if err != nil {
        return nil, err
    }
    
    // Compare results
    return &ShadowResult{
        Original:    original,
        Shadow:      shadowResult,
        Differences: r.compareMutableStates(original.MutableState, shadowResult.MutableState),
    }, nil
}
```
---
## 7. Execution Engine
### 7.1 DAG Graph Builder
Convert workflow definition to executable DAG.
```go
// internal/execution/graph/dag.go
package graph
type DAG struct {
    Nodes       map[string]*Node
    Edges       map[string][]string // source -> targets
    ReverseEdges map[string][]string // target -> sources
    
    EntryNodes  []string
    ExitNodes   []string
    
    // Topological ordering
    Order       []string
    Levels      map[string]int
}
type Node struct {
    ID         string
    Type       string
    Name       string
    Config     json.RawMessage
    Position   Position
    Conditions []Condition // Conditional edges
}
type Condition struct {
    TargetNode string
    Expression string // CEL expression
}
func BuildDAG(workflow *Workflow) (*DAG, error) {
    dag := &DAG{
        Nodes:        make(map[string]*Node),
        Edges:        make(map[string][]string),
        ReverseEdges: make(map[string][]string),
        Levels:       make(map[string]int),
    }
    
    // Add nodes
    for _, n := range workflow.Nodes {
        dag.Nodes[n.ID] = &Node{
            ID:     n.ID,
            Type:   n.Type,
            Name:   n.Data.Label,
            Config: n.Data.Config,
        }
    }
    
    // Add edges
    for _, e := range workflow.Edges {
        dag.Edges[e.Source] = append(dag.Edges[e.Source], e.Target)
        dag.ReverseEdges[e.Target] = append(dag.ReverseEdges[e.Target], e.Source)
    }
    
    // Find entry nodes (no incoming edges)
    for id := range dag.Nodes {
        if len(dag.ReverseEdges[id]) == 0 {
            dag.EntryNodes = append(dag.EntryNodes, id)
        }
    }
    
    // Find exit nodes (no outgoing edges)
    for id := range dag.Nodes {
        if len(dag.Edges[id]) == 0 {
            dag.ExitNodes = append(dag.ExitNodes, id)
        }
    }
    
    // Compute topological order
    if err := dag.computeTopologicalOrder(); err != nil {
        return nil, fmt.Errorf("invalid DAG: %w", err)
    }
    
    // Validate no cycles
    if err := dag.validateNoCycles(); err != nil {
        return nil, err
    }
    
    return dag, nil
}
func (d *DAG) computeTopologicalOrder() error {
    visited := make(map[string]bool)
    temp := make(map[string]bool)
    order := make([]string, 0, len(d.Nodes))
    
    var visit func(string) error
    visit = func(id string) error {
        if temp[id] {
            return errors.New("cycle detected")
        }
        if visited[id] {
            return nil
        }
        
        temp[id] = true
        
        for _, next := range d.Edges[id] {
            if err := visit(next); err != nil {
                return err
            }
        }
        
        delete(temp, id)
        visited[id] = true
        order = append([]string{id}, order...)
        
        return nil
    }
    
    for id := range d.Nodes {
        if !visited[id] {
            if err := visit(id); err != nil {
                return err
            }
        }
    }
    
    d.Order = order
    
    // Compute levels for parallel execution
    for _, id := range order {
        level := 0
        for _, prev := range d.ReverseEdges[id] {
            if d.Levels[prev] >= level {
                level = d.Levels[prev] + 1
            }
        }
        d.Levels[id] = level
    }
    
    return nil
}
// GetParallelNodes returns nodes that can execute in parallel
func (d *DAG) GetParallelNodes(level int) []string {
    var nodes []string
    for id, l := range d.Levels {
        if l == level {
            nodes = append(nodes, id)
        }
    }
    return nodes
}
// GetNextNodes returns nodes ready to execute given completed nodes
func (d *DAG) GetNextNodes(completed map[string]bool) []string {
    var ready []string
    
    for id := range d.Nodes {
        if completed[id] {
            continue
        }
        
        // Check if all dependencies are satisfied
        allDependenciesMet := true
        for _, dep := range d.ReverseEdges[id] {
            if !completed[dep] {
                allDependenciesMet = false
                break
            }
        }
        
        if allDependenciesMet {
            ready = append(ready, id)
        }
    }
    
    return ready
}
```
### 7.2 Execution Scheduler
Schedule and coordinate node execution.
```go
// internal/execution/scheduler/scheduler.go
package scheduler
type Scheduler struct {
    dag          *graph.DAG
    state        *ExecutionState
    nodeRunner   nodes.Runner
    
    taskQueue    chan *NodeTask
    resultQueue  chan *NodeResult
    errorQueue   chan *NodeError
    
    concurrency  int
    timeout      time.Duration
}
type ExecutionState struct {
    ExecutionID  string
    Status       ExecutionStatus
    
    NodeStates   map[string]*NodeState
    NodeOutputs  map[string]json.RawMessage
    
    CompletedNodes map[string]bool
    FailedNodes    map[string]*NodeError
    SkippedNodes   map[string]bool
    
    StartedAt    time.Time
    CompletedAt  time.Time
    
    mu sync.RWMutex
}
type NodeState struct {
    NodeID      string
    Status      NodeStatus
    StartedAt   time.Time
    CompletedAt time.Time
    Attempt     int
    Error       *NodeError
}
func (s *Scheduler) Execute(ctx context.Context, input json.RawMessage) (*ExecutionResult, error) {
    span, ctx := tracing.StartSpan(ctx, "scheduler.execute")
    defer span.End()
    
    // Initialize state
    s.state = &ExecutionState{
        ExecutionID:    id.NewExecutionID(),
        Status:         ExecutionStatusRunning,
        NodeStates:     make(map[string]*NodeState),
        NodeOutputs:    make(map[string]json.RawMessage),
        CompletedNodes: make(map[string]bool),
        FailedNodes:    make(map[string]*NodeError),
        SkippedNodes:   make(map[string]bool),
        StartedAt:      time.Now(),
    }
    
    // Store trigger data as entry node output
    for _, entryID := range s.dag.EntryNodes {
        s.state.NodeOutputs[entryID] = input
    }
    
    // Start worker pool
    var wg sync.WaitGroup
    for i := 0; i < s.concurrency; i++ {
        wg.Add(1)
        go s.worker(ctx, &wg)
    }
    
    // Schedule entry nodes
    for _, entryID := range s.dag.EntryNodes {
        s.scheduleNode(ctx, entryID, input)
    }
    
    // Process results until complete
    err := s.processUntilComplete(ctx)
    
    // Cleanup
    close(s.taskQueue)
    wg.Wait()
    
    s.state.CompletedAt = time.Now()
    
    if err != nil {
        s.state.Status = ExecutionStatusFailed
        return nil, err
    }
    
    s.state.Status = ExecutionStatusCompleted
    
    return &ExecutionResult{
        ExecutionID: s.state.ExecutionID,
        Status:      s.state.Status,
        Outputs:     s.collectOutputs(),
        Duration:    s.state.CompletedAt.Sub(s.state.StartedAt),
    }, nil
}
func (s *Scheduler) worker(ctx context.Context, wg *sync.WaitGroup) {
    defer wg.Done()
    
    for {
        select {
        case <-ctx.Done():
            return
            
        case task, ok := <-s.taskQueue:
            if !ok {
                return
            }
            
            result, err := s.executeNode(ctx, task)
            if err != nil {
                s.errorQueue <- &NodeError{
                    NodeID:  task.NodeID,
                    Error:   err,
                    Attempt: task.Attempt,
                }
            } else {
                s.resultQueue <- result
            }
        }
    }
}
func (s *Scheduler) processUntilComplete(ctx context.Context) error {
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
            
        case result := <-s.resultQueue:
            s.handleNodeCompleted(ctx, result)
            
            // Check if execution is complete
            if s.isExecutionComplete() {
                return nil
            }
            
        case nodeErr := <-s.errorQueue:
            if s.shouldRetry(nodeErr) {
                s.scheduleRetry(ctx, nodeErr)
            } else {
                return s.handleNodeFailed(nodeErr)
            }
        }
    }
}
func (s *Scheduler) handleNodeCompleted(ctx context.Context, result *NodeResult) {
    s.state.mu.Lock()
    defer s.state.mu.Unlock()
    
    // Update state
    s.state.CompletedNodes[result.NodeID] = true
    s.state.NodeOutputs[result.NodeID] = result.Output
    s.state.NodeStates[result.NodeID].Status = NodeStatusCompleted
    s.state.NodeStates[result.NodeID].CompletedAt = time.Now()
    
    // Find and schedule next nodes
    nextNodes := s.dag.GetNextNodes(s.state.CompletedNodes)
    
    for _, nextID := range nextNodes {
        // Check conditions
        if s.dag.Nodes[nextID].Conditions != nil {
            if !s.evaluateConditions(result.Output, s.dag.Nodes[nextID].Conditions) {
                s.state.SkippedNodes[nextID] = true
                s.state.CompletedNodes[nextID] = true // Mark as done for scheduling
                continue
            }
        }
        
        // Merge inputs from all upstream nodes
        input := s.mergeInputs(nextID)
        s.scheduleNode(ctx, nextID, input)
    }
}
func (s *Scheduler) mergeInputs(nodeID string) json.RawMessage {
    s.state.mu.RLock()
    defer s.state.mu.RUnlock()
    
    merged := make(map[string]json.RawMessage)
    
    for _, upstream := range s.dag.ReverseEdges[nodeID] {
        if output, ok := s.state.NodeOutputs[upstream]; ok {
            merged[upstream] = output
        }
    }
    
    result, _ := json.Marshal(merged)
    return result
}
```
---
## 8. Matching Service
### 8.1 Task Queue Implementation
```go
// internal/matching/engine/task_queue.go
package engine
type TaskQueue struct {
    name        string
    workspaceID int64
    partitionID int32
    
    // Tasks waiting to be dispatched
    tasks       *list.List
    tasksMap    map[string]*list.Element
    
    // Workers waiting for tasks
    pollers     *list.List
    
    // Rate limiting
    rateLimiter ratelimit.Limiter
    
    // Metrics
    metrics     *metrics.TaskQueueMetrics
    
    mu sync.Mutex
}
type Task struct {
    ID             string
    Token          []byte
    ActivityID     string
    ActivityType   string
    Input          []byte
    ScheduledTime  time.Time
    Attempt        int32
    
    // For ordering
    Priority       int32
    CreateTime     time.Time
}
func (tq *TaskQueue) AddTask(ctx context.Context, task *Task) error {
    tq.mu.Lock()
    defer tq.mu.Unlock()
    
    // Check rate limit
    if !tq.rateLimiter.Allow() {
        return ErrRateLimited
    }
    
    // Add to queue
    elem := tq.tasks.PushBack(task)
    tq.tasksMap[task.ID] = elem
    
    // Update metrics
    tq.metrics.TaskAdded()
    
    // Try to dispatch immediately if pollers waiting
    if tq.pollers.Len() > 0 {
        tq.tryDispatch()
    }
    
    return nil
}
func (tq *TaskQueue) Poll(ctx context.Context, identity string) (*Task, error) {
    tq.mu.Lock()
    
    // Try to get task immediately
    if tq.tasks.Len() > 0 {
        task := tq.dispatchNext()
        tq.mu.Unlock()
        return task, nil
    }
    
    // Register as poller
    poller := &Poller{
        Identity:  identity,
        ResultCh:  make(chan *Task, 1),
        CreatedAt: time.Now(),
    }
    elem := tq.pollers.PushBack(poller)
    tq.mu.Unlock()
    
    // Wait for task or timeout
    select {
    case <-ctx.Done():
        tq.removePoller(elem)
        return nil, ctx.Err()
    case task := <-poller.ResultCh:
        return task, nil
    }
}
func (tq *TaskQueue) tryDispatch() {
    for tq.tasks.Len() > 0 && tq.pollers.Len() > 0 {
        // Get oldest task
        taskElem := tq.tasks.Front()
        task := taskElem.Value.(*Task)
        
        // Get oldest poller
        pollerElem := tq.pollers.Front()
        poller := pollerElem.Value.(*Poller)
        
        // Remove from queues
        tq.tasks.Remove(taskElem)
        delete(tq.tasksMap, task.ID)
        tq.pollers.Remove(pollerElem)
        
        // Dispatch
        poller.ResultCh <- task
        
        // Metrics
        tq.metrics.TaskDispatched(time.Since(task.CreateTime))
    }
}
```
### 8.2 Partition Management
```go
// internal/matching/partition/manager.go
package partition
type Manager struct {
    numPartitions int32
    partitions    map[int32]*Partition
    
    // Consistent hashing for partition assignment
    hashRing     *hashring.Ring
    
    // Ownership tracking
    ownershipMgr *ownership.Manager
    
    mu sync.RWMutex
}
type Partition struct {
    ID           int32
    TaskQueues   map[string]*engine.TaskQueue
    
    // Load balancing
    Load         int64
    LastActive   time.Time
}
func (m *Manager) GetPartition(workspaceID int64, taskQueue string, workerID string) int32 {
    // Use consistent hashing
    key := fmt.Sprintf("%d:%s", workspaceID, taskQueue)
    return m.hashRing.GetPartition(key)
}
func (m *Manager) RebalancePartitions(ctx context.Context) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // Calculate load per partition
    loads := make(map[int32]int64)
    for id, p := range m.partitions {
        loads[id] = p.Load
    }
    
    // Find imbalanced partitions
    avgLoad := m.calculateAverageLoad(loads)
    
    for id, load := range loads {
        if float64(load) > float64(avgLoad)*1.5 {
            // This partition is overloaded, split some task queues
            m.splitPartition(ctx, id)
        } else if float64(load) < float64(avgLoad)*0.5 {
            // This partition is underloaded, merge with neighbor
            m.mergePartition(ctx, id)
        }
    }
    
    return nil
}
```
---
## 9. Worker Service
### 9.1 Process Isolation
```go
// internal/worker/isolation/sandbox.go
package isolation
type Sandbox interface {
    Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error)
    Cleanup() error
}
type ExecuteRequest struct {
    NodeType   string
    Config     json.RawMessage
    Input      json.RawMessage
    Timeout    time.Duration
    
    // Resource limits
    MaxMemory  int64
    MaxCPU     float64
}
type ExecuteResponse struct {
    Output    json.RawMessage
    Logs      []LogEntry
    Metrics   ExecutionMetrics
}
// Process sandbox using OS-level isolation
type ProcessSandbox struct {
    workDir    string
    binaryPath string
    
    // cgroups for resource limiting
    cgroupPath string
}
func (s *ProcessSandbox) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
    // Create cgroup for resource limiting
    cgroup, err := s.createCgroup(req.MaxMemory, req.MaxCPU)
    if err != nil {
        return nil, fmt.Errorf("failed to create cgroup: %w", err)
    }
    defer cgroup.Cleanup()
    
    // Prepare input file
    inputFile, err := s.writeInput(req)
    if err != nil {
        return nil, err
    }
    defer os.Remove(inputFile)
    
    // Execute in subprocess
    cmd := exec.CommandContext(ctx, s.binaryPath,
        "--type", req.NodeType,
        "--input", inputFile,
        "--config", string(req.Config),
    )
    
    // Set resource limits
    cmd.SysProcAttr = &syscall.SysProcAttr{
        Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID,
    }
    
    // Capture output
    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("execution failed: %w", err)
    }
    
    var response ExecuteResponse
    if err := json.Unmarshal(output, &response); err != nil {
        return nil, fmt.Errorf("invalid response: %w", err)
    }
    
    return &response, nil
}
```
### 9.2 WASM Runtime
```go
// internal/worker/isolation/wasm.go
package isolation
import (
    "github.com/tetratelabs/wazero"
    "github.com/tetratelabs/wazero/api"
)
type WASMSandbox struct {
    runtime wazero.Runtime
    cache   wazero.CompilationCache
    
    // Module pool for reuse
    modules sync.Pool
}
func NewWASMSandbox() (*WASMSandbox, error) {
    ctx := context.Background()
    
    // Create runtime with caching
    cache, err := wazero.NewCompilationCacheWithDir(".wasm-cache")
    if err != nil {
        return nil, err
    }
    
    runtime := wazero.NewRuntimeWithConfig(ctx,
        wazero.NewRuntimeConfig().
            WithCompilationCache(cache).
            WithMemoryLimitPages(256), // 16MB max
    )
    
    return &WASMSandbox{
        runtime: runtime,
        cache:   cache,
    }, nil
}
func (s *WASMSandbox) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
    // Load WASM module
    wasmBytes, err := s.loadModule(req.NodeType)
    if err != nil {
        return nil, err
    }
    
    // Compile module
    compiled, err := s.runtime.CompileModule(ctx, wasmBytes)
    if err != nil {
        return nil, fmt.Errorf("compilation failed: %w", err)
    }
    defer compiled.Close(ctx)
    
    // Instantiate with memory limits
    moduleConfig := wazero.NewModuleConfig().
        WithStartFunctions(). // Don't auto-start
        WithStdout(io.Discard).
        WithStderr(io.Discard)
    
    module, err := s.runtime.InstantiateModule(ctx, compiled, moduleConfig)
    if err != nil {
        return nil, fmt.Errorf("instantiation failed: %w", err)
    }
    defer module.Close(ctx)
    
    // Call execute function
    execute := module.ExportedFunction("execute")
    if execute == nil {
        return nil, errors.New("module missing execute function")
    }
    
    // Allocate input in WASM memory
    inputPtr, err := s.allocateInput(module, req.Input)
    if err != nil {
        return nil, err
    }
    
    // Execute with timeout
    results, err := execute.Call(ctx, inputPtr)
    if err != nil {
        return nil, fmt.Errorf("execution failed: %w", err)
    }
    
    // Read output from WASM memory
    output, err := s.readOutput(module, results[0])
    if err != nil {
        return nil, err
    }
    
    return &ExecuteResponse{
        Output: output,
    }, nil
}
```
### 9.3 Circuit Breaker
```go
// internal/worker/circuit/breaker.go
package circuit
type State int
const (
    StateClosed State = iota
    StateOpen
    StateHalfOpen
)
type Breaker struct {
    name          string
    state         State
    
    // Thresholds
    failureThreshold    int
    successThreshold    int
    halfOpenRequests    int
    
    // Timeouts
    openTimeout         time.Duration
    
    // Counters
    failures       int
    successes      int
    requests       int
    lastFailure    time.Time
    lastStateChange time.Time
    
    mu sync.RWMutex
}
func NewBreaker(name string, cfg *Config) *Breaker {
    return &Breaker{
        name:             name,
        state:            StateClosed,
        failureThreshold: cfg.FailureThreshold,
        successThreshold: cfg.SuccessThreshold,
        halfOpenRequests: cfg.HalfOpenRequests,
        openTimeout:      cfg.OpenTimeout,
    }
}
func (b *Breaker) Allow() bool {
    b.mu.Lock()
    defer b.mu.Unlock()
    
    switch b.state {
    case StateClosed:
        return true
        
    case StateOpen:
        // Check if we should transition to half-open
        if time.Since(b.lastStateChange) > b.openTimeout {
            b.transitionTo(StateHalfOpen)
            return true
        }
        return false
        
    case StateHalfOpen:
        // Allow limited requests
        if b.requests < b.halfOpenRequests {
            b.requests++
            return true
        }
        return false
    }
    
    return false
}
func (b *Breaker) RecordSuccess() {
    b.mu.Lock()
    defer b.mu.Unlock()
    
    switch b.state {
    case StateHalfOpen:
        b.successes++
        if b.successes >= b.successThreshold {
            b.transitionTo(StateClosed)
        }
    case StateClosed:
        b.failures = 0 // Reset consecutive failures
    }
}
func (b *Breaker) RecordFailure() {
    b.mu.Lock()
    defer b.mu.Unlock()
    
    b.failures++
    b.lastFailure = time.Now()
    
    switch b.state {
    case StateClosed:
        if b.failures >= b.failureThreshold {
            b.transitionTo(StateOpen)
        }
    case StateHalfOpen:
        b.transitionTo(StateOpen)
    }
}
func (b *Breaker) transitionTo(state State) {
    b.state = state
    b.lastStateChange = time.Now()
    b.failures = 0
    b.successes = 0
    b.requests = 0
}
```
---
## 10. Node SDK
### 10.1 Node Interface
```go
// internal/nodes/interface.go
package nodes
import (
    "context"
)
// Runner is the interface all nodes must implement
type Runner interface {
    // Type returns the node type identifier
    Type() string
    
    // Category returns the node category (http, email, database, etc.)
    Category() string
    
    // Execute runs the node with the given context
    Execute(ctx context.Context, execCtx *Context) (*Result, error)
    
    // Validate validates the node configuration
    Validate(config json.RawMessage) error
    
    // Schema returns the JSON schema for configuration
    Schema() *Schema
}
// Context provides execution context to nodes
type Context struct {
    // Execution info
    ExecutionID   string
    WorkflowID    int64
    WorkspaceID   int64
    NodeID        string
    
    // Input from previous nodes
    Input         json.RawMessage
    TriggerData   json.RawMessage
    
    // All node outputs (for expressions)
    NodeOutputs   map[string]json.RawMessage
    
    // Resolved credentials
    Credentials   map[string]map[string]string
    
    // Workspace variables
    Variables     map[string]string
    
    // Attempt info
    Attempt       int
    MaxAttempts   int
    
    // Services
    HTTPClient    *http.Client
    Logger        *zap.Logger
    Metrics       *metrics.Collector
    
    // Expression evaluator
    Evaluator     *expression.Evaluator
}
// Result represents node execution result
type Result struct {
    Output    json.RawMessage
    Metadata  map[string]string
    
    // For binary data (files, etc.)
    Binary    []byte
    MimeType  string
}
// Schema defines node configuration schema
type Schema struct {
    Type        string                 `json:"type"`
    Properties  map[string]*Property   `json:"properties"`
    Required    []string               `json:"required"`
}
type Property struct {
    Type        string      `json:"type"`
    Title       string      `json:"title"`
    Description string      `json:"description"`
    Default     interface{} `json:"default,omitempty"`
    Enum        []string    `json:"enum,omitempty"`
    Secret      bool        `json:"secret,omitempty"`
}
```
### 10.2 HTTP Request Node
```go
// internal/nodes/actions/http/request.go
package http
import (
    "bytes"
    "context"
    "encoding/json"
    "io"
    "net/http"
    "time"
    
    "github.com/linkflow/engine/internal/nodes"
)
type RequestRunner struct {
    client *http.Client
}
type Config struct {
    URL             string            `json:"url"`
    Method          string            `json:"method"`
    Headers         map[string]string `json:"headers"`
    QueryParams     map[string]string `json:"query_params"`
    BodyType        string            `json:"body_type"` // none, json, form, raw
    Body            json.RawMessage   `json:"body"`
    Timeout         int               `json:"timeout"` // seconds
    FollowRedirects bool              `json:"follow_redirects"`
    IgnoreSSL       bool              `json:"ignore_ssl"`
}
type Output struct {
    Status     int               `json:"status"`
    StatusText string            `json:"status_text"`
    Headers    map[string]string `json:"headers"`
    Body       interface{}       `json:"body"`
    DurationMs int64             `json:"duration_ms"`
}
func NewRequestRunner() *RequestRunner {
    return &RequestRunner{
        client: &http.Client{
            Timeout: 30 * time.Second,
            Transport: &http.Transport{
                MaxIdleConns:        100,
                MaxIdleConnsPerHost: 10,
                IdleConnTimeout:     90 * time.Second,
            },
        },
    }
}
func (r *RequestRunner) Type() string     { return "action_http_request" }
func (r *RequestRunner) Category() string { return "http" }
func (r *RequestRunner) Execute(ctx context.Context, execCtx *nodes.Context) (*nodes.Result, error) {
    // Parse config
    var cfg Config
    if err := json.Unmarshal(execCtx.Input, &cfg); err != nil {
        return nil, fmt.Errorf("invalid config: %w", err)
    }
    
    // Interpolate expressions in URL, headers, body
    url, err := execCtx.Evaluator.Interpolate(cfg.URL, execCtx.NodeOutputs)
    if err != nil {
        return nil, fmt.Errorf("invalid URL expression: %w", err)
    }
    
    headers := make(map[string]string)
    for k, v := range cfg.Headers {
        headers[k], _ = execCtx.Evaluator.Interpolate(v, execCtx.NodeOutputs)
    }
    
    // Build request
    var body io.Reader
    if cfg.BodyType == "json" {
        interpolatedBody, _ := execCtx.Evaluator.InterpolateJSON(cfg.Body, execCtx.NodeOutputs)
        body = bytes.NewReader(interpolatedBody)
        headers["Content-Type"] = "application/json"
    }
    
    req, err := http.NewRequestWithContext(ctx, cfg.Method, url, body)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    
    // Set headers
    for k, v := range headers {
        req.Header.Set(k, v)
    }
    
    // Inject credentials
    if creds, ok := execCtx.Credentials["http"]; ok {
        if token, ok := creds["bearer_token"]; ok {
            req.Header.Set("Authorization", "Bearer "+token)
        }
        if apiKey, ok := creds["api_key"]; ok {
            headerName := creds["header_name"]
            if headerName == "" {
                headerName = "X-API-Key"
            }
            req.Header.Set(headerName, apiKey)
        }
    }
    
    // Execute request
    start := time.Now()
    resp, err := r.client.Do(req)
    duration := time.Since(start)
    
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()
    
    // Read response
    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response: %w", err)
    }
    
    // Parse body based on content type
    var parsedBody interface{}
    contentType := resp.Header.Get("Content-Type")
    if strings.Contains(contentType, "application/json") {
        json.Unmarshal(respBody, &parsedBody)
    } else {
        parsedBody = string(respBody)
    }
    
    // Build output
    output := &Output{
        Status:     resp.StatusCode,
        StatusText: resp.Status,
        Headers:    r.flattenHeaders(resp.Header),
        Body:       parsedBody,
        DurationMs: duration.Milliseconds(),
    }
    
    // Record metrics
    execCtx.Metrics.HTTPRequestCompleted(url, cfg.Method, resp.StatusCode, duration)
    
    result, _ := json.Marshal(output)
    return &nodes.Result{Output: result}, nil
}
func (r *RequestRunner) Validate(config json.RawMessage) error {
    var cfg Config
    if err := json.Unmarshal(config, &cfg); err != nil {
        return err
    }
    
    if cfg.URL == "" {
        return errors.New("url is required")
    }
    
    validMethods := map[string]bool{
        "GET": true, "POST": true, "PUT": true, 
        "PATCH": true, "DELETE": true, "HEAD": true,
    }
    if !validMethods[cfg.Method] {
        return fmt.Errorf("invalid method: %s", cfg.Method)
    }
    
    return nil
}
func (r *RequestRunner) Schema() *nodes.Schema {
    return &nodes.Schema{
        Type: "object",
        Properties: map[string]*nodes.Property{
            "url": {
                Type:        "string",
                Title:       "URL",
                Description: "The request URL",
            },
            "method": {
                Type:    "string",
                Title:   "Method",
                Enum:    []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"},
                Default: "GET",
            },
            "headers": {
                Type:  "object",
                Title: "Headers",
            },
            "body": {
                Type:  "object",
                Title: "Request Body",
            },
            "timeout": {
                Type:    "integer",
                Title:   "Timeout (seconds)",
                Default: 30,
            },
        },
        Required: []string{"url", "method"},
    }
}
```
### 10.3 Node Registry
```go
// internal/nodes/registry/registry.go
package registry
import (
    "sync"
    
    "github.com/linkflow/engine/internal/nodes"
    "github.com/linkflow/engine/internal/nodes/actions/http"
    "github.com/linkflow/engine/internal/nodes/actions/email"
    // ... other imports
)
type Registry struct {
    runners  map[string]nodes.Runner
    mu       sync.RWMutex
}
func NewRegistry() *Registry {
    r := &Registry{
        runners: make(map[string]nodes.Runner),
    }
    
    // Register built-in nodes
    r.registerBuiltins()
    
    return r
}
func (r *Registry) registerBuiltins() {
    // Triggers
    r.Register(triggers.NewManualTrigger())
    r.Register(triggers.NewWebhookTrigger())
    r.Register(triggers.NewScheduleTrigger())
    
    // HTTP
    r.Register(http.NewRequestRunner())
    r.Register(http.NewGraphQLRunner())
    
    // Email
    r.Register(email.NewSMTPRunner())
    r.Register(email.NewSendGridRunner())
    
    // Messaging
    r.Register(messaging.NewSlackRunner())
    r.Register(messaging.NewDiscordRunner())
    r.Register(messaging.NewTelegramRunner())
    
    // Database
    r.Register(database.NewPostgresRunner())
    r.Register(database.NewMySQLRunner())
    r.Register(database.NewMongoDBRunner())
    r.Register(database.NewRedisRunner())
    
    // AI
    r.Register(ai.NewOpenAIRunner())
    r.Register(ai.NewAnthropicRunner())
    
    // Logic
    r.Register(logic.NewConditionRunner())
    r.Register(logic.NewSwitchRunner())
    r.Register(logic.NewLoopRunner())
    r.Register(logic.NewDelayRunner())
    
    // Transform
    r.Register(transform.NewSetRunner())
    r.Register(transform.NewCodeRunner())
    r.Register(transform.NewTemplateRunner())
}
func (r *Registry) Register(runner nodes.Runner) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.runners[runner.Type()] = runner
}
func (r *Registry) Get(nodeType string) (nodes.Runner, error) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    runner, ok := r.runners[nodeType]
    if !ok {
        return nil, fmt.Errorf("unknown node type: %s", nodeType)
    }
    return runner, nil
}
func (r *Registry) List() []nodes.Runner {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    list := make([]nodes.Runner, 0, len(r.runners))
    for _, runner := range r.runners {
        list = append(list, runner)
    }
    return list
}
func (r *Registry) ListByCategory(category string) []nodes.Runner {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    var list []nodes.Runner
    for _, runner := range r.runners {
        if runner.Category() == category {
            list = append(list, runner)
        }
    }
    return list
}
```
---
## 11. Expression Engine
### 11.1 Expression Evaluator
```go
// internal/expression/engine/engine.go
package engine
import (
    "github.com/google/cel-go/cel"
    "github.com/PaesslerAG/jsonpath"
)
type Engine struct {
    celEnv       *cel.Env
    functions    map[string]Function
    cache        *lru.Cache
    pool         *sync.Pool
}
type Function func(args ...interface{}) (interface{}, error)
func NewEngine() (*Engine, error) {
    // Create CEL environment with custom functions
    env, err := cel.NewEnv(
        cel.Variable("trigger", cel.DynType),
        cel.Variable("nodes", cel.MapType(cel.StringType, cel.DynType)),
        cel.Variable("env", cel.MapType(cel.StringType, cel.StringType)),
        cel.Variable("now", cel.TimestampType),
        
        // Custom functions
        cel.Function("json_parse",
            cel.Overload("json_parse_string",
                []*cel.Type{cel.StringType},
                cel.DynType,
            ),
        ),
        cel.Function("json_path",
            cel.Overload("json_path_any_string",
                []*cel.Type{cel.DynType, cel.StringType},
                cel.DynType,
            ),
        ),
        // ... more functions
    )
    if err != nil {
        return nil, err
    }
    
    return &Engine{
        celEnv:    env,
        functions: builtinFunctions(),
        cache:     lru.New(10000),
        pool: &sync.Pool{
            New: func() interface{} {
                return &evalContext{}
            },
        },
    }, nil
}
// Interpolate replaces {{expression}} with evaluated values
func (e *Engine) Interpolate(template string, data map[string]interface{}) (string, error) {
    // Fast path: no expressions
    if !strings.Contains(template, "{{") {
        return template, nil
    }
    
    // Check cache
    if cached, ok := e.cache.Get(template); ok {
        return e.executeCompiled(cached.(*compiledTemplate), data)
    }
    
    // Parse template
    compiled, err := e.compile(template)
    if err != nil {
        return "", err
    }
    
    e.cache.Add(template, compiled)
    
    return e.executeCompiled(compiled, data)
}
func (e *Engine) compile(template string) (*compiledTemplate, error) {
    compiled := &compiledTemplate{
        parts: make([]templatePart, 0),
    }
    
    scanner := newScanner(template)
    
    for scanner.Scan() {
        token := scanner.Token()
        
        switch token.Type {
        case tokenText:
            compiled.parts = append(compiled.parts, templatePart{
                isExpression: false,
                text:         token.Value,
            })
            
        case tokenExpression:
            // Compile CEL expression
            ast, issues := e.celEnv.Compile(token.Value)
            if issues != nil && issues.Err() != nil {
                return nil, fmt.Errorf("expression error: %w", issues.Err())
            }
            
            prg, err := e.celEnv.Program(ast)
            if err != nil {
                return nil, err
            }
            
            compiled.parts = append(compiled.parts, templatePart{
                isExpression: true,
                program:      prg,
            })
        }
    }
    
    return compiled, nil
}
func (e *Engine) executeCompiled(compiled *compiledTemplate, data map[string]interface{}) (string, error) {
    ctx := e.pool.Get().(*evalContext)
    defer e.pool.Put(ctx)
    
    ctx.reset()
    
    // Build activation
    activation := map[string]interface{}{
        "trigger": data["trigger"],
        "nodes":   data["nodes"],
        "env":     data["env"],
        "now":     time.Now(),
    }
    
    var result strings.Builder
    
    for _, part := range compiled.parts {
        if !part.isExpression {
            result.WriteString(part.text)
            continue
        }
        
        out, _, err := part.program.Eval(activation)
        if err != nil {
            return "", fmt.Errorf("evaluation error: %w", err)
        }
        
        result.WriteString(fmt.Sprintf("%v", out.Value()))
    }
    
    return result.String(), nil
}
// EvaluateCondition evaluates a boolean condition
func (e *Engine) EvaluateCondition(expression string, data map[string]interface{}) (bool, error) {
    ast, issues := e.celEnv.Compile(expression)
    if issues != nil && issues.Err() != nil {
        return false, issues.Err()
    }
    
    prg, err := e.celEnv.Program(ast)
    if err != nil {
        return false, err
    }
    
    activation := map[string]interface{}{
        "trigger": data["trigger"],
        "nodes":   data["nodes"],
        "env":     data["env"],
    }
    
    out, _, err := prg.Eval(activation)
    if err != nil {
        return false, err
    }
    
    result, ok := out.Value().(bool)
    if !ok {
        return false, errors.New("condition must return boolean")
    }
    
    return result, nil
}
```
### 11.2 Built-in Functions
```go
// internal/expression/functions/stdlib.go
package functions
func Stdlib() map[string]Function {
    return map[string]Function{
        // String functions
        "upper":      strings.ToUpper,
        "lower":      strings.ToLower,
        "trim":       strings.TrimSpace,
        "split":      strings.Split,
        "join":       strings.Join,
        "replace":    strings.ReplaceAll,
        "contains":   strings.Contains,
        "startsWith": strings.HasPrefix,
        "endsWith":   strings.HasSuffix,
        "substring":  substring,
        "length":     length,
        
        // Math functions
        "abs":     math.Abs,
        "ceil":    math.Ceil,
        "floor":   math.Floor,
        "round":   math.Round,
        "min":     min,
        "max":     max,
        "sum":     sum,
        "avg":     avg,
        
        // Date functions
        "now":         time.Now,
        "parseDate":   parseDate,
        "formatDate":  formatDate,
        "addDays":     addDays,
        "addHours":    addHours,
        "diffDays":    diffDays,
        
        // JSON functions
        "jsonParse":    jsonParse,
        "jsonPath":     jsonPath,
        "jsonStringify": jsonStringify,
        "get":          getPath,
        "set":          setPath,
        
        // Crypto functions
        "md5":          md5Hash,
        "sha256":       sha256Hash,
        "hmacSha256":   hmacSha256,
        "base64Encode": base64Encode,
        "base64Decode": base64Decode,
        "uuid":         uuid,
        
        // Array functions
        "first":   first,
        "last":    last,
        "filter":  filter,
        "map":     mapFunc,
        "reduce":  reduce,
        "flatten": flatten,
        "unique":  unique,
        "sort":    sortFunc,
        "reverse": reverse,
        
        // Type conversion
        "toString":  toString,
        "toInt":     toInt,
        "toFloat":   toFloat,
        "toBool":    toBool,
        "toArray":   toArray,
        
        // Utility
        "if":        ifFunc,
        "coalesce":  coalesce,
        "default":   defaultFunc,
        "isEmpty":   isEmpty,
        "isNull":    isNull,
        "typeof":    typeOf,
    }
}
func jsonPath(data interface{}, path string) (interface{}, error) {
    result, err := jsonpath.Get(path, data)
    if err != nil {
        return nil, fmt.Errorf("jsonpath error: %w", err)
    }
    return result, nil
}
func getPath(data interface{}, path string) (interface{}, error) {
    parts := strings.Split(path, ".")
    current := data
    
    for _, part := range parts {
        switch v := current.(type) {
        case map[string]interface{}:
            var ok bool
            current, ok = v[part]
            if !ok {
                return nil, nil
            }
        case []interface{}:
            idx, err := strconv.Atoi(part)
            if err != nil || idx < 0 || idx >= len(v) {
                return nil, nil
            }
            current = v[idx]
        default:
            return nil, nil
        }
    }
    
    return current, nil
}
```
---
## 12. Storage Layer
### 12.1 PostgreSQL Implementation
```go
// internal/store/persistence/postgres/execution.go
package postgres
import (
    "context"
    
    "github.com/jackc/pgx/v5/pgxpool"
)
type ExecutionStore struct {
    pool *pgxpool.Pool
}
func NewExecutionStore(pool *pgxpool.Pool) *ExecutionStore {
    return &ExecutionStore{pool: pool}
}
func (s *ExecutionStore) CreateExecution(ctx context.Context, exec *Execution) error {
    query := `
        INSERT INTO executions (
            execution_id, workflow_id, workspace_id, run_id,
            status, input, started_at, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `
    
    _, err := s.pool.Exec(ctx, query,
        exec.ExecutionID,
        exec.WorkflowID,
        exec.WorkspaceID,
        exec.RunID,
        exec.Status,
        exec.Input,
        exec.StartedAt,
        time.Now(),
    )
    
    return err
}
func (s *ExecutionStore) UpdateExecution(ctx context.Context, exec *Execution) error {
    query := `
        UPDATE executions
        SET status = $2,
            output = $3,
            error = $4,
            finished_at = $5,
            updated_at = NOW()
        WHERE execution_id = $1
    `
    
    _, err := s.pool.Exec(ctx, query,
        exec.ExecutionID,
        exec.Status,
        exec.Output,
        exec.Error,
        exec.FinishedAt,
    )
    
    return err
}
func (s *ExecutionStore) GetExecution(ctx context.Context, executionID string) (*Execution, error) {
    query := `
        SELECT 
            execution_id, workflow_id, workspace_id, run_id,
            status, input, output, error,
            started_at, finished_at, created_at, updated_at
        FROM executions
        WHERE execution_id = $1
    `
    
    var exec Execution
    err := s.pool.QueryRow(ctx, query, executionID).Scan(
        &exec.ExecutionID,
        &exec.WorkflowID,
        &exec.WorkspaceID,
        &exec.RunID,
        &exec.Status,
        &exec.Input,
        &exec.Output,
        &exec.Error,
        &exec.StartedAt,
        &exec.FinishedAt,
        &exec.CreatedAt,
        &exec.UpdatedAt,
    )
    
    if err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            return nil, ErrNotFound
        }
        return nil, err
    }
    
    return &exec, nil
}
// internal/store/persistence/postgres/history.go
type HistoryStore struct {
    pool *pgxpool.Pool
}
func (s *HistoryStore) AppendEvents(
    ctx context.Context,
    executionID string,
    events []*HistoryEvent,
) error {
    tx, err := s.pool.Begin(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback(ctx)
    
    // Batch insert events
    batch := &pgx.Batch{}
    
    for _, event := range events {
        batch.Queue(`
            INSERT INTO execution_events (
                execution_id, event_id, event_type, 
                node_id, data, version, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `,
            executionID,
            event.EventID,
            event.EventType,
            event.NodeID,
            event.Data,
            event.Version,
            event.Timestamp,
        )
    }
    
    results := tx.SendBatch(ctx, batch)
    defer results.Close()
    
    for range events {
        if _, err := results.Exec(); err != nil {
            return err
        }
    }
    
    return tx.Commit(ctx)
}
func (s *HistoryStore) ReadEvents(
    ctx context.Context,
    executionID string,
    minEventID, maxEventID int64,
    pageSize int,
) ([]*HistoryEvent, error) {
    query := `
        SELECT 
            event_id, event_type, node_id, 
            data, version, created_at
        FROM execution_events
        WHERE execution_id = $1
          AND event_id >= $2
          AND event_id <= $3
        ORDER BY event_id ASC
        LIMIT $4
    `
    
    rows, err := s.pool.Query(ctx, query, 
        executionID, minEventID, maxEventID, pageSize)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var events []*HistoryEvent
    for rows.Next() {
        var event HistoryEvent
        if err := rows.Scan(
            &event.EventID,
            &event.EventType,
            &event.NodeID,
            &event.Data,
            &event.Version,
            &event.Timestamp,
        ); err != nil {
            return nil, err
        }
        events = append(events, &event)
    }
    
    return events, nil
}
```
### 12.2 Multi-Level Cache
```go
// internal/store/cache/multilevel.go
package cache
import (
    "github.com/dgraph-io/ristretto"
    "github.com/redis/go-redis/v9"
)
type MultiLevelCache struct {
    l1 *ristretto.Cache  // In-process cache (fastest)
    l2 *redis.Client     // Distributed cache
    
    l1TTL time.Duration
    l2TTL time.Duration
    
    metrics *metrics.CacheMetrics
}
func NewMultiLevelCache(cfg *Config, redisClient *redis.Client) (*MultiLevelCache, error) {
    l1, err := ristretto.NewCache(&ristretto.Config{
        NumCounters: cfg.L1NumCounters,
        MaxCost:     cfg.L1MaxCost,
        BufferItems: 64,
    })
    if err != nil {
        return nil, err
    }
    
    return &MultiLevelCache{
        l1:    l1,
        l2:    redisClient,
        l1TTL: cfg.L1TTL,
        l2TTL: cfg.L2TTL,
    }, nil
}
func (c *MultiLevelCache) Get(ctx context.Context, key string) ([]byte, error) {
    // Try L1 first
    if value, found := c.l1.Get(key); found {
        c.metrics.L1Hit()
        return value.([]byte), nil
    }
    c.metrics.L1Miss()
    
    // Try L2
    value, err := c.l2.Get(ctx, key).Bytes()
    if err == nil {
        c.metrics.L2Hit()
        // Populate L1
        c.l1.SetWithTTL(key, value, int64(len(value)), c.l1TTL)
        return value, nil
    }
    
    if errors.Is(err, redis.Nil) {
        c.metrics.L2Miss()
        return nil, ErrNotFound
    }
    
    return nil, err
}
func (c *MultiLevelCache) Set(ctx context.Context, key string, value []byte) error {
    // Set in both levels
    c.l1.SetWithTTL(key, value, int64(len(value)), c.l1TTL)
    
    return c.l2.Set(ctx, key, value, c.l2TTL).Err()
}
func (c *MultiLevelCache) Delete(ctx context.Context, key string) error {
    c.l1.Del(key)
    return c.l2.Del(ctx, key).Err()
}
func (c *MultiLevelCache) GetOrSet(
    ctx context.Context,
    key string,
    loader func() ([]byte, error),
) ([]byte, error) {
    // Try cache first
    value, err := c.Get(ctx, key)
    if err == nil {
        return value, nil
    }
    if !errors.Is(err, ErrNotFound) {
        return nil, err
    }
    
    // Load from source
    value, err = loader()
    if err != nil {
        return nil, err
    }
    
    // Store in cache
    c.Set(ctx, key, value)
    
    return value, nil
}
```
---
## 13. Security
### 13.1 Laravel-Compatible Encryption
```go
// internal/security/crypto/laravel.go
package crypto
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
)
type LaravelEncryptor struct {
    key []byte
}
type encryptedPayload struct {
    IV    string `json:"iv"`
    Value string `json:"value"`
    MAC   string `json:"mac"`
}
func NewLaravelEncryptor(key string) (*LaravelEncryptor, error) {
    // Laravel stores key as base64
    decoded, err := base64.StdEncoding.DecodeString(
        strings.TrimPrefix(key, "base64:"),
    )
    if err != nil {
        return nil, fmt.Errorf("invalid key: %w", err)
    }
    
    return &LaravelEncryptor{key: decoded}, nil
}
func (e *LaravelEncryptor) Decrypt(encrypted string) ([]byte, error) {
    // Decode base64 payload
    payloadBytes, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return nil, err
    }
    
    // Parse JSON payload
    var payload encryptedPayload
    if err := json.Unmarshal(payloadBytes, &payload); err != nil {
        return nil, err
    }
    
    // Verify MAC
    if !e.verifyMAC(payload) {
        return nil, errors.New("invalid MAC")
    }
    
    // Decode IV and value
    iv, err := base64.StdEncoding.DecodeString(payload.IV)
    if err != nil {
        return nil, err
    }
    
    value, err := base64.StdEncoding.DecodeString(payload.Value)
    if err != nil {
        return nil, err
    }
    
    // Decrypt using AES-256-CBC
    block, err := aes.NewCipher(e.key)
    if err != nil {
        return nil, err
    }
    
    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(value, value)
    
    // Remove PKCS7 padding
    value = e.removePadding(value)
    
    // Laravel serializes with PHP serialize(), we need to unserialize
    return e.phpUnserialize(value)
}
func (e *LaravelEncryptor) verifyMAC(payload encryptedPayload) bool {
    // Calculate expected MAC
    mac := hmac.New(sha256.New, e.key)
    mac.Write([]byte(payload.IV + payload.Value))
    expected := hex.EncodeToString(mac.Sum(nil))
    
    return hmac.Equal([]byte(expected), []byte(payload.MAC))
}
func (e *LaravelEncryptor) removePadding(data []byte) []byte {
    if len(data) == 0 {
        return data
    }
    padding := int(data[len(data)-1])
    return data[:len(data)-padding]
}
func (e *LaravelEncryptor) phpUnserialize(data []byte) ([]byte, error) {
    // Simple PHP string unserialization
    // Format: s:length:"value";
    str := string(data)
    if strings.HasPrefix(str, "s:") {
        // Extract the string value
        parts := strings.SplitN(str, ":", 3)
        if len(parts) >= 3 {
            // Remove quotes and trailing semicolon
            value := parts[2]
            value = strings.TrimPrefix(value, "\"")
            value = strings.TrimSuffix(value, "\";")
            return []byte(value), nil
        }
    }
    return data, nil
}
```
### 13.2 Credential Resolver
```go
// internal/resolver/credential.go
package resolver
import (
    "context"
    
    "github.com/linkflow/engine/internal/security/crypto"
    "github.com/linkflow/engine/internal/store/cache"
)
type CredentialResolver struct {
    db        *pgxpool.Pool
    encryptor *crypto.LaravelEncryptor
    cache     *cache.MultiLevelCache
    
    cacheTTL  time.Duration
}
func NewCredentialResolver(
    db *pgxpool.Pool,
    appKey string,
    cache *cache.MultiLevelCache,
) (*CredentialResolver, error) {
    encryptor, err := crypto.NewLaravelEncryptor(appKey)
    if err != nil {
        return nil, err
    }
    
    return &CredentialResolver{
        db:        db,
        encryptor: encryptor,
        cache:     cache,
        cacheTTL:  5 * time.Minute,
    }, nil
}
func (r *CredentialResolver) Resolve(
    ctx context.Context,
    workspaceID int64,
    credentialIDs []int64,
) (map[int64]map[string]string, error) {
    result := make(map[int64]map[string]string)
    
    // Check cache first
    var missing []int64
    for _, id := range credentialIDs {
        key := fmt.Sprintf("cred:%d:%d", workspaceID, id)
        
        cached, err := r.cache.Get(ctx, key)
        if err == nil {
            var cred map[string]string
            json.Unmarshal(cached, &cred)
            result[id] = cred
        } else {
            missing = append(missing, id)
        }
    }
    
    if len(missing) == 0 {
        return result, nil
    }
    
    // Fetch missing from database
    query := `
        SELECT id, data
        FROM credentials
        WHERE workspace_id = $1 AND id = ANY($2) AND deleted_at IS NULL
    `
    
    rows, err := r.db.Query(ctx, query, workspaceID, missing)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    for rows.Next() {
        var id int64
        var encryptedData string
        
        if err := rows.Scan(&id, &encryptedData); err != nil {
            return nil, err
        }
        
        // Decrypt
        decrypted, err := r.encryptor.Decrypt(encryptedData)
        if err != nil {
            return nil, fmt.Errorf("failed to decrypt credential %d: %w", id, err)
        }
        
        var data map[string]string
        if err := json.Unmarshal(decrypted, &data); err != nil {
            return nil, err
        }
        
        result[id] = data
        
        // Cache for next time
        key := fmt.Sprintf("cred:%d:%d", workspaceID, id)
        cached, _ := json.Marshal(data)
        r.cache.Set(ctx, key, cached)
    }
    
    return result, nil
}
```
---
## 14. Observability
### 14.1 Metrics
```go
// internal/observability/metrics/collector.go
package metrics
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)
type Collector struct {
    // Execution metrics
    executionsTotal    *prometheus.CounterVec
    executionDuration  *prometheus.HistogramVec
    activeExecutions   *prometheus.GaugeVec
    
    // Node metrics
    nodeExecutionsTotal   *prometheus.CounterVec
    nodeExecutionDuration *prometheus.HistogramVec
    nodeErrors            *prometheus.CounterVec
    
    // Queue metrics
    queueDepth    *prometheus.GaugeVec
    queueLatency  *prometheus.HistogramVec
    
    // Worker metrics
    workerUtilization *prometheus.GaugeVec
    workerErrors      *prometheus.CounterVec
}
func NewCollector(namespace string) *Collector {
    return &Collector{
        executionsTotal: promauto.NewCounterVec(
            prometheus.CounterOpts{
                Namespace: namespace,
                Name:      "executions_total",
                Help:      "Total number of workflow executions",
            },
            []string{"workspace_id", "workflow_id", "status"},
        ),
        
        executionDuration: promauto.NewHistogramVec(
            prometheus.HistogramOpts{
                Namespace: namespace,
                Name:      "execution_duration_seconds",
                Help:      "Workflow execution duration in seconds",
                Buckets:   prometheus.ExponentialBuckets(0.001, 2, 20),
            },
            []string{"workspace_id", "workflow_id"},
        ),
        
        activeExecutions: promauto.NewGaugeVec(
            prometheus.GaugeOpts{
                Namespace: namespace,
                Name:      "active_executions",
                Help:      "Number of currently active executions",
            },
            []string{"workspace_id"},
        ),
        
        nodeExecutionsTotal: promauto.NewCounterVec(
            prometheus.CounterOpts{
                Namespace: namespace,
                Name:      "node_executions_total",
                Help:      "Total number of node executions",
            },
            []string{"node_type", "status"},
        ),
        
        nodeExecutionDuration: promauto.NewHistogramVec(
            prometheus.HistogramOpts{
                Namespace: namespace,
                Name:      "node_execution_duration_seconds",
                Help:      "Node execution duration in seconds",
                Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
            },
            []string{"node_type"},
        ),
        
        queueDepth: promauto.NewGaugeVec(
            prometheus.GaugeOpts{
                Namespace: namespace,
                Name:      "queue_depth",
                Help:      "Current queue depth",
            },
            []string{"queue_name"},
        ),
        
        queueLatency: promauto.NewHistogramVec(
            prometheus.HistogramOpts{
                Namespace: namespace,
                Name:      "queue_latency_seconds",
                Help:      "Time spent waiting in queue",
                Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
            },
            []string{"queue_name"},
        ),
    }
}
func (c *Collector) ExecutionStarted(workspaceID, workflowID int64) {
    c.activeExecutions.WithLabelValues(fmt.Sprint(workspaceID)).Inc()
}
func (c *Collector) ExecutionCompleted(workspaceID, workflowID int64, status string, duration time.Duration) {
    c.executionsTotal.WithLabelValues(
        fmt.Sprint(workspaceID),
        fmt.Sprint(workflowID),
        status,
    ).Inc()
    
    c.executionDuration.WithLabelValues(
        fmt.Sprint(workspaceID),
        fmt.Sprint(workflowID),
    ).Observe(duration.Seconds())
    
    c.activeExecutions.WithLabelValues(fmt.Sprint(workspaceID)).Dec()
}
func (c *Collector) NodeExecuted(nodeType, status string, duration time.Duration) {
    c.nodeExecutionsTotal.WithLabelValues(nodeType, status).Inc()
    c.nodeExecutionDuration.WithLabelValues(nodeType).Observe(duration.Seconds())
}
```
### 14.2 Distributed Tracing
```go
// internal/observability/tracing/tracer.go
package tracing
import (
    "context"
    
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/trace"
)
var tracer = otel.Tracer("linkflow-engine")
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (trace.Span, context.Context) {
    return tracer.Start(ctx, name, opts...)
}
func StartExecutionSpan(ctx context.Context, executionID string, workflowID int64) (trace.Span, context.Context) {
    return tracer.Start(ctx, "execution",
        trace.WithAttributes(
            attribute.String("execution.id", executionID),
            attribute.Int64("workflow.id", workflowID),
        ),
    )
}
func StartNodeSpan(ctx context.Context, nodeID, nodeType string) (trace.Span, context.Context) {
    return tracer.Start(ctx, "node.execute",
        trace.WithAttributes(
            attribute.String("node.id", nodeID),
            attribute.String("node.type", nodeType),
        ),
    )
}
func AddEvent(span trace.Span, name string, attrs ...attribute.KeyValue) {
    span.AddEvent(name, trace.WithAttributes(attrs...))
}
func RecordError(span trace.Span, err error) {
    span.RecordError(err)
    span.SetStatus(codes.Error, err.Error())
}
```
---
## 15. Resilience & Chaos
### 15.1 Chaos Injector
```go
// internal/resilience/chaos/injector.go
package chaos
import (
    "context"
    "math/rand"
    "time"
)
type Injector struct {
    enabled    bool
    scenarios  map[string]*Scenario
    
    mu sync.RWMutex
}
type Scenario struct {
    Name        string
    Type        ScenarioType
    Probability float64
    Duration    time.Duration
    Config      map[string]interface{}
    
    Active      bool
    ActivatedAt time.Time
}
type ScenarioType int
const (
    ScenarioLatency ScenarioType = iota
    ScenarioError
    ScenarioTimeout
    ScenarioPartition
    ScenarioResourceExhaustion
)
func NewInjector(enabled bool) *Injector {
    return &Injector{
        enabled:   enabled,
        scenarios: make(map[string]*Scenario),
    }
}
func (i *Injector) RegisterScenario(scenario *Scenario) {
    i.mu.Lock()
    defer i.mu.Unlock()
    i.scenarios[scenario.Name] = scenario
}
func (i *Injector) MaybeInject(ctx context.Context, point string) error {
    if !i.enabled {
        return nil
    }
    
    i.mu.RLock()
    defer i.mu.RUnlock()
    
    for _, scenario := range i.scenarios {
        if !scenario.Active {
            continue
        }
        
        if rand.Float64() > scenario.Probability {
            continue
        }
        
        switch scenario.Type {
        case ScenarioLatency:
            delay := scenario.Config["delay"].(time.Duration)
            select {
            case <-time.After(delay):
            case <-ctx.Done():
                return ctx.Err()
            }
            
        case ScenarioError:
            return fmt.Errorf("chaos: injected error at %s", point)
            
        case ScenarioTimeout:
            <-ctx.Done()
            return context.DeadlineExceeded
        }
    }
    
    return nil
}
func (i *Injector) ActivateScenario(name string, duration time.Duration) error {
    i.mu.Lock()
    defer i.mu.Unlock()
    
    scenario, ok := i.scenarios[name]
    if !ok {
        return fmt.Errorf("scenario not found: %s", name)
    }
    
    scenario.Active = true
    scenario.ActivatedAt = time.Now()
    
    // Auto-deactivate after duration
    go func() {
        time.Sleep(duration)
        i.DeactivateScenario(name)
    }()
    
    return nil
}
func (i *Injector) DeactivateScenario(name string) {
    i.mu.Lock()
    defer i.mu.Unlock()
    
    if scenario, ok := i.scenarios[name]; ok {
        scenario.Active = false
    }
}
```
---
## 16. Edge Execution
### 16.1 Edge Runtime
```go
// internal/edge/runtime/engine.go
package runtime
import (
    "context"
    "sync"
    
    "github.com/linkflow/engine/internal/nodes"
    "github.com/linkflow/engine/internal/store/cache"
)
type EdgeEngine struct {
    cellID      string
    location    string
    
    nodeRegistry *nodes.Registry
    localCache   *cache.LocalCache
    
    // Sync with control plane
    syncClient   SyncClient
    syncInterval time.Duration
    
    // Offline buffer
    offlineQueue *OfflineQueue
    
    // Metrics and health
    metrics      *metrics.Collector
    health       *health.Checker
    
    mu sync.RWMutex
}

func NewEdgeEngine(cfg *EdgeConfig) (*EdgeEngine, error) {
    nodeRegistry := nodes.NewRegistry()
    localCache, err := cache.NewLocalCache(cfg.CacheSize)
    if err != nil {
        return nil, fmt.Errorf("failed to create local cache: %w", err)
    }
    
    syncClient, err := NewSyncClient(cfg.ControlPlaneURL)
    if err != nil {
        return nil, fmt.Errorf("failed to create sync client: %w", err)
    }
    
    return &EdgeEngine{
        cellID:       cfg.CellID,
        location:     cfg.Location,
        nodeRegistry: nodeRegistry,
        localCache:   localCache,
        syncClient:   syncClient,
        syncInterval: cfg.SyncInterval,
        offlineQueue: NewOfflineQueue(cfg.OfflineQueueSize),
        metrics:      metrics.NewCollector("edge"),
        health:       health.NewChecker(),
    }, nil
}

func (e *EdgeEngine) Start(ctx context.Context) error {
    g, ctx := errgroup.WithContext(ctx)
    
    // Start background sync
    g.Go(func() error {
        return e.runSync(ctx)
    })
    
    // Start offline queue processor
    g.Go(func() error {
        return e.processOfflineQueue(ctx)
    })
    
    // Start health checks
    g.Go(func() error {
        return e.runHealthChecks(ctx)
    })
    
    return g.Wait()
}

func (e *EdgeEngine) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
    span, ctx := tracing.StartSpan(ctx, "edge.execute")
    defer span.End()
    
    // Check if workflow is cached
    workflow, err := e.getWorkflow(ctx, req.WorkflowID)
    if err != nil {
        return nil, fmt.Errorf("failed to get workflow: %w", err)
    }
    
    // Execute locally
    result, err := e.executeWorkflow(ctx, workflow, req.Input)
    if err != nil {
        // If offline, queue for later sync
        if e.isOffline() {
            e.offlineQueue.Enqueue(&QueuedExecution{
                Request:   req,
                Timestamp: time.Now(),
            })
            return nil, ErrQueued
        }
        return nil, err
    }
    
    // Sync result to control plane
    if err := e.syncResult(ctx, result); err != nil {
        // Queue for later if sync fails
        e.offlineQueue.EnqueueResult(result)
    }
    
    return result, nil
}

func (e *EdgeEngine) runSync(ctx context.Context) error {
    ticker := time.NewTicker(e.syncInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-ticker.C:
            if err := e.syncWithControlPlane(ctx); err != nil {
                e.metrics.SyncFailed()
                continue
            }
            e.metrics.SyncSucceeded()
        }
    }
}

func (e *EdgeEngine) syncWithControlPlane(ctx context.Context) error {
    e.mu.Lock()
    defer e.mu.Unlock()
    
    // Fetch updated workflows
    updates, err := e.syncClient.FetchUpdates(ctx, e.cellID)
    if err != nil {
        return err
    }
    
    // Update local cache
    for _, workflow := range updates.Workflows {
        e.localCache.Set(workflow.ID, workflow)
    }
    
    // Push pending results
    pending := e.offlineQueue.DrainResults()
    for _, result := range pending {
        if err := e.syncClient.PushResult(ctx, result); err != nil {
            // Re-queue if push fails
            e.offlineQueue.EnqueueResult(result)
        }
    }
    
    return nil
}
```

### 16.2 Offline Queue
```go
// internal/edge/runtime/offline.go
package runtime

type OfflineQueue struct {
    executions *list.List
    results    *list.List
    maxSize    int
    
    persistPath string
    
    mu sync.Mutex
}

type QueuedExecution struct {
    Request   *ExecuteRequest
    Timestamp time.Time
    Attempts  int
}

type QueuedResult struct {
    Result    *ExecuteResponse
    Timestamp time.Time
    Attempts  int
}

func NewOfflineQueue(maxSize int) *OfflineQueue {
    q := &OfflineQueue{
        executions: list.New(),
        results:    list.New(),
        maxSize:    maxSize,
    }
    
    // Restore from disk if persisted
    q.restore()
    
    return q
}

func (q *OfflineQueue) Enqueue(exec *QueuedExecution) error {
    q.mu.Lock()
    defer q.mu.Unlock()
    
    if q.executions.Len() >= q.maxSize {
        // Remove oldest
        q.executions.Remove(q.executions.Front())
    }
    
    q.executions.PushBack(exec)
    q.persist()
    
    return nil
}

func (q *OfflineQueue) EnqueueResult(result *ExecuteResponse) error {
    q.mu.Lock()
    defer q.mu.Unlock()
    
    q.results.PushBack(&QueuedResult{
        Result:    result,
        Timestamp: time.Now(),
    })
    q.persist()
    
    return nil
}

func (q *OfflineQueue) DrainResults() []*ExecuteResponse {
    q.mu.Lock()
    defer q.mu.Unlock()
    
    results := make([]*ExecuteResponse, 0, q.results.Len())
    for e := q.results.Front(); e != nil; e = e.Next() {
        queued := e.Value.(*QueuedResult)
        results = append(results, queued.Result)
    }
    
    q.results.Init()
    q.persist()
    
    return results
}

func (q *OfflineQueue) persist() {
    if q.persistPath == "" {
        return
    }
    
    data, _ := json.Marshal(struct {
        Executions []*QueuedExecution
        Results    []*QueuedResult
    }{
        Executions: q.listToSlice(q.executions),
        Results:    q.resultsToSlice(q.results),
    })
    
    os.WriteFile(q.persistPath, data, 0644)
}

func (q *OfflineQueue) restore() {
    if q.persistPath == "" {
        return
    }
    
    data, err := os.ReadFile(q.persistPath)
    if err != nil {
        return
    }
    
    var stored struct {
        Executions []*QueuedExecution
        Results    []*QueuedResult
    }
    
    if err := json.Unmarshal(data, &stored); err != nil {
        return
    }
    
    for _, exec := range stored.Executions {
        q.executions.PushBack(exec)
    }
    for _, result := range stored.Results {
        q.results.PushBack(result)
    }
}
```

### 16.3 WASM Edge Runtime
```go
// internal/edge/wasm/runtime.go
package wasm

import (
    "context"
    
    "github.com/tetratelabs/wazero"
)

type EdgeRuntime struct {
    runtime wazero.Runtime
    modules map[string]wazero.CompiledModule
    
    mu sync.RWMutex
}

func NewEdgeRuntime() (*EdgeRuntime, error) {
    ctx := context.Background()
    
    runtime := wazero.NewRuntimeWithConfig(ctx,
        wazero.NewRuntimeConfig().
            WithMemoryLimitPages(64). // 4MB per module
            WithCloseOnContextDone(true),
    )
    
    return &EdgeRuntime{
        runtime: runtime,
        modules: make(map[string]wazero.CompiledModule),
    }, nil
}

func (r *EdgeRuntime) LoadModule(ctx context.Context, name string, wasmBytes []byte) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    compiled, err := r.runtime.CompileModule(ctx, wasmBytes)
    if err != nil {
        return fmt.Errorf("failed to compile module %s: %w", name, err)
    }
    
    r.modules[name] = compiled
    return nil
}

func (r *EdgeRuntime) Execute(ctx context.Context, moduleName string, input []byte) ([]byte, error) {
    r.mu.RLock()
    compiled, ok := r.modules[moduleName]
    r.mu.RUnlock()
    
    if !ok {
        return nil, fmt.Errorf("module not found: %s", moduleName)
    }
    
    // Instantiate with memory isolation
    module, err := r.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
    if err != nil {
        return nil, err
    }
    defer module.Close(ctx)
    
    // Call execute function
    execute := module.ExportedFunction("execute")
    if execute == nil {
        return nil, errors.New("module missing execute function")
    }
    
    // Allocate input in WASM memory
    malloc := module.ExportedFunction("malloc")
    if malloc == nil {
        return nil, errors.New("module missing malloc function")
    }
    
    results, err := malloc.Call(ctx, uint64(len(input)))
    if err != nil {
        return nil, err
    }
    inputPtr := uint32(results[0])
    
    // Write input to memory
    if !module.Memory().Write(inputPtr, input) {
        return nil, errors.New("failed to write input to memory")
    }
    
    // Execute
    execResults, err := execute.Call(ctx, uint64(inputPtr), uint64(len(input)))
    if err != nil {
        return nil, err
    }
    
    // Read output
    outputPtr := uint32(execResults[0])
    outputLen := uint32(execResults[1])
    
    output, ok := module.Memory().Read(outputPtr, outputLen)
    if !ok {
        return nil, errors.New("failed to read output from memory")
    }
    
    return output, nil
}
```
---
## 17. Database Schema
### 17.1 Execution Tables
```sql
-- migrations/postgres/0001_initial.up.sql

-- Executions table
CREATE TABLE executions (
    execution_id    VARCHAR(64) PRIMARY KEY,
    workflow_id     BIGINT NOT NULL,
    workspace_id    BIGINT NOT NULL,
    run_id          VARCHAR(64) NOT NULL,
    
    status          VARCHAR(32) NOT NULL DEFAULT 'pending',
    input           JSONB,
    output          JSONB,
    error           TEXT,
    
    started_at      TIMESTAMP WITH TIME ZONE,
    finished_at     TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    CONSTRAINT fk_workflow FOREIGN KEY (workflow_id) REFERENCES workflows(id),
    CONSTRAINT fk_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX idx_executions_workspace ON executions(workspace_id);
CREATE INDEX idx_executions_workflow ON executions(workflow_id);
CREATE INDEX idx_executions_status ON executions(status);
CREATE INDEX idx_executions_started_at ON executions(started_at DESC);
CREATE INDEX idx_executions_workspace_status ON executions(workspace_id, status);

-- Execution events (history)
CREATE TABLE execution_events (
    id              BIGSERIAL PRIMARY KEY,
    execution_id    VARCHAR(64) NOT NULL,
    event_id        BIGINT NOT NULL,
    event_type      VARCHAR(64) NOT NULL,
    
    node_id         VARCHAR(64),
    data            JSONB,
    version         BIGINT DEFAULT 1,
    
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_execution FOREIGN KEY (execution_id) REFERENCES executions(execution_id),
    CONSTRAINT unique_execution_event UNIQUE (execution_id, event_id)
);

CREATE INDEX idx_events_execution ON execution_events(execution_id);
CREATE INDEX idx_events_execution_type ON execution_events(execution_id, event_type);

-- Node executions
CREATE TABLE node_executions (
    id              BIGSERIAL PRIMARY KEY,
    execution_id    VARCHAR(64) NOT NULL,
    node_id         VARCHAR(64) NOT NULL,
    
    status          VARCHAR(32) NOT NULL DEFAULT 'pending',
    input           JSONB,
    output          JSONB,
    error           TEXT,
    attempts        INT DEFAULT 0,
    
    scheduled_at    TIMESTAMP WITH TIME ZONE,
    started_at      TIMESTAMP WITH TIME ZONE,
    finished_at     TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_execution FOREIGN KEY (execution_id) REFERENCES executions(execution_id),
    CONSTRAINT unique_node_execution UNIQUE (execution_id, node_id)
);

CREATE INDEX idx_node_exec_execution ON node_executions(execution_id);
CREATE INDEX idx_node_exec_status ON node_executions(status);
```

### 17.2 Task Queue Tables
```sql
-- Task queue tables
CREATE TABLE task_queues (
    id              BIGSERIAL PRIMARY KEY,
    workspace_id    BIGINT NOT NULL,
    name            VARCHAR(255) NOT NULL,
    partition_id    INT NOT NULL DEFAULT 0,
    
    task_count      BIGINT DEFAULT 0,
    poller_count    INT DEFAULT 0,
    last_poll_at    TIMESTAMP WITH TIME ZONE,
    
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT unique_queue UNIQUE (workspace_id, name, partition_id)
);

CREATE INDEX idx_task_queues_workspace ON task_queues(workspace_id);

-- Pending tasks
CREATE TABLE tasks (
    id              BIGSERIAL PRIMARY KEY,
    task_id         VARCHAR(64) NOT NULL UNIQUE,
    queue_id        BIGINT NOT NULL,
    
    execution_id    VARCHAR(64) NOT NULL,
    activity_id     VARCHAR(64) NOT NULL,
    activity_type   VARCHAR(255) NOT NULL,
    
    input           JSONB,
    priority        INT DEFAULT 0,
    attempt         INT DEFAULT 1,
    
    scheduled_at    TIMESTAMP WITH TIME ZONE NOT NULL,
    expire_at       TIMESTAMP WITH TIME ZONE,
    
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_queue FOREIGN KEY (queue_id) REFERENCES task_queues(id)
);

CREATE INDEX idx_tasks_queue ON tasks(queue_id);
CREATE INDEX idx_tasks_scheduled ON tasks(queue_id, scheduled_at);
CREATE INDEX idx_tasks_priority ON tasks(queue_id, priority DESC, scheduled_at);
```

### 17.3 Timer Tables
```sql
-- Timers for delayed execution
CREATE TABLE timers (
    id              BIGSERIAL PRIMARY KEY,
    timer_id        VARCHAR(64) NOT NULL UNIQUE,
    
    execution_id    VARCHAR(64) NOT NULL,
    node_id         VARCHAR(64),
    timer_type      VARCHAR(32) NOT NULL, -- delay, schedule, deadline
    
    fire_at         TIMESTAMP WITH TIME ZONE NOT NULL,
    fired           BOOLEAN DEFAULT FALSE,
    
    data            JSONB,
    
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_execution FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
);

CREATE INDEX idx_timers_fire_at ON timers(fire_at) WHERE NOT fired;
CREATE INDEX idx_timers_execution ON timers(execution_id);

-- Shard ownership for distributed coordination
CREATE TABLE shard_ownership (
    shard_id        INT PRIMARY KEY,
    owner_id        VARCHAR(255) NOT NULL,
    
    acquired_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    heartbeat_at    TIMESTAMP WITH TIME ZONE NOT NULL,
    
    steal_token     VARCHAR(64)
);

CREATE INDEX idx_shard_owner ON shard_ownership(owner_id);
```

### 17.4 Visibility Tables
```sql
-- Visibility for search and query
CREATE TABLE execution_visibility (
    execution_id    VARCHAR(64) PRIMARY KEY,
    workflow_id     BIGINT NOT NULL,
    workspace_id    BIGINT NOT NULL,
    
    workflow_name   VARCHAR(255),
    status          VARCHAR(32) NOT NULL,
    
    start_time      TIMESTAMP WITH TIME ZONE,
    close_time      TIMESTAMP WITH TIME ZONE,
    execution_time  BIGINT, -- duration in milliseconds
    
    -- Searchable attributes
    search_attrs    JSONB,
    
    -- Memo for user-defined data
    memo            JSONB,
    
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_visibility_workspace ON execution_visibility(workspace_id);
CREATE INDEX idx_visibility_status ON execution_visibility(workspace_id, status);
CREATE INDEX idx_visibility_start_time ON execution_visibility(workspace_id, start_time DESC);
CREATE INDEX idx_visibility_workflow ON execution_visibility(workspace_id, workflow_id);
CREATE INDEX idx_visibility_search ON execution_visibility USING GIN (search_attrs);
```
---
## 18. Message Formats
### 18.1 Execution Messages
```protobuf
// api/proto/linkflow/api/v1/execution.proto
syntax = "proto3";

package linkflow.api.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/any.proto";

message StartWorkflowExecutionRequest {
    int64 workspace_id = 1;
    int64 workflow_id = 2;
    string execution_id = 3;
    bytes input = 4;
    string idempotency_key = 5;
    
    // Optional overrides
    ExecutionOptions options = 6;
}

message ExecutionOptions {
    int32 timeout_seconds = 1;
    RetryPolicy retry_policy = 2;
    map<string, string> search_attributes = 3;
    bytes memo = 4;
}

message StartWorkflowExecutionResponse {
    string execution_id = 1;
    string run_id = 2;
    bool started = 3; // false if already existed (idempotent)
}

message GetExecutionRequest {
    string execution_id = 1;
}

message GetExecutionResponse {
    ExecutionInfo execution = 1;
    repeated NodeExecutionInfo nodes = 2;
}

message ExecutionInfo {
    string execution_id = 1;
    int64 workflow_id = 2;
    int64 workspace_id = 3;
    string run_id = 4;
    
    ExecutionStatus status = 5;
    bytes input = 6;
    bytes output = 7;
    string error = 8;
    
    google.protobuf.Timestamp started_at = 9;
    google.protobuf.Timestamp finished_at = 10;
}

enum ExecutionStatus {
    EXECUTION_STATUS_UNSPECIFIED = 0;
    EXECUTION_STATUS_PENDING = 1;
    EXECUTION_STATUS_RUNNING = 2;
    EXECUTION_STATUS_COMPLETED = 3;
    EXECUTION_STATUS_FAILED = 4;
    EXECUTION_STATUS_CANCELLED = 5;
    EXECUTION_STATUS_TIMED_OUT = 6;
}

message NodeExecutionInfo {
    string node_id = 1;
    string node_type = 2;
    NodeStatus status = 3;
    
    bytes input = 4;
    bytes output = 5;
    string error = 6;
    int32 attempts = 7;
    
    google.protobuf.Timestamp scheduled_at = 8;
    google.protobuf.Timestamp started_at = 9;
    google.protobuf.Timestamp finished_at = 10;
}

enum NodeStatus {
    NODE_STATUS_UNSPECIFIED = 0;
    NODE_STATUS_PENDING = 1;
    NODE_STATUS_SCHEDULED = 2;
    NODE_STATUS_RUNNING = 3;
    NODE_STATUS_COMPLETED = 4;
    NODE_STATUS_FAILED = 5;
    NODE_STATUS_SKIPPED = 6;
    NODE_STATUS_CANCELLED = 7;
}
```

### 18.2 History Events
```protobuf
// api/proto/linkflow/history/v1/events.proto
syntax = "proto3";

package linkflow.history.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/any.proto";

message HistoryEvent {
    int64 event_id = 1;
    google.protobuf.Timestamp timestamp = 2;
    EventType event_type = 3;
    int64 version = 4;
    int64 task_id = 5;
    
    oneof attributes {
        WorkflowExecutionStartedEventAttributes workflow_execution_started = 10;
        WorkflowExecutionCompletedEventAttributes workflow_execution_completed = 11;
        WorkflowExecutionFailedEventAttributes workflow_execution_failed = 12;
        
        ActivityTaskScheduledEventAttributes activity_task_scheduled = 20;
        ActivityTaskStartedEventAttributes activity_task_started = 21;
        ActivityTaskCompletedEventAttributes activity_task_completed = 22;
        ActivityTaskFailedEventAttributes activity_task_failed = 23;
        
        TimerStartedEventAttributes timer_started = 30;
        TimerFiredEventAttributes timer_fired = 31;
        TimerCanceledEventAttributes timer_canceled = 32;
    }
}

enum EventType {
    EVENT_TYPE_UNSPECIFIED = 0;
    
    // Workflow lifecycle
    EVENT_TYPE_WORKFLOW_EXECUTION_STARTED = 1;
    EVENT_TYPE_WORKFLOW_EXECUTION_COMPLETED = 2;
    EVENT_TYPE_WORKFLOW_EXECUTION_FAILED = 3;
    EVENT_TYPE_WORKFLOW_EXECUTION_TIMED_OUT = 4;
    EVENT_TYPE_WORKFLOW_EXECUTION_CANCELED = 5;
    
    // Activity lifecycle
    EVENT_TYPE_ACTIVITY_TASK_SCHEDULED = 10;
    EVENT_TYPE_ACTIVITY_TASK_STARTED = 11;
    EVENT_TYPE_ACTIVITY_TASK_COMPLETED = 12;
    EVENT_TYPE_ACTIVITY_TASK_FAILED = 13;
    EVENT_TYPE_ACTIVITY_TASK_TIMED_OUT = 14;
    
    // Timer lifecycle
    EVENT_TYPE_TIMER_STARTED = 20;
    EVENT_TYPE_TIMER_FIRED = 21;
    EVENT_TYPE_TIMER_CANCELED = 22;
}

message WorkflowExecutionStartedEventAttributes {
    int64 workflow_id = 1;
    int64 workspace_id = 2;
    bytes input = 3;
    string idempotency_key = 4;
    
    int32 workflow_execution_timeout_seconds = 5;
    RetryPolicy retry_policy = 6;
}

message ActivityTaskScheduledEventAttributes {
    string activity_id = 1;
    string activity_type = 2;
    string task_queue = 3;
    bytes input = 4;
    
    int32 schedule_to_close_timeout_seconds = 5;
    int32 schedule_to_start_timeout_seconds = 6;
    int32 start_to_close_timeout_seconds = 7;
    int32 heartbeat_timeout_seconds = 8;
    
    RetryPolicy retry_policy = 9;
}

message ActivityTaskCompletedEventAttributes {
    int64 scheduled_event_id = 1;
    int64 started_event_id = 2;
    bytes result = 3;
}

message ActivityTaskFailedEventAttributes {
    int64 scheduled_event_id = 1;
    int64 started_event_id = 2;
    Failure failure = 3;
    string identity = 4;
    int32 attempt = 5;
}

message RetryPolicy {
    int32 maximum_attempts = 1;
    int32 initial_interval_seconds = 2;
    double backoff_coefficient = 3;
    int32 maximum_interval_seconds = 4;
    repeated string non_retryable_error_types = 5;
}

message Failure {
    string message = 1;
    string type = 2;
    string stack_trace = 3;
    Failure cause = 4;
}
```

### 18.3 Task Messages
```protobuf
// api/proto/linkflow/matching/v1/task.proto
syntax = "proto3";

package linkflow.matching.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/duration.proto";

message AddActivityTaskRequest {
    int64 workspace_id = 1;
    string task_queue = 2;
    string execution_id = 3;
    
    string activity_id = 4;
    string activity_type = 5;
    bytes input = 6;
    
    google.protobuf.Timestamp scheduled_at = 7;
    google.protobuf.Duration schedule_to_start_timeout = 8;
    
    int32 attempt = 9;
}

message PollActivityTaskRequest {
    int64 workspace_id = 1;
    string task_queue = 2;
    string worker_identity = 3;
    google.protobuf.Duration poll_timeout = 4;
}

message PollActivityTaskResponse {
    bytes task_token = 1;
    string execution_id = 2;
    
    string activity_id = 3;
    string activity_type = 4;
    bytes input = 5;
    
    google.protobuf.Timestamp scheduled_at = 6;
    google.protobuf.Timestamp started_at = 7;
    int32 attempt = 8;
    
    google.protobuf.Duration start_to_close_timeout = 9;
    google.protobuf.Duration heartbeat_timeout = 10;
}

message RespondActivityTaskCompletedRequest {
    bytes task_token = 1;
    bytes result = 2;
    string identity = 3;
}

message RespondActivityTaskFailedRequest {
    bytes task_token = 1;
    Failure failure = 2;
    string identity = 3;
}

message Failure {
    string message = 1;
    string type = 2;
    string stack_trace = 3;
}
```
---
## 19. API Specifications
### 19.1 gRPC Service Definitions
```protobuf
// api/proto/linkflow/api/v1/service.proto
syntax = "proto3";

package linkflow.api.v1;

service WorkflowService {
    // Start a new workflow execution
    rpc StartWorkflowExecution(StartWorkflowExecutionRequest) returns (StartWorkflowExecutionResponse);
    
    // Get execution details
    rpc GetExecution(GetExecutionRequest) returns (GetExecutionResponse);
    
    // List executions with filters
    rpc ListExecutions(ListExecutionsRequest) returns (ListExecutionsResponse);
    
    // Cancel a running execution
    rpc CancelExecution(CancelExecutionRequest) returns (CancelExecutionResponse);
    
    // Terminate an execution immediately
    rpc TerminateExecution(TerminateExecutionRequest) returns (TerminateExecutionResponse);
    
    // Get execution history
    rpc GetExecutionHistory(GetExecutionHistoryRequest) returns (GetExecutionHistoryResponse);
    
    // Query execution state
    rpc QueryExecution(QueryExecutionRequest) returns (QueryExecutionResponse);
    
    // Signal execution
    rpc SignalExecution(SignalExecutionRequest) returns (SignalExecutionResponse);
}

service HealthService {
    rpc Check(HealthCheckRequest) returns (HealthCheckResponse);
    rpc Watch(HealthCheckRequest) returns (stream HealthCheckResponse);
}

message ListExecutionsRequest {
    int64 workspace_id = 1;
    int32 page_size = 2;
    string page_token = 3;
    
    // Filters
    ExecutionStatus status = 4;
    int64 workflow_id = 5;
    google.protobuf.Timestamp start_time_min = 6;
    google.protobuf.Timestamp start_time_max = 7;
    
    // Query for search attributes
    string query = 8;
}

message ListExecutionsResponse {
    repeated ExecutionInfo executions = 1;
    string next_page_token = 2;
}

message CancelExecutionRequest {
    string execution_id = 1;
    string reason = 2;
}

message TerminateExecutionRequest {
    string execution_id = 1;
    string reason = 2;
}

message GetExecutionHistoryRequest {
    string execution_id = 1;
    int32 page_size = 2;
    bytes next_page_token = 3;
    bool wait_new_event = 4;
}

message GetExecutionHistoryResponse {
    repeated HistoryEvent events = 1;
    bytes next_page_token = 2;
}
```

### 19.2 REST API Endpoints
```yaml
# api/openapi/v1.yaml
openapi: 3.0.3
info:
  title: LinkFlow Engine API
  version: 1.0.0
  description: Workflow Execution Engine API

servers:
  - url: https://api.linkflow.io/v1
    description: Production
  - url: https://staging-api.linkflow.io/v1
    description: Staging

paths:
  /executions:
    post:
      summary: Start a new workflow execution
      operationId: startExecution
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/StartExecutionRequest'
      responses:
        '201':
          description: Execution started
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ExecutionResponse'
        '409':
          description: Execution already exists (idempotent)
          
    get:
      summary: List executions
      operationId: listExecutions
      parameters:
        - name: workspace_id
          in: query
          required: true
          schema:
            type: integer
        - name: status
          in: query
          schema:
            $ref: '#/components/schemas/ExecutionStatus'
        - name: limit
          in: query
          schema:
            type: integer
            default: 20
        - name: cursor
          in: query
          schema:
            type: string
      responses:
        '200':
          description: List of executions
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ExecutionListResponse'

  /executions/{execution_id}:
    get:
      summary: Get execution details
      operationId: getExecution
      parameters:
        - name: execution_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Execution details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ExecutionDetails'
        '404':
          description: Execution not found
          
    delete:
      summary: Cancel execution
      operationId: cancelExecution
      parameters:
        - name: execution_id
          in: path
          required: true
          schema:
            type: string
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                reason:
                  type: string
      responses:
        '200':
          description: Execution cancelled

  /executions/{execution_id}/history:
    get:
      summary: Get execution history
      operationId: getExecutionHistory
      parameters:
        - name: execution_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Execution history
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ExecutionHistory'

  /executions/{execution_id}/signal:
    post:
      summary: Signal execution
      operationId: signalExecution
      parameters:
        - name: execution_id
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SignalRequest'
      responses:
        '200':
          description: Signal sent

components:
  schemas:
    StartExecutionRequest:
      type: object
      required:
        - workspace_id
        - workflow_id
      properties:
        workspace_id:
          type: integer
        workflow_id:
          type: integer
        input:
          type: object
        idempotency_key:
          type: string
        options:
          $ref: '#/components/schemas/ExecutionOptions'
          
    ExecutionOptions:
      type: object
      properties:
        timeout_seconds:
          type: integer
        retry_policy:
          $ref: '#/components/schemas/RetryPolicy'
          
    RetryPolicy:
      type: object
      properties:
        max_attempts:
          type: integer
          default: 3
        initial_interval_ms:
          type: integer
          default: 1000
        backoff_coefficient:
          type: number
          default: 2.0
        max_interval_ms:
          type: integer
          default: 60000
          
    ExecutionStatus:
      type: string
      enum:
        - pending
        - running
        - completed
        - failed
        - cancelled
        - timed_out
        
    ExecutionResponse:
      type: object
      properties:
        execution_id:
          type: string
        run_id:
          type: string
        started:
          type: boolean
```
---
## 20. Deployment
### 20.1 Docker Compose (Development)
```yaml
# deploy/docker/docker-compose.yaml
version: '3.8'

services:
  frontend:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile.frontend
    ports:
      - "8080:8080"
      - "9090:9090"  # gRPC
    environment:
      - HISTORY_SERVICE_ADDRESS=history:9090
      - MATCHING_SERVICE_ADDRESS=matching:9090
      - REDIS_ADDRESS=redis:6379
      - JAEGER_ENDPOINT=http://jaeger:14268/api/traces
    depends_on:
      - history
      - matching
      - redis
      - jaeger

  history:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile.history
    ports:
      - "8081:8080"
      - "9091:9090"
    environment:
      - DATABASE_URL=postgres://linkflow:linkflow@postgres:5432/linkflow
      - REDIS_ADDRESS=redis:6379
      - NUM_SHARDS=16
    depends_on:
      - postgres
      - redis

  matching:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile.matching
    ports:
      - "8082:8080"
      - "9092:9090"
    environment:
      - REDIS_ADDRESS=redis:6379
      - HISTORY_SERVICE_ADDRESS=history:9090
    depends_on:
      - redis
      - history

  worker:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile.worker
    deploy:
      replicas: 3
    environment:
      - MATCHING_SERVICE_ADDRESS=matching:9090
      - HISTORY_SERVICE_ADDRESS=history:9090
      - DATABASE_URL=postgres://linkflow:linkflow@postgres:5432/linkflow
      - LARAVEL_APP_KEY=${LARAVEL_APP_KEY}
    depends_on:
      - matching
      - history
      - postgres

  timer:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile.timer
    environment:
      - DATABASE_URL=postgres://linkflow:linkflow@postgres:5432/linkflow
      - MATCHING_SERVICE_ADDRESS=matching:9090
    depends_on:
      - postgres
      - matching

  postgres:
    image: postgres:15-alpine
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_USER=linkflow
      - POSTGRES_PASSWORD=linkflow
      - POSTGRES_DB=linkflow
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ../migrations/postgres:/docker-entrypoint-initdb.d

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

  jaeger:
    image: jaegertracing/all-in-one:1.50
    ports:
      - "16686:16686"  # UI
      - "14268:14268"  # Collector
      - "6831:6831/udp"

  prometheus:
    image: prom/prometheus:v2.47.0
    ports:
      - "9000:9090"
    volumes:
      - ./prometheus.yaml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus

  grafana:
    image: grafana/grafana:10.1.0
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/datasources:/etc/grafana/provisioning/datasources

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:
```

### 20.2 Kubernetes Deployment
```yaml
# deploy/kubernetes/base/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: linkflow-frontend
  labels:
    app: linkflow
    component: frontend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: linkflow
      component: frontend
  template:
    metadata:
      labels:
        app: linkflow
        component: frontend
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
    spec:
      serviceAccountName: linkflow
      containers:
        - name: frontend
          image: linkflow/frontend:latest
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9090
              name: grpc
          env:
            - name: HISTORY_SERVICE_ADDRESS
              value: linkflow-history:9090
            - name: MATCHING_SERVICE_ADDRESS
              value: linkflow-matching:9090
            - name: REDIS_ADDRESS
              valueFrom:
                secretKeyRef:
                  name: linkflow-secrets
                  key: redis-address
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: linkflow-history
  labels:
    app: linkflow
    component: history
spec:
  replicas: 3
  selector:
    matchLabels:
      app: linkflow
      component: history
  template:
    metadata:
      labels:
        app: linkflow
        component: history
    spec:
      containers:
        - name: history
          image: linkflow/history:latest
          ports:
            - containerPort: 8080
            - containerPort: 9090
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: linkflow-secrets
                  key: database-url
            - name: REDIS_ADDRESS
              valueFrom:
                secretKeyRef:
                  name: linkflow-secrets
                  key: redis-address
            - name: NUM_SHARDS
              value: "256"
          resources:
            requests:
              cpu: 500m
              memory: 1Gi
            limits:
              cpu: 2000m
              memory: 4Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: linkflow-worker
  labels:
    app: linkflow
    component: worker
spec:
  replicas: 10
  selector:
    matchLabels:
      app: linkflow
      component: worker
  template:
    metadata:
      labels:
        app: linkflow
        component: worker
    spec:
      containers:
        - name: worker
          image: linkflow/worker:latest
          env:
            - name: MATCHING_SERVICE_ADDRESS
              value: linkflow-matching:9090
            - name: HISTORY_SERVICE_ADDRESS
              value: linkflow-history:9090
            - name: LARAVEL_APP_KEY
              valueFrom:
                secretKeyRef:
                  name: linkflow-secrets
                  key: laravel-app-key
          resources:
            requests:
              cpu: 200m
              memory: 512Mi
            limits:
              cpu: 1000m
              memory: 2Gi
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: linkflow-worker-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: linkflow-worker
  minReplicas: 5
  maxReplicas: 100
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Pods
      pods:
        metric:
          name: queue_depth
        target:
          type: AverageValue
          averageValue: "50"
```

### 20.3 Helm Chart
```yaml
# deploy/helm/linkflow/values.yaml
global:
  environment: production
  imageRegistry: docker.io/linkflow

frontend:
  replicas: 3
  image:
    repository: frontend
    tag: latest
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi
  service:
    type: ClusterIP
    httpPort: 8080
    grpcPort: 9090

history:
  replicas: 3
  image:
    repository: history
    tag: latest
  shards: 256
  resources:
    requests:
      cpu: 500m
      memory: 1Gi
    limits:
      cpu: 2000m
      memory: 4Gi

matching:
  replicas: 3
  image:
    repository: matching
    tag: latest
  partitions: 64
  resources:
    requests:
      cpu: 200m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 2Gi

worker:
  replicas: 10
  autoscaling:
    enabled: true
    minReplicas: 5
    maxReplicas: 100
    targetCPU: 70
  image:
    repository: worker
    tag: latest
  pools:
    http:
      workers: 50
      timeout: 30s
    email:
      workers: 20
      timeout: 60s
    database:
      workers: 10
      timeout: 120s
    ai:
      workers: 20
      timeout: 300s

postgresql:
  enabled: true
  auth:
    database: linkflow
    username: linkflow
  primary:
    persistence:
      size: 100Gi
    resources:
      requests:
        cpu: 500m
        memory: 2Gi

redis:
  enabled: true
  architecture: replication
  replica:
    replicaCount: 3
  master:
    persistence:
      size: 10Gi

observability:
  prometheus:
    enabled: true
  grafana:
    enabled: true
  jaeger:
    enabled: true
    collector:
      samplingRate: 0.1
```
---
## 21. Performance Targets
### 21.1 Latency Targets
| Operation | P50 | P95 | P99 |
|-----------|-----|-----|-----|
| Start Execution | 10ms | 50ms | 100ms |
| Complete Activity | 5ms | 20ms | 50ms |
| Poll Activity Task | 2ms | 10ms | 30ms |
| Query Execution | 5ms | 25ms | 75ms |
| List Executions | 20ms | 100ms | 250ms |

### 21.2 Throughput Targets
| Metric | Target |
|--------|--------|
| Executions started/sec | 10,000 |
| Activities completed/sec | 50,000 |
| Events persisted/sec | 100,000 |
| Queries/sec | 5,000 |

### 21.3 Scalability Targets
| Resource | Single Cell | Multi-Cell |
|----------|-------------|------------|
| Concurrent Executions | 1,000,000 | 10,000,000 |
| Workers | 1,000 | 10,000 |
| Event History Size | 50,000 events | 50,000 events |
| Retention | 30 days | 30 days |

### 21.4 Availability Targets
| Environment | Target |
|-------------|--------|
| Production | 99.99% |
| Staging | 99.9% |
| Development | 99% |

### 21.5 Recovery Targets
| Metric | Target |
|--------|--------|
| RTO (Recovery Time Objective) | < 5 minutes |
| RPO (Recovery Point Objective) | 0 (no data loss) |
| Failover Time | < 30 seconds |
---
## 22. Implementation Phases
### Phase 1: Core Foundation (Weeks 1-4)
**Goal**: Basic workflow execution with reliability

| Week | Deliverables |
|------|-------------|
| 1 | Project setup, proto definitions, DB schema |
| 2 | History service: event store, mutable state |
| 3 | Matching service: task queues, polling |
| 4 | Worker service: basic execution, retries |

**Milestone**: Execute a simple linear workflow with retry

### Phase 2: Production Ready (Weeks 5-8)
**Goal**: Production-grade reliability and observability

| Week | Deliverables |
|------|-------------|
| 5 | Frontend service: API gateway, rate limiting |
| 6 | Metrics, tracing, structured logging |
| 7 | Circuit breakers, bulkheads, timeouts |
| 8 | Integration testing, load testing |

**Milestone**: Handle 1000 req/sec with 99.9% availability

### Phase 3: Node Ecosystem (Weeks 9-12)
**Goal**: Complete node implementation

| Week | Deliverables |
|------|-------------|
| 9 | HTTP, Email, Messaging nodes |
| 10 | Database, Cloud provider nodes |
| 11 | AI/ML nodes (OpenAI, Anthropic) |
| 12 | Logic nodes (conditions, loops, parallel) |

**Milestone**: 50+ production-ready nodes

### Phase 4: Advanced Features (Weeks 13-16)
**Goal**: Enterprise capabilities

| Week | Deliverables |
|------|-------------|
| 13 | Expression engine with CEL |
| 14 | Timer service, scheduling |
| 15 | Shadow replay, debugging tools |
| 16 | Multi-tenancy, quotas, priorities |

**Milestone**: Feature parity with Temporal basics

### Phase 5: Scale & Resilience (Weeks 17-20)
**Goal**: Horizontal scaling and chaos engineering

| Week | Deliverables |
|------|-------------|
| 17 | Sharding, partition management |
| 18 | Worker isolation (WASM, containers) |
| 19 | Chaos engineering, fault injection |
| 20 | Auto-healing, graceful degradation |

**Milestone**: Handle 10,000 req/sec, survive any single failure

### Phase 6: Multi-Region (Weeks 21-24)
**Goal**: Global deployment with consistency

| Week | Deliverables |
|------|-------------|
| 21 | Cell architecture, routing |
| 22 | Cross-region replication (NDC) |
| 23 | Conflict resolution, consistency |
| 24 | Edge execution, offline support |

**Milestone**: Active-active across 3 regions

### Success Criteria per Phase

| Phase | Criteria |
|-------|----------|
| 1 | Simple workflow executes end-to-end |
| 2 | SLO metrics dashboard, <1% error rate |
| 3 | All node types tested with real integrations |
| 4 | Replay any execution for debugging |
| 5 | Survive chaos scenarios without data loss |
| 6 | Multi-region deployment with automatic failover |

---
## Summary

The LinkFlow Execution Engine is designed to be a **Temporal-grade** workflow execution system with:

- **Event Sourcing**: Full history for replay and debugging
- **Horizontal Scalability**: Sharding, partitioning, cell architecture
- **Multi-Region**: Active-active with conflict resolution
- **Edge Execution**: Local processing with offline support
- **Node Ecosystem**: 50+ integrations with isolation options
- **Enterprise Ready**: Multi-tenancy, quotas, observability

This architecture enables LinkFlow to compete with enterprise workflow platforms while remaining self-hostable and developer-friendly.