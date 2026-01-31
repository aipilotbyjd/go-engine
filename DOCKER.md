# LinkFlow Go Engine - Docker Setup

Complete workflow execution engine with 8 microservices.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         LINKFLOW ENGINE                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│  │  Frontend   │────▶│  Matching   │────▶│   Worker    │               │
│  │   :8080     │     │   :8082     │     │   :8083     │               │
│  │   :9090     │     │   :7235     │     │             │               │
│  └──────┬──────┘     └─────────────┘     └──────┬──────┘               │
│         │                                        │                       │
│         ▼                                        ▼                       │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│  │  History    │◀───▶│   Timer     │     │ Visibility  │               │
│  │   :8081     │     │   :8084     │     │   :8085     │               │
│  │   :7234     │     │   :7238     │     │   :7237     │               │
│  └─────────────┘     └─────────────┘     └─────────────┘               │
│                                                                          │
│  Optional:                                                               │
│  ┌─────────────┐     ┌─────────────┐                                   │
│  │    Edge     │     │Control Plane│                                   │
│  │   :8086     │     │   :8087     │                                   │
│  └─────────────┘     └─────────────┘                                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Services

| Service | Port | gRPC Port | Description |
|---------|------|-----------|-------------|
| **Frontend** | 8080 | 9090 | API Gateway - entry point for all requests |
| **History** | 8081 | 7234 | Event sourcing - stores all workflow events |
| **Matching** | 8082 | 7235 | Task queue - routes work to workers |
| **Worker** | 8083 | - | Node executor - runs HTTP, AI, Email, etc. |
| **Timer** | 8084 | 7238 | Scheduling - handles delays, cron, timeouts |
| **Visibility** | 8085 | 7237 | Search - query and list workflows |
| **Edge** | 8086 | - | Edge execution - low-latency edge computing |
| **Control Plane** | 8087 | 7239 | Cluster management - multi-region coordination |

## Quick Start

### 1. Start Infrastructure (required first)

```bash
cd ../infrastructure
docker-compose up -d
```

### 2. Setup Environment

```bash
cp .env.example .env
# Edit .env with your settings
```

### 3. Start Core Services

```bash
# Start main services (frontend, history, matching, worker, timer, visibility)
docker-compose up -d

# View logs
docker-compose logs -f
```

### 4. (Optional) Start Edge & Control Plane

```bash
# Include edge service
docker-compose --profile edge up -d

# Include control plane
docker-compose --profile control up -d

# Include both
docker-compose --profile edge --profile control up -d
```

## Service Details

### Frontend (API Gateway)
- **Purpose**: Entry point for all client requests
- **Features**: Authentication, rate limiting, request routing
- **Endpoints**:
  - `POST /api/v1/workflows/{id}/execute` - Start workflow
  - `GET /api/v1/executions/{id}` - Get execution status
  - `GET /api/v1/executions` - List executions

### History (Event Store)
- **Purpose**: Stores all workflow events for replay
- **Features**: Event sourcing, mutable state, sharding
- **Data**: WorkflowStarted, NodeCompleted, WorkflowFailed events

### Matching (Task Queue)
- **Purpose**: Routes tasks to available workers
- **Features**: Priority queues, long polling, load distribution
- **Flow**: History → Matching → Worker

### Worker (Executor)
- **Purpose**: Executes workflow nodes
- **Supported Nodes**:
  - HTTP Request, GraphQL, SOAP
  - OpenAI, Anthropic (AI)
  - SMTP, SendGrid, SES (Email)
  - Slack, Discord, Twilio
  - PostgreSQL, MySQL, MongoDB
  - If/Else, Switch, Loop
  - Delay, Wait

### Timer (Scheduler)
- **Purpose**: Time-based operations
- **Features**: Cron schedules, delays, timeouts
- **Use Cases**: "Run every Monday", "Wait 5 minutes"

### Visibility (Search)
- **Purpose**: Query and search workflows
- **Features**: Full-text search, filtering, pagination
- **Queries**: By status, time range, custom attributes

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | info | Logging level (debug, info, warn, error) |
| `JWT_SECRET` | - | JWT signing secret |
| `LINKFLOW_SECRET` | - | Shared secret with Laravel |
| `CELL_ID` | cell-1 | Cell identifier for multi-region |
| `REGION` | local | Region name |

### Scaling

Scale workers for more capacity:

```bash
docker-compose up -d --scale worker=4
```

## Health Checks

All services expose health endpoints:

```bash
# Check all services
curl http://localhost:8080/health  # Frontend
curl http://localhost:8081/health  # History
curl http://localhost:8082/health  # Matching
curl http://localhost:8083/health  # Worker
curl http://localhost:8084/health  # Timer
curl http://localhost:8085/health  # Visibility
```

## Troubleshooting

### Services not starting

1. Ensure infrastructure is running:
   ```bash
   docker ps | grep linkflow-postgres
   docker ps | grep linkflow-redis
   ```

2. Check network exists:
   ```bash
   docker network ls | grep linkflow
   ```

3. View service logs:
   ```bash
   docker-compose logs frontend
   docker-compose logs history
   ```

### Connection errors

Services use container names for discovery:
- `linkflow-postgres` for database
- `linkflow-redis` for cache/queue
- `linkflow-history`, `linkflow-matching`, etc. for internal communication

## Development

### Build all services

```bash
docker-compose build
```

### Rebuild specific service

```bash
docker-compose build worker
docker-compose up -d worker
```

### Run migrations

```bash
docker-compose --profile migrate run --rm migrate
```
