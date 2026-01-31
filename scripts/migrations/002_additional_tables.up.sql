-- Add timer table for the timer service
CREATE TABLE IF NOT EXISTS timers (
    shard_id INTEGER NOT NULL,
    namespace_id VARCHAR(255) NOT NULL,
    workflow_id VARCHAR(255) NOT NULL,
    run_id VARCHAR(255) NOT NULL,
    timer_id VARCHAR(255) NOT NULL,
    fire_time TIMESTAMP WITH TIME ZONE NOT NULL,
    status SMALLINT NOT NULL DEFAULT 0,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    fired_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (namespace_id, workflow_id, run_id, timer_id)
);

CREATE INDEX IF NOT EXISTS idx_timers_shard_fire ON timers (shard_id, status, fire_time);
CREATE INDEX IF NOT EXISTS idx_timers_execution ON timers (namespace_id, workflow_id, run_id);

-- Add visibility table for workflow search
CREATE TABLE IF NOT EXISTS visibility (
    namespace_id VARCHAR(255) NOT NULL,
    workflow_id VARCHAR(255) NOT NULL,
    run_id VARCHAR(255) NOT NULL,
    workflow_type_name VARCHAR(255),
    status SMALLINT NOT NULL DEFAULT 0,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    close_time TIMESTAMP WITH TIME ZONE,
    execution_time TIMESTAMP WITH TIME ZONE NOT NULL,
    memo JSONB,
    search_attributes JSONB,
    task_queue VARCHAR(255),
    parent_workflow_id VARCHAR(255),
    parent_run_id VARCHAR(255),
    PRIMARY KEY (namespace_id, workflow_id, run_id)
);

CREATE INDEX IF NOT EXISTS idx_visibility_namespace_status ON visibility (namespace_id, status);
CREATE INDEX IF NOT EXISTS idx_visibility_namespace_type ON visibility (namespace_id, workflow_type_name);
CREATE INDEX IF NOT EXISTS idx_visibility_start_time ON visibility (namespace_id, start_time DESC);
CREATE INDEX IF NOT EXISTS idx_visibility_close_time ON visibility (namespace_id, close_time DESC);

-- Add namespaces table for control plane
CREATE TABLE IF NOT EXISTS namespaces (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    owner_email VARCHAR(255),
    retention_days INTEGER DEFAULT 30,
    history_size_limit_mb INTEGER DEFAULT 50,
    workflow_execution_ttl_seconds BIGINT,
    allowed_clusters TEXT[],
    default_cluster VARCHAR(255),
    search_attributes JSONB,
    archival_enabled BOOLEAN DEFAULT FALSE,
    archival_uri TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Add clusters table for federation
CREATE TABLE IF NOT EXISTS clusters (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    region VARCHAR(100),
    endpoint VARCHAR(255),
    status SMALLINT NOT NULL DEFAULT 0,
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Add service_instances table for service discovery
CREATE TABLE IF NOT EXISTS service_instances (
    id VARCHAR(255) PRIMARY KEY,
    service VARCHAR(100) NOT NULL,
    address VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    metadata JSONB,
    health SMALLINT NOT NULL DEFAULT 0,
    last_check TIMESTAMP WITH TIME ZONE,
    version VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_service_instances_service ON service_instances (service, health);

-- Add credentials table for encrypted credential storage
CREATE TABLE IF NOT EXISTS credentials (
    id VARCHAR(255) PRIMARY KEY,
    namespace_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    encrypted_value TEXT NOT NULL,
    credential_type VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (namespace_id, name)
);

CREATE INDEX IF NOT EXISTS idx_credentials_namespace ON credentials (namespace_id);
