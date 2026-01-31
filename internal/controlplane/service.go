package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"
)

var (
	ErrClusterNotFound = errors.New("cluster not found")
	ErrNamespaceExists = errors.New("namespace already exists")
	ErrServiceNotFound = errors.New("service not found")
)

// ClusterInfo represents a cluster in the federation
type ClusterInfo struct {
	ID            string
	Name          string
	Region        string
	Endpoint      string
	Status        ClusterStatus
	LastHeartbeat time.Time
	Metadata      map[string]string
}

// ClusterStatus represents cluster health status
type ClusterStatus int

const (
	ClusterStatusUnknown ClusterStatus = iota
	ClusterStatusHealthy
	ClusterStatusDegraded
	ClusterStatusUnhealthy
	ClusterStatusOffline
)

// NamespaceConfig represents namespace configuration
type NamespaceConfig struct {
	ID                   string
	Name                 string
	Description          string
	OwnerEmail           string
	RetentionDays        int
	HistorySizeLimitMB   int
	WorkflowExecutionTTL time.Duration
	AllowedClusters      []string
	DefaultCluster       string
	SearchAttributes     map[string]SearchAttributeType
	ArchivalConfig       *ArchivalConfig
}

// SearchAttributeType defines the type of a search attribute
type SearchAttributeType int

const (
	SearchAttributeTypeString SearchAttributeType = iota
	SearchAttributeTypeKeyword
	SearchAttributeTypeInt
	SearchAttributeTypeDouble
	SearchAttributeTypeBool
	SearchAttributeDatetime
)

// ArchivalConfig defines archival settings
type ArchivalConfig struct {
	Enabled       bool
	URI           string
	HistoryURI    string
	VisibilityURI string
}

// ServiceInstance represents a registered service instance
type ServiceInstance struct {
	ID        string
	Service   string
	Address   string
	Port      int
	Metadata  map[string]string
	Health    HealthStatus
	LastCheck time.Time
	Version   string
}

// HealthStatus represents service health
type HealthStatus int

const (
	HealthStatusUnknown HealthStatus = iota
	HealthStatusServing
	HealthStatusNotServing
)

// Config holds control plane configuration
type Config struct {
	ClusterID   string
	ClusterName string
	Region      string
	Logger      *slog.Logger
}

// Service is the control plane service
type Service struct {
	config Config
	logger *slog.Logger

	clusters   map[string]*ClusterInfo
	namespaces map[string]*NamespaceConfig
	services   map[string][]*ServiceInstance

	mu      sync.RWMutex
	stopCh  chan struct{}
	running bool
}

// NewService creates a new control plane service
func NewService(config Config) *Service {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Service{
		config:     config,
		logger:     config.Logger,
		clusters:   make(map[string]*ClusterInfo),
		namespaces: make(map[string]*NamespaceConfig),
		services:   make(map[string][]*ServiceInstance),
		stopCh:     make(chan struct{}),
	}
}

// Start starts the control plane service
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("control plane already running")
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	// Register self as a cluster
	s.RegisterCluster(ctx, &ClusterInfo{
		ID:       s.config.ClusterID,
		Name:     s.config.ClusterName,
		Region:   s.config.Region,
		Status:   ClusterStatusHealthy,
		Metadata: map[string]string{"role": "primary"},
	})

	// Start background tasks
	go s.runHealthChecker(ctx)
	go s.runClusterSync(ctx)

	s.logger.Info("control plane started",
		slog.String("cluster_id", s.config.ClusterID),
		slog.String("region", s.config.Region),
	)

	return nil
}

// Stop stops the control plane service
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	s.logger.Info("control plane stopped")
	return nil
}

// RegisterCluster registers a cluster
func (s *Service) RegisterCluster(ctx context.Context, cluster *ClusterInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cluster.LastHeartbeat = time.Now()
	s.clusters[cluster.ID] = cluster

	s.logger.Info("cluster registered",
		slog.String("cluster_id", cluster.ID),
		slog.String("region", cluster.Region),
	)

	return nil
}

// GetCluster retrieves a cluster by ID
func (s *Service) GetCluster(ctx context.Context, clusterID string) (*ClusterInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cluster, exists := s.clusters[clusterID]
	if !exists {
		return nil, ErrClusterNotFound
	}
	return cluster, nil
}

// ListClusters returns all clusters
func (s *Service) ListClusters(ctx context.Context) []*ClusterInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clusters := make([]*ClusterInfo, 0, len(s.clusters))
	for _, c := range s.clusters {
		clusters = append(clusters, c)
	}
	return clusters
}

// CreateNamespace creates a new namespace
func (s *Service) CreateNamespace(ctx context.Context, ns *NamespaceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.namespaces[ns.Name]; exists {
		return ErrNamespaceExists
	}

	s.namespaces[ns.Name] = ns

	s.logger.Info("namespace created",
		slog.String("namespace", ns.Name),
	)

	return nil
}

// GetNamespace retrieves a namespace by name
func (s *Service) GetNamespace(ctx context.Context, name string) (*NamespaceConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ns, exists := s.namespaces[name]
	if !exists {
		return nil, errors.New("namespace not found")
	}
	return ns, nil
}

// UpdateNamespace updates a namespace
func (s *Service) UpdateNamespace(ctx context.Context, ns *NamespaceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.namespaces[ns.Name]; !exists {
		return errors.New("namespace not found")
	}

	s.namespaces[ns.Name] = ns
	return nil
}

// ListNamespaces returns all namespaces
func (s *Service) ListNamespaces(ctx context.Context) []*NamespaceConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	namespaces := make([]*NamespaceConfig, 0, len(s.namespaces))
	for _, ns := range s.namespaces {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

// RegisterService registers a service instance
func (s *Service) RegisterService(ctx context.Context, instance *ServiceInstance) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	instance.LastCheck = time.Now()
	instance.Health = HealthStatusServing

	instances := s.services[instance.Service]

	// Update existing or add new
	found := false
	for i, inst := range instances {
		if inst.ID == instance.ID {
			instances[i] = instance
			found = true
			break
		}
	}
	if !found {
		s.services[instance.Service] = append(instances, instance)
	}

	s.logger.Info("service registered",
		slog.String("service", instance.Service),
		slog.String("instance_id", instance.ID),
		slog.String("address", instance.Address),
	)

	return nil
}

// DeregisterService removes a service instance
func (s *Service) DeregisterService(ctx context.Context, service, instanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	instances := s.services[service]
	for i, inst := range instances {
		if inst.ID == instanceID {
			s.services[service] = append(instances[:i], instances[i+1:]...)
			break
		}
	}

	return nil
}

// GetServiceInstances returns all instances of a service
func (s *Service) GetServiceInstances(ctx context.Context, service string) ([]*ServiceInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	instances, exists := s.services[service]
	if !exists {
		return nil, ErrServiceNotFound
	}

	// Filter healthy instances
	healthy := make([]*ServiceInstance, 0)
	for _, inst := range instances {
		if inst.Health == HealthStatusServing {
			healthy = append(healthy, inst)
		}
	}

	return healthy, nil
}

// RouteRequest determines which cluster should handle a request
func (s *Service) RouteRequest(ctx context.Context, namespaceID, workflowID string) (*ClusterInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get namespace config
	ns, exists := s.namespaces[namespaceID]
	if !exists {
		// Use default cluster
		for _, cluster := range s.clusters {
			if cluster.Status == ClusterStatusHealthy {
				return cluster, nil
			}
		}
		return nil, errors.New("no healthy cluster available")
	}

	// Use namespace's default cluster if specified
	if ns.DefaultCluster != "" {
		if cluster, exists := s.clusters[ns.DefaultCluster]; exists {
			if cluster.Status == ClusterStatusHealthy {
				return cluster, nil
			}
		}
	}

	// Find first healthy allowed cluster
	for _, clusterID := range ns.AllowedClusters {
		if cluster, exists := s.clusters[clusterID]; exists {
			if cluster.Status == ClusterStatusHealthy {
				return cluster, nil
			}
		}
	}

	return nil, errors.New("no healthy cluster available for namespace")
}

// GetConfig returns global configuration as JSON
func (s *Service) GetConfig(ctx context.Context, key string) (json.RawMessage, error) {
	// Placeholder for dynamic configuration
	return nil, errors.New("config key not found")
}

func (s *Service) runHealthChecker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkServiceHealth()
		}
	}
}

func (s *Service) checkServiceHealth() {
	s.mu.Lock()
	defer s.mu.Unlock()

	staleThreshold := 30 * time.Second

	for service, instances := range s.services {
		for _, inst := range instances {
			if time.Since(inst.LastCheck) > staleThreshold {
				inst.Health = HealthStatusNotServing
				s.logger.Warn("service instance unhealthy",
					slog.String("service", service),
					slog.String("instance_id", inst.ID),
				)
			}
		}
	}

	for _, cluster := range s.clusters {
		if time.Since(cluster.LastHeartbeat) > staleThreshold {
			cluster.Status = ClusterStatusOffline
			s.logger.Warn("cluster offline",
				slog.String("cluster_id", cluster.ID),
			)
		}
	}
}

func (s *Service) runClusterSync(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			// Sync cluster state with other clusters in federation
			s.syncClusters()
		}
	}
}

func (s *Service) syncClusters() {
	// Placeholder for cross-cluster synchronization
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update own heartbeat
	if cluster, exists := s.clusters[s.config.ClusterID]; exists {
		cluster.LastHeartbeat = time.Now()
	}
}
