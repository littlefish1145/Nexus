package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Version        string           `mapstructure:"version"`
	Node           NodeConfig       `mapstructure:"node"`
	Tiering        TieringConfig    `mapstructure:"tiering"`
	Encryption     EncryptionConfig `mapstructure:"encryption"`
	CryptoServices CryptoServicesConfig `mapstructure:"crypto_services"`
	Vector         VectorConfig     `mapstructure:"vector"`
	Pipelines      PipelineConfig   `mapstructure:"pipelines"`
	Cache          CacheConfig      `mapstructure:"cache"`
	Performance    PerformanceConfig `mapstructure:"performance"`
	Logging        LoggingConfig    `mapstructure:"logging"`
	Auth           AuthConfig       `mapstructure:"auth"`
	IAM            IAMConfig        `mapstructure:"iam"`
	TLS            TLSConfig        `mapstructure:"tls"`
	RateLimit      RateLimitConfig   `mapstructure:"ratelimit"`
	Replication    ReplicationConfig `mapstructure:"replication"`
	Events         EventsConfig      `mapstructure:"events"`
}

type ReplicationConfig struct {
	AllowPrivateEndpoint bool `mapstructure:"allow_private_endpoint"`
}

type EventsConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Workers        int    `mapstructure:"workers"`
	MaxRetries     int    `mapstructure:"max_retries"`
	RetryBaseMS    int    `mapstructure:"retry_base_ms"`
	WebhookTimeout string `mapstructure:"webhook_timeout"`
	DeadLetterDir  string `mapstructure:"dead_letter_dir"`
}

type NodeConfig struct {
	Role         string   `mapstructure:"role"`
	ListenAddr   string   `mapstructure:"listen_addr"`
	DataDir      string   `mapstructure:"data_dir"`
	ClusterPeers []string `mapstructure:"cluster_peers"`
}

type AuthConfig struct {
	RequireAuth    bool   `mapstructure:"require_auth"`
	AnonymousRead  bool   `mapstructure:"anonymous_read"`
	JWTSecret      string `mapstructure:"jwt_secret"`
	TokenExpiry    string `mapstructure:"token_expiry"`
	RefreshExpiry  string `mapstructure:"refresh_expiry"`
}

// IAMConfig for the new IAM system
type IAMConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	DBPath        string `mapstructure:"db_path"`
	MasterKeyPath string `mapstructure:"master_key_path"`
	STSServiceAddr string `mapstructure:"sts_service_addr"`
}

type TLSConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	CertFile     string `mapstructure:"cert_file"`
	KeyFile      string `mapstructure:"key_file"`
	AutoCert     bool   `mapstructure:"auto_cert"`
	AutoCertHost string `mapstructure:"auto_cert_host"`
	RedirectAddr string `mapstructure:"redirect_addr"`
	MinVersion   string `mapstructure:"min_version"`
}

type RateLimitConfig struct {
	Enabled           bool              `mapstructure:"enabled"`
	GlobalRPS         int64             `mapstructure:"global_rps"`
	GlobalBurst       int               `mapstructure:"global_burst"`
	IPRPS             int64             `mapstructure:"ip_rps"`
	IPBurst           int               `mapstructure:"ip_burst"`
	UserRPS           int               `mapstructure:"user_rps"`
	UserBurst         int               `mapstructure:"user_burst"`
	BucketRPS         int               `mapstructure:"bucket_rps"`
	BucketBurst       int               `mapstructure:"bucket_burst"`
	UploadBytesPerSec int64             `mapstructure:"upload_bytes_per_sec"`
	UploadBurstBytes  int64             `mapstructure:"upload_burst_bytes"`
	APILimits         map[string]APILimitConfig `mapstructure:"api_limits"`
	Whitelist         []string          `mapstructure:"whitelist"`
}

type APILimitConfig struct {
	RPS   int `mapstructure:"rps"`
	Burst int `mapstructure:"burst"`
}

type TieringConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	Schedule     string   `mapstructure:"schedule"`
	HotMaxSize   string   `mapstructure:"hot_max_size"`
	WarmDevices  []string `mapstructure:"warm_devices"`
	ColdDevices  []string `mapstructure:"cold_devices"`
	ArchivePath  string   `mapstructure:"archive_path"`
	HotMaxBytes  int64    `mapstructure:"-"`
	WarmEnabled  bool     `mapstructure:"warm_enabled"`
	ColdEnabled  bool     `mapstructure:"cold_enabled"`
	ArchiveEnabled bool   `mapstructure:"archive_enabled"`
}

type EncryptionConfig struct {
	KMSType         string `mapstructure:"kms_type"`
	VaultAddr       string `mapstructure:"vault_addr"`
	VaultTokenFile  string `mapstructure:"vault_token_file"`
	VaultTransitKey string `mapstructure:"vault_transit_key"`
	AWSKMSKeyID     string `mapstructure:"aws_kms_key_id"`
	AWSRegion       string `mapstructure:"aws_region"`
	EnableDedup     bool   `mapstructure:"enable_dedup"`
	MasterKeyPath   string `mapstructure:"master_key_path"`
}

// CryptoServicesConfig for distributed crypto microservices
type CryptoServicesConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	DistributedMode bool   `mapstructure:"distributed_mode"`
	KeyPath         string `mapstructure:"key_path"`
	KeyStorePath    string `mapstructure:"keystore_path"`
	OPAAddress      string `mapstructure:"opa_address"`
	ConsulAddress   string `mapstructure:"consul_address"`
	MTLSCertFile    string `mapstructure:"mtls_cert_file"`
	MTLSKeyFile     string `mapstructure:"mtls_key_file"`
	MTLSCAFile      string `mapstructure:"mtls_ca_file"`
	AuditSize       int    `mapstructure:"audit_size"`
	// gRPC service addresses for distributed mode
	TokenServiceAddr     string `mapstructure:"token_service_addr"`
	KeyGenServiceAddr    string `mapstructure:"keygen_service_addr"`
	KeyUnwrapServiceAddr string `mapstructure:"keyunwrap_service_addr"`
	EncryptServiceAddr   string `mapstructure:"encrypt_service_addr"`
	DecryptServiceAddr   string `mapstructure:"decrypt_service_addr"`
	KeyStoreServiceAddr  string `mapstructure:"keystore_service_addr"`
}

type VectorConfig struct {
	Enabled              bool   `mapstructure:"enabled"`
	HotIndexSize         string `mapstructure:"hot_index_size"`
	ModelDir             string `mapstructure:"model_dir"`
	Dimension            int    `mapstructure:"dim"`
	HotIndexBytes        int64  `mapstructure:"-"`
	IndexType            string `mapstructure:"index_type"`
	MetricType           string `mapstructure:"metric_type"`
	MaxVectors           int64  `mapstructure:"max_vectors"`
	EmbeddingProvider    string `mapstructure:"embedding_provider"`
	EmbeddingModelPath   string `mapstructure:"embedding_model_path"`
	EmbeddingAPIEndpoint string `mapstructure:"embedding_api_endpoint"`
	EmbeddingAPIKey      string `mapstructure:"embedding_api_key"`
	EmbeddingModelName   string `mapstructure:"embedding_model_name"`
	AutoIndex            bool   `mapstructure:"auto_index"`
	MaxSearchTopK        int    `mapstructure:"max_search_top_k"`
	MaxQueryLength       int    `mapstructure:"max_query_length"`
	RequireAuth          bool   `mapstructure:"require_auth"`
	AllowedContentTypes  []string `mapstructure:"allowed_content_types"`
	MaxIndexContentSize  int64  `mapstructure:"max_index_content_size"`
}

type PipelineConfig struct {
	ConfigFile    string `mapstructure:"config_file"`
	MaxConcurrent int    `mapstructure:"max_concurrent"`
	Enabled       bool   `mapstructure:"enabled"`
}

type CacheConfig struct {
	MetadataMaxSize string `mapstructure:"metadata_max_size"`
	ObjectMaxSize   string `mapstructure:"object_max_size"`
	Policy          string `mapstructure:"policy"`
	MetadataMaxBytes int64 `mapstructure:"-"`
	ObjectMaxBytes   int64 `mapstructure:"-"`
	TTL             time.Duration `mapstructure:"ttl"`
}

type PerformanceConfig struct {
	MaxUploadSize        string   `mapstructure:"max_upload_size"`
	MaxConcurrentUploads int      `mapstructure:"max_concurrent_uploads"`
	IOWorkersPerCore     int      `mapstructure:"io_workers_per_core"`
	MaxUploadBytes       int64    `mapstructure:"-"`
	UseDirectIO          bool     `mapstructure:"use_direct_io"`
	EnableHTTP2          bool     `mapstructure:"enable_http2"`
	ReadBufferSize       int      `mapstructure:"read_buffer_size"`
	WriteBufferSize      int      `mapstructure:"write_buffer_size"`
}

type LoggingConfig struct {
	Level        string `mapstructure:"level"`
	Format       string `mapstructure:"format"`
	OutputPath   string `mapstructure:"output_path"`
	AccessLogDir string `mapstructure:"access_log_dir"`
}

func Load(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	viper.SetDefault("version", "2.0")
	viper.SetDefault("node.role", "all")
	viper.SetDefault("node.listen_addr", ":8080")
	viper.SetDefault("node.data_dir", "/var/lib/nexus")
	viper.SetDefault("tiering.enabled", true)
	viper.SetDefault("tiering.hot_max_size", "32GB")
	viper.SetDefault("encryption.enable_dedup", true)
	viper.SetDefault("encryption.vault_transit_key", "nexus")
	viper.SetDefault("crypto_services.enabled", false)
	viper.SetDefault("crypto_services.distributed_mode", false)
	viper.SetDefault("crypto_services.audit_size", 10000)
	viper.SetDefault("vector.enabled", true)
	viper.SetDefault("vector.dim", 768)
	viper.SetDefault("vector.hot_index_size", "10GB")
	viper.SetDefault("vector.auto_index", true)
	viper.SetDefault("vector.max_search_top_k", 100)
	viper.SetDefault("vector.max_query_length", 10000)
	viper.SetDefault("vector.require_auth", true)
	viper.SetDefault("vector.max_index_content_size", 1048576) // 1MB
	viper.SetDefault("cache.policy", "tinyLFU")
	viper.SetDefault("cache.metadata_max_size", "10GB")
	viper.SetDefault("cache.object_max_size", "30GB")
	viper.SetDefault("performance.max_upload_size", "100GB")
	viper.SetDefault("performance.max_concurrent_uploads", 500)
	viper.SetDefault("performance.enable_http2", true)
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("auth.require_auth", false)
	viper.SetDefault("auth.anonymous_read", true)
	viper.SetDefault("auth.token_expiry", "24h")
	viper.SetDefault("auth.refresh_expiry", "168h")
	viper.SetDefault("tls.enabled", false)
	viper.SetDefault("tls.min_version", "1.2")
	viper.SetDefault("ratelimit.enabled", false)
	viper.SetDefault("ratelimit.global_rps", 1000)
	viper.SetDefault("ratelimit.global_burst", 100)
	viper.SetDefault("ratelimit.ip_rps", 100)
	viper.SetDefault("ratelimit.ip_burst", 20)
	viper.SetDefault("ratelimit.user_rps", 50)
	viper.SetDefault("ratelimit.user_burst", 10)
	viper.SetDefault("ratelimit.bucket_rps", 200)
	viper.SetDefault("ratelimit.bucket_burst", 30)
	viper.SetDefault("ratelimit.upload_bytes_per_sec", 52428800)
	viper.SetDefault("ratelimit.upload_burst_bytes", 104857600)
	viper.SetDefault("replication.allow_private_endpoint", false)
	viper.SetDefault("events.enabled", false)
	viper.SetDefault("events.workers", 16)
	viper.SetDefault("events.max_retries", 3)
	viper.SetDefault("events.retry_base_ms", 1000)
	viper.SetDefault("events.webhook_timeout", "5s")
	viper.SetDefault("events.dead_letter_dir", "data/deadletter")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cfg.normalize(); err != nil {
		return nil, fmt.Errorf("failed to normalize config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) normalize() error {
	var err error

	if c.Tiering.HotMaxSize != "" {
		c.Tiering.HotMaxBytes, err = parseSize(c.Tiering.HotMaxSize)
		if err != nil {
			return fmt.Errorf("invalid hot_max_size: %w", err)
		}
	}

	if c.Vector.HotIndexSize != "" {
		c.Vector.HotIndexBytes, err = parseSize(c.Vector.HotIndexSize)
		if err != nil {
			return fmt.Errorf("invalid hot_index_size: %w", err)
		}
	}

	if c.Cache.MetadataMaxSize != "" {
		c.Cache.MetadataMaxBytes, err = parseSize(c.Cache.MetadataMaxSize)
		if err != nil {
			return fmt.Errorf("invalid metadata_max_size: %w", err)
		}
	}

	if c.Cache.ObjectMaxSize != "" {
		c.Cache.ObjectMaxBytes, err = parseSize(c.Cache.ObjectMaxSize)
		if err != nil {
			return fmt.Errorf("invalid object_max_size: %w", err)
		}
	}

	if c.Performance.MaxUploadSize != "" {
		c.Performance.MaxUploadBytes, err = parseSize(c.Performance.MaxUploadSize)
		if err != nil {
			return fmt.Errorf("invalid max_upload_size: %w", err)
		}
	}

	if c.Cache.TTL == 0 {
		c.Cache.TTL = 5 * time.Minute
	}

	if c.Performance.IOWorkersPerCore == 0 {
		c.Performance.IOWorkersPerCore = 2
	}

	if c.Performance.ReadBufferSize == 0 {
		c.Performance.ReadBufferSize = 32 * 1024
	}

	if c.Performance.WriteBufferSize == 0 {
		c.Performance.WriteBufferSize = 32 * 1024
	}

	return nil
}

func parseSize(s string) (int64, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("empty size string")
	}

	var multiplier int64 = 1

	if len(s) >= 2 {
		switch s[len(s)-2:] {
		case "GB":
			multiplier = 1 << 30
			s = s[:len(s)-2]
		case "MB":
			multiplier = 1 << 20
			s = s[:len(s)-2]
		case "KB":
			multiplier = 1 << 10
			s = s[:len(s)-2]
		case "TB":
			multiplier = 1 << 40
			s = s[:len(s)-2]
		default:
			if s[len(s)-1] == 'B' {
				multiplier = 1
				s = s[:len(s)-1]
			}
		}
	} else if len(s) == 1 && s[0] == 'B' {
		return 0, nil
	}

	var value int64
	_, err := fmt.Sscanf(s, "%d", &value)
	if err != nil {
		return 0, err
	}

	return value * multiplier, nil
}
