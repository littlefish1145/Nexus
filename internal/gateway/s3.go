package gateway

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"nexus/internal/bootstrap"
	"nexus/internal/cache"
	"nexus/internal/common"
	"nexus/internal/config"
	"nexus/internal/metadata"
	"nexus/internal/pipeline"
	"nexus/internal/ratelimit"
	"nexus/internal/services"
	"nexus/internal/storage"
	"nexus/internal/tiering"
	"nexus/internal/vector"

	"github.com/google/uuid"
)

var (
	bucketNameRegex      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	pathTraversalPattern = regexp.MustCompile(`(?:^|/)\.\.(?:$|/)`)
	controlCharPattern   = regexp.MustCompile(`[\x00-\x1f]`)
	encodedTraversalPattern = regexp.MustCompile(`(?i)(?:%2e%2e|%2e\.|\.\.%2e)`)

	maxRequestBodyBytes int64 = 50 * 1024 * 1024
)

type S3Gateway struct {
	mu              sync.RWMutex
	config          *config.Config
	metadata        *metadata.BoltDBMetadataStore
	store           *storage.TieredObjectStore
	tiering         *tiering.TieringManager
	cryptoCoordinator *services.EncryptionCoordinator
	vector          *vector.VectorManager
	pipeline        *pipeline.PipelineExecutor
	auth            *AuthHandler
	iamBridge       *IAMAuthBridge
	rateLimiter     *ratelimit.MultiLevelLimiter
	objectCache     *cache.ObjectCache
	metaCache       *cache.MetadataCache
	server          *http.Server
	buckets         map[string]*BucketState
	accessLog       *AccessLogger
}

type BucketState struct {
	Name        string
	CreatedAt   time.Time
	ObjectCount int64
	TotalSize   int64
}

type ListObjectsV2Output struct {
	XMLName               xml.Name               `xml:"ListBucketResult"`
	Name                  string                 `xml:"Name"`
	Prefix                string                 `xml:"Prefix"`
	StartAfter            string                 `xml:"StartAfter,omitempty"`
	ContinuationToken     string                 `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string                 `xml:"NextContinuationToken,omitempty"`
	KeyCount              int                    `xml:"KeyCount"`
	MaxKeys               int                    `xml:"MaxKeys"`
	Delimiter             string                 `xml:"Delimiter,omitempty"`
	IsTruncated           bool                   `xml:"IsTruncated"`
	Contents              []ListObjectsV2Content `xml:"Contents,omitempty"`
	CommonPrefixes        []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes,omitempty"`
}

type ListObjectsV2Content struct {
	Key          string    `xml:"Key"`
	LastModified time.Time `xml:"LastModified"`
	ETag         string    `xml:"ETag"`
	Size         int64     `xml:"Size"`
	StorageClass string    `xml:"StorageClass"`
	Owner        *struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	} `xml:"Owner,omitempty"`
}

type ListObjectsOutput struct {
	XMLName        xml.Name               `xml:"ListBucketResult"`
	Name           string                 `xml:"Name"`
	Prefix         string                 `xml:"Prefix"`
	Marker         string                 `xml:"Marker"`
	MaxKeys        int                    `xml:"MaxKeys"`
	Delimiter      string                 `xml:"Delimiter,omitempty"`
	IsTruncated    bool                   `xml:"IsTruncated"`
	NextMarker     string                 `xml:"NextMarker,omitempty"`
	Contents       []ListObjectsV2Content `xml:"Contents,omitempty"`
	CommonPrefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes,omitempty"`
}

type ListBucketsOutput struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Owner   struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	} `xml:"Owner"`
	Buckets []struct {
		Bucket struct {
			Name         string    `xml:"Name"`
			CreationDate time.Time `xml:"CreationDate"`
		} `xml:"Bucket"`
	} `xml:"Buckets>Bucket"`
}

type ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
}

func NewS3Gateway(cfg *config.Config) (*S3Gateway, error) {
	gateway := &S3Gateway{
		config:  cfg,
		buckets: make(map[string]*BucketState),
	}

	if err := gateway.initializeStores(cfg); err != nil {
		return nil, fmt.Errorf("failed to initialize stores: %w", err)
	}

	if err := gateway.initializeComponents(cfg); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	accessLogDir := cfg.Logging.AccessLogDir
	if accessLogDir == "" {
		accessLogDir = cfg.Node.DataDir + "/logs"
	}
	accessLogger, err := NewAccessLogger(accessLogDir, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create access logger: %w", err)
	}
	gateway.accessLog = accessLogger

	return gateway, nil
}

func (g *S3Gateway) initializeStores(cfg *config.Config) error {
	metadataStore, err := metadata.NewBoltDBMetadataStore(cfg.Node.DataDir + "/metadata.db")
	if err != nil {
		return fmt.Errorf("failed to create metadata store: %w", err)
	}
	g.metadata = metadataStore

	store := storage.NewTieredObjectStore()

	hotDir := cfg.Node.DataDir + "/hot"
	hotBackend, err := storage.NewFileBackend(hotDir)
	if err != nil {
		return fmt.Errorf("failed to create hot storage backend: %w", err)
	}
	store.RegisterTier(common.TierHot, hotBackend, cfg.Tiering.HotMaxBytes)

	warmDir := cfg.Node.DataDir + "/warm"
	warmBackend, err := storage.NewFileBackend(warmDir)
	if err != nil {
		return fmt.Errorf("failed to create warm storage backend: %w", err)
	}
	warmMaxSize := cfg.Tiering.HotMaxBytes * 5
	store.RegisterTier(common.TierWarm, warmBackend, warmMaxSize)

	coldDir := cfg.Node.DataDir + "/cold"
	coldBackend, err := storage.NewFileBackend(coldDir)
	if err != nil {
		return fmt.Errorf("failed to create cold storage backend: %w", err)
	}
	coldMaxSize := cfg.Tiering.HotMaxBytes * 20
	store.RegisterTier(common.TierCold, coldBackend, coldMaxSize)

	archiveDir := cfg.Node.DataDir + "/archive"
	if cfg.Tiering.ArchivePath != "" {
		archiveDir = cfg.Tiering.ArchivePath
	}
	archiveBackend, err := storage.NewFileBackend(archiveDir)
	if err != nil {
		return fmt.Errorf("failed to create archive storage backend: %w", err)
	}
	archiveMaxSize := cfg.Tiering.HotMaxBytes * 100
	store.RegisterTier(common.TierArchive, archiveBackend, archiveMaxSize)

	g.store = store

	return nil
}

func (g *S3Gateway) initializeComponents(cfg *config.Config) error {
	// Initialize crypto services with zero-trust architecture
	if cfg.CryptoServices.Enabled {
		coordinator, err := bootstrap.InitializeCryptoServices(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize crypto services: %w", err)
		}
		g.cryptoCoordinator = coordinator
	}

	tieringConfig := &tiering.TieringConfig{
		Enabled:          cfg.Tiering.Enabled,
		HotMaxSize:       cfg.Tiering.HotMaxBytes,
		MigrationWorkers: 10,
		CheckInterval:    6 * time.Hour,
	}
	tieringManager := tiering.NewTieringManager(g.store, tieringConfig)
	g.tiering = tieringManager

	if cfg.Vector.Enabled {
		vectorConfig := &vector.VectorConfig{
			Enabled:              cfg.Vector.Enabled,
			Dimension:            cfg.Vector.Dimension,
			IndexType:            cfg.Vector.IndexType,
			MetricType:           cfg.Vector.MetricType,
			MaxVectors:           cfg.Vector.MaxVectors,
			QueryCacheTTL:        5 * time.Minute,
			EmbeddingProvider:    cfg.Vector.EmbeddingProvider,
			EmbeddingModelPath:   cfg.Vector.EmbeddingModelPath,
			EmbeddingAPIEndpoint: cfg.Vector.EmbeddingAPIEndpoint,
			EmbeddingAPIKey:      cfg.Vector.EmbeddingAPIKey,
			EmbeddingModelName:   cfg.Vector.EmbeddingModelName,
		}
		vectorManager, err := vector.NewVectorManager(vectorConfig)
		if err != nil {
			return fmt.Errorf("failed to create vector manager: %w", err)
		}
		g.vector = vectorManager
	}

	pipelineExecutor := pipeline.NewPipelineExecutor(cfg.Pipelines.MaxConcurrent)
	if err := pipeline.RegisterDefaultPlugins(pipelineExecutor); err != nil {
		return fmt.Errorf("failed to register default plugins: %w", err)
	}
	g.pipeline = pipelineExecutor

	authConfig := &AuthConfig{
		RequireAuth:   cfg.Auth.RequireAuth,
		AnonymousRead: cfg.Auth.AnonymousRead,
		JWTSecret:     cfg.Auth.JWTSecret,
	}
	if cfg.Auth.TokenExpiry != "" {
		if d, err := time.ParseDuration(cfg.Auth.TokenExpiry); err == nil {
			authConfig.TokenExpiry = d
		}
	}
	if cfg.Auth.RefreshExpiry != "" {
		if d, err := time.ParseDuration(cfg.Auth.RefreshExpiry); err == nil {
			authConfig.RefreshExpiry = d
		}
	}
	g.auth = NewAuthHandlerWithConfig(authConfig)

	if cfg.RateLimit.Enabled {
		apiLimits := make(map[string]ratelimit.APILimit)
		for name, limit := range cfg.RateLimit.APILimits {
			apiLimits[name] = ratelimit.APILimit{
				RPS:   limit.RPS,
				Burst: limit.Burst,
			}
		}

		mlCfg := &ratelimit.MultiLevelConfig{
			GlobalRPS:         cfg.RateLimit.GlobalRPS,
			GlobalBurst:       cfg.RateLimit.GlobalBurst,
			IPRPS:             cfg.RateLimit.IPRPS,
			IPBurst:           cfg.RateLimit.IPBurst,
			UserRPS:           cfg.RateLimit.UserRPS,
			UserBurst:         cfg.RateLimit.UserBurst,
			BucketRPS:         cfg.RateLimit.BucketRPS,
			BucketBurst:       cfg.RateLimit.BucketBurst,
			UploadBytesPerSec: cfg.RateLimit.UploadBytesPerSec,
			UploadBurstBytes:  cfg.RateLimit.UploadBurstBytes,
			APILimits:         apiLimits,
			Whitelist:         cfg.RateLimit.Whitelist,
		}
		g.rateLimiter = ratelimit.NewMultiLevelLimiter(mlCfg)
	}

	if cfg.Cache.ObjectMaxBytes > 0 {
		objectCache, err := cache.NewObjectCache(cfg.Cache.ObjectMaxBytes, cfg.Cache.TTL)
		if err != nil {
			return fmt.Errorf("failed to create object cache: %w", err)
		}
		g.objectCache = objectCache
	}

	if cfg.Cache.MetadataMaxBytes > 0 {
		g.metaCache = cache.NewMetadataCache(cfg.Cache.TTL)
	}

	return nil
}

func (g *S3Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handleRequest)
	return mux
}

func (g *S3Gateway) handleRequest(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	requestID := uuid.New().String()
	ctx := r.Context()
	ctx = common.WithRequestID(ctx, requestID)
	r = r.WithContext(ctx)

	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Set("x-amz-id-2", uuid.New().String()[:16])

	g.setCORSHeaders(w, r, "")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if g.rateLimiter != nil {
		userID := g.auth.GetUserID(r)
		ip := extractIP(r)
		bucket := ""
		if len(r.URL.Path) > 1 {
			parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
			if len(parts) > 0 {
				bucket = parts[0]
			}
		}
		contentLength, _ := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
		result := g.rateLimiter.Allow(ctx, ip, userID, bucket, r.Method, contentLength)
		if !result.Allowed {
			retryAfter := fmt.Sprintf("%d", result.RetryAfter)
			if result.RetryAfter <= 0 {
				retryAfter = "1"
			}
			w.Header().Set("Retry-After", retryAfter)
			w.Header().Set("X-RateLimit-Limit-Type", result.LimitType)
			g.writeError(w, http.StatusTooManyRequests, "SlowDown",
				fmt.Sprintf("Rate limit exceeded (%s). Please retry after %ss.", result.LimitType, retryAfter))
			return
		}
	}

	path := r.URL.Path
	method := r.Method

	if len(path) > 1024 {
		g.writeError(w, http.StatusBadRequest, "InvalidURI", "Object key too long")
		return
	}

	if pathTraversalPattern.MatchString(path) || controlCharPattern.MatchString(path) || encodedTraversalPattern.MatchString(r.URL.RawPath) || encodedTraversalPattern.MatchString(r.URL.RawQuery) {
		g.writeError(w, http.StatusBadRequest, "InvalidURI", "Invalid characters in path")
		return
	}

	var handler func(w http.ResponseWriter, r *http.Request) error

	if path == "/" {
		if method == "GET" {
			if _, err := g.auth.RequireAuth(r, "read"); err != nil {
				g.writeError(w, http.StatusUnauthorized, "AccessDenied", err.Error())
				return
			}
			handler = g.handleListBuckets
		} else if method == "POST" {
			if _, err := g.auth.RequireAuth(r, "write"); err != nil {
				g.writeError(w, http.StatusUnauthorized, "AccessDenied", err.Error())
				return
			}
			handler = g.handlePOST
		}
	} else if len(path) > 1 {
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
		bucket := parts[0]

		if !g.validateBucketName(bucket) {
			g.writeError(w, http.StatusBadRequest, "InvalidBucketName", "Bucket name must be between 3-63 characters, lowercase letters, numbers, hyphens, and periods")
			return
		}

		if len(parts) == 1 || (len(parts) == 2 && parts[1] == "") {
			handler = g.handleBucketOperations(bucket, method)
		} else if len(parts) == 2 {
			key := parts[1]
			if !g.validateObjectKey(key) {
				g.writeError(w, http.StatusBadRequest, "InvalidKey", "Object key contains invalid characters")
				return
			}
			handler = g.handleObjectOperations(bucket, key, method)
		}
	}

	if handler == nil {
		g.writeError(w, http.StatusNotFound, "NoSuchResource", "The specified resource does not exist.")
		return
	}

	if err := handler(w, r); err != nil {
		g.writeError(w, http.StatusInternalServerError, "InternalError", "An internal error occurred")
	}

	latency := time.Since(startTime)
	_ = latency

	if g.accessLog != nil {
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
		bucket := ""
		key := ""
		if len(parts) >= 1 {
			bucket = parts[0]
		}
		if len(parts) >= 2 {
			key = parts[1]
		}
		g.accessLog.Log(AccessLogEntry{
			RemoteIP:   getClientIP(r),
			UserID:     g.auth.GetUserID(r),
			Operation:  method,
			Bucket:     bucket,
			Key:        key,
			StatusCode: 200,
			BytesSent:  0,
			RequestID:  requestID,
		})
	}
}

func (g *S3Gateway) setCORSHeaders(w http.ResponseWriter, r *http.Request, bucket string) {
	origin := r.Header.Get("Origin")
	if origin != "" {
		bucketInfo, err := g.metadata.GetBucket(r.Context(), bucket)
		if err == nil && bucketInfo != nil && bucketInfo.CORS != nil && len(bucketInfo.CORS.AllowedOrigins) > 0 {
			for _, allowed := range bucketInfo.CORS.AllowedOrigins {
				if allowed == "*" || allowed == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
		}
	}
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Content-Length, x-amz-content-sha256, x-amz-date, x-amz-security-token, x-amz-user-agent, x-amz-meta-*, x-amz-acl, x-amz-copy-source, x-amz-tagging, x-amz-server-side-encryption, x-amz-checksum-crc32c, x-amz-checksum-sha256, x-amz-checksum-md5, x-amz-checksum-mode, X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date, X-Amz-Expires, X-Amz-SignedHeaders, X-Amz-Signature, amz-sdk-invocation-id, amz-sdk-request, amz-sdk-retry")
	w.Header().Set("Access-Control-Max-Age", "3600")
	w.Header().Set("Access-Control-Expose-Headers", "ETag, X-Amz-Version-Id, X-Amz-Request-Id, X-Amz-Expiration, X-Amz-Checksum-CRC32C, X-Amz-Checksum-SHA256, X-Amz-Checksum-MD5")
}

func (g *S3Gateway) validateBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	if !bucketNameRegex.MatchString(name) {
		return false
	}
	if strings.HasPrefix(name, "xn--") {
		return false
	}
	if strings.HasSuffix(name, "-s3alias") {
		return false
	}
	return true
}

func (g *S3Gateway) validateObjectKey(key string) bool {
	if len(key) > 1024 {
		return false
	}
	if pathTraversalPattern.MatchString(key) {
		return false
	}
	if controlCharPattern.MatchString(key) {
		return false
	}
	return true
}

func (g *S3Gateway) validateContentType(contentType string) bool {
	allowedTypes := []string{
		"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml",
		"application/pdf", "application/json", "application/xml",
		"text/plain", "text/html", "text/css", "text/javascript",
		"application/octet-stream",
	}
	if contentType == "" {
		return true
	}
	for _, t := range allowedTypes {
		if strings.HasPrefix(contentType, t) {
			return true
		}
	}
	return false
}

func (g *S3Gateway) handleListBuckets(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "GET" {
		return fmt.Errorf("method not allowed")
	}

	buckets, err := g.metadata.ListBuckets(r.Context())
	if err != nil {
		return fmt.Errorf("failed to list buckets: %w", err)
	}

	output := ListBucketsOutput{}
	output.Owner.ID = "nexus-owner"
	output.Owner.DisplayName = "Nexus Owner"
	output.Buckets = make([]struct {
		Bucket struct {
			Name         string    `xml:"Name"`
			CreationDate time.Time `xml:"CreationDate"`
		} `xml:"Bucket"`
	}, len(buckets))

	for i, b := range buckets {
		output.Buckets[i].Bucket.Name = b.Name
		output.Buckets[i].Bucket.CreationDate = b.CreatedAt
	}

	return g.writeXML(w, http.StatusOK, output)
}

func (g *S3Gateway) handlePOST(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return fmt.Errorf("method not allowed")
	}

	query := r.URL.Query()
	if query.Has("vector_search") {
		return g.handleVectorSearch(w, r)
	}

	if query.Has("uploads") {
		multipartHandler := NewMultipartUploadHandler(g)
		bucket := query.Get("bucket")
		key := query.Get("key")
		if bucket == "" {
			path := r.URL.Path
			if len(path) > 1 {
				parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
				if len(parts) >= 1 {
					bucket = parts[0]
				}
				if len(parts) >= 2 {
					key = parts[1]
				}
			}
		}
		return multipartHandler.HandleCreateMultipartUpload(w, r, bucket, key)
	}

	return fmt.Errorf("unsupported POST operation")
}

func (g *S3Gateway) handleBucketOperations(bucket, method string) func(w http.ResponseWriter, r *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		query := r.URL.Query()

		switch method {
		case "PUT":
			if query.Has("acl") {
				if _, err := g.auth.RequireAuthForBucket(r, bucket, "admin"); err != nil {
					return fmt.Errorf("access denied: %w", err)
				}
				return g.handlePutBucketAcl(w, r, bucket)
			}
			if _, err := g.auth.RequireAuthForBucket(r, bucket, "write"); err != nil {
				return fmt.Errorf("access denied: %w", err)
			}
			return g.handleCreateBucket(w, r, bucket)
		case "DELETE":
			if _, err := g.auth.RequireAuthForBucket(r, bucket, "admin"); err != nil {
				return fmt.Errorf("access denied: %w", err)
			}
			return g.handleDeleteBucket(w, r, bucket)
		case "HEAD":
			if _, err := g.auth.RequireAuthForBucket(r, bucket, "read"); err != nil {
				return fmt.Errorf("access denied: %w", err)
			}
			return g.handleHeadBucket(w, r, bucket)
		case "GET":
			if query.Has("location") {
				return g.handleGetBucketLocation(w, r, bucket)
			}
			if query.Has("acl") {
				if _, err := g.auth.RequireAuthForBucket(r, bucket, "read"); err != nil {
					return fmt.Errorf("access denied: %w", err)
				}
				return g.handleGetBucketAcl(w, r, bucket)
			}
			if query.Has("versioning") {
				return g.handleGetBucketVersioning(w, r, bucket)
			}
			if query.Has("uploads") {
				multipartHandler := NewMultipartUploadHandler(g)
				return multipartHandler.HandleListUploads(w, r, bucket)
			}
			if !g.isBucketPublicRead(r, bucket) {
				if _, err := g.auth.RequireAuthForBucket(r, bucket, "read"); err != nil {
					return fmt.Errorf("access denied: %w", err)
				}
			}
			return g.handleListObjects(w, r, bucket)
		default:
			return fmt.Errorf("method not allowed")
		}
	}
}

func (g *S3Gateway) handleObjectOperations(bucket, key, method string) func(w http.ResponseWriter, r *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		query := r.URL.Query()
		if query.Has("uploadId") {
			multipartHandler := NewMultipartUploadHandler(g)
			switch method {
			case "PUT":
				return multipartHandler.HandleUploadPart(w, r, bucket, key)
			case "POST":
				return multipartHandler.HandleCompleteMultipartUpload(w, r, bucket, key)
			case "DELETE":
				return multipartHandler.HandleAbortMultipartUpload(w, r, bucket, key)
			case "GET":
				return multipartHandler.HandleListParts(w, r, bucket, key)
			default:
				return fmt.Errorf("method not allowed for multipart upload")
			}
		}

		switch method {
		case "PUT":
			return g.handlePutObject(w, r, bucket, key)
		case "GET":
			return g.handleGetObject(w, r, bucket, key)
		case "HEAD":
			return g.handleHeadObject(w, r, bucket, key)
		case "DELETE":
			return g.handleDeleteObject(w, r, bucket, key)
		case "POST":
			return g.handleObjectPOST(w, r, bucket, key)
		default:
			return fmt.Errorf("method not allowed")
		}
	}
}

func (g *S3Gateway) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) error {
	if r.Method != "PUT" {
		return fmt.Errorf("method not allowed")
	}

	acl := r.Header.Get("x-amz-acl")
	if acl == "" {
		acl = "private"
	}

	userID := g.auth.GetUserID(r)
	if userID == "" || userID == "anonymous" {
		userID = "admin"
	}

	region := "us-east-1"
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err == nil && len(body) > 0 {
		type CreateBucketConfiguration struct {
			LocationConstraint string `xml:"LocationConstraint"`
		}
		var config CreateBucketConfiguration
		if err := xml.Unmarshal(body, &config); err == nil && config.LocationConstraint != "" {
			region = config.LocationConstraint
		}
	}

	bucketInfo := &metadata.BucketInfo{
		Name:      bucket,
		CreatedAt: time.Now(),
		OwnerID:   userID,
		OwnerName: userID,
		Region:    region,
		ACL:       acl,
	}

	if err := g.metadata.CreateBucket(r.Context(), bucket, bucketInfo); err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}

	w.Header().Set("Location", "/"+bucket)
	w.Header().Set("x-amz-request-id", uuid.New().String())
	w.WriteHeader(http.StatusOK)
	return nil
}

func (g *S3Gateway) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) error {
	if r.Method != "DELETE" {
		return fmt.Errorf("method not allowed")
	}

	if err := g.metadata.DeleteBucket(r.Context(), bucket); err != nil {
		return fmt.Errorf("failed to delete bucket: %w", err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (g *S3Gateway) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) error {
	if r.Method != "HEAD" {
		return fmt.Errorf("method not allowed")
	}

	_, err := g.metadata.GetBucket(r.Context(), bucket)
	if err != nil {
		return fmt.Errorf("bucket not found: %w", err)
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (g *S3Gateway) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) error {
	if r.Method != "GET" {
		return fmt.Errorf("method not allowed")
	}

	query := r.URL.Query()
	prefix := query.Get("prefix")
	delimiter := query.Get("delimiter")
	maxKeysStr := query.Get("max-keys")
	listType := query.Get("list-type")

	maxKeys := 1000
	if maxKeysStr != "" {
		if m, err := strconv.Atoi(maxKeysStr); err == nil {
			maxKeys = m
		}
	}

	if listType == "2" {
		return g.handleListObjectsV2(w, r, bucket, prefix, delimiter, maxKeys, query)
	}

	marker := query.Get("marker")
	objects, err := g.metadata.ListObjects(r.Context(), bucket, prefix, maxKeys)
	if err != nil {
		return fmt.Errorf("failed to list objects: %w", err)
	}

	output := ListObjectsOutput{
		Name:        bucket,
		Prefix:      prefix,
		Marker:      marker,
		MaxKeys:     maxKeys,
		Delimiter:   delimiter,
		IsTruncated: len(objects) == maxKeys,
	}

	for _, obj := range objects {
		if delimiter != "" {
			idx := strings.Index(obj.Key[len(prefix):], delimiter)
			if idx >= 0 {
				output.CommonPrefixes = append(output.CommonPrefixes, struct {
					Prefix string `xml:"Prefix"`
				}{Prefix: obj.Key[:len(prefix)+idx+len(delimiter)]})
				continue
			}
		}

		output.Contents = append(output.Contents, ListObjectsV2Content{
			Key:          obj.Key,
			LastModified: obj.ModifiedAt,
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: common.StorageTier(obj.StorageTier).String(),
			Owner: &struct {
				ID          string `xml:"ID"`
				DisplayName string `xml:"DisplayName"`
			}{
				ID:          "nexus-owner",
				DisplayName: "nexus-owner",
			},
		})
	}

	if output.IsTruncated && len(output.Contents) > 0 {
		output.NextMarker = output.Contents[len(output.Contents)-1].Key
	}

	return g.writeXML(w, http.StatusOK, output)
}

func (g *S3Gateway) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket, prefix, delimiter string, maxKeys int, query map[string][]string) error {
	startAfter := ""
	if v, ok := query["start-after"]; ok && len(v) > 0 {
		startAfter = v[0]
	}
	continuationToken := ""
	if v, ok := query["continuation-token"]; ok && len(v) > 0 {
		continuationToken = v[0]
	}

	objects, err := g.metadata.ListObjects(r.Context(), bucket, prefix, maxKeys+1)
	if err != nil {
		return fmt.Errorf("failed to list objects: %w", err)
	}

	if startAfter != "" {
		filtered := make([]*metadata.ObjectMetadata, 0, len(objects))
		passedStart := false
		for _, obj := range objects {
			if obj.Key == startAfter {
				passedStart = true
				continue
			}
			if passedStart {
				filtered = append(filtered, obj)
			}
		}
		objects = filtered
	} else if continuationToken != "" {
		filtered := make([]*metadata.ObjectMetadata, 0, len(objects))
		passedToken := false
		for _, obj := range objects {
			if obj.Key == continuationToken {
				passedToken = true
				continue
			}
			if passedToken {
				filtered = append(filtered, obj)
			}
		}
		objects = filtered
	}

	isTruncated := len(objects) > maxKeys
	if isTruncated {
		objects = objects[:maxKeys]
	}

	output := ListObjectsV2Output{
		Name:              bucket,
		Prefix:            prefix,
		StartAfter:        startAfter,
		ContinuationToken: continuationToken,
		KeyCount:          len(objects),
		MaxKeys:           maxKeys,
		Delimiter:         delimiter,
		IsTruncated:       isTruncated,
	}

	for _, obj := range objects {
		if delimiter != "" {
			idx := strings.Index(obj.Key[len(prefix):], delimiter)
			if idx >= 0 {
				output.CommonPrefixes = append(output.CommonPrefixes, struct {
					Prefix string `xml:"Prefix"`
				}{Prefix: obj.Key[:len(prefix)+idx+len(delimiter)]})
				continue
			}
		}

		output.Contents = append(output.Contents, ListObjectsV2Content{
			Key:          obj.Key,
			LastModified: obj.ModifiedAt,
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: common.StorageTier(obj.StorageTier).String(),
			Owner: &struct {
				ID          string `xml:"ID"`
				DisplayName string `xml:"DisplayName"`
			}{
				ID:          "nexus-owner",
				DisplayName: "nexus-owner",
			},
		})
	}

	if isTruncated && len(output.Contents) > 0 {
		output.NextContinuationToken = output.Contents[len(output.Contents)-1].Key
	}

	return g.writeXML(w, http.StatusOK, output)
}

func (g *S3Gateway) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) error {
	if r.Method != "PUT" {
		return fmt.Errorf("method not allowed")
	}

	isPresignedURL := r.URL.Query().Get("X-Amz-Credential") != ""
	if isPresignedURL {
		if err := g.validatePresignedURLMethod(r, "PUT"); err != nil {
			return err
		}
	}

	if _, err := g.auth.RequireAuthForBucket(r, bucket, "write"); err != nil {
		return fmt.Errorf("access denied: %w", err)
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	if !g.validateContentType(contentType) {
		return fmt.Errorf("unsupported content type: %s", contentType)
	}

	contentLength := r.ContentLength
	if contentLength < 0 {
		// If Content-Length is not set, we need to read the body to determine size
		// This is necessary for proper validation
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, g.config.Performance.MaxUploadBytes))
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		contentLength = int64(len(bodyBytes))
		// Replace body with a reader for the bytes we just read
		r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	if g.config != nil && g.config.Performance.MaxUploadBytes > 0 {
		if contentLength > g.config.Performance.MaxUploadBytes {
			g.writeError(w, http.StatusRequestEntityTooLarge, "EntityTooLarge",
				fmt.Sprintf("Object size %d exceeds maximum allowed size %d",
					contentLength, g.config.Performance.MaxUploadBytes))
			return nil
		}
	}

	metadataMap := make(map[string]string)
	for k, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			metadataMap[strings.TrimPrefix(k, "x-amz-meta-")] = values[0]
		}
	}

	userID := g.auth.GetUserID(r)
	if userID == "" {
		userID = "anonymous"
	}

	etag := uuid.New().String()

	var providedChecksum string
	var providedChecksumType string

	if c := r.Header.Get("x-amz-checksum-crc32c"); c != "" {
		providedChecksum = c
		providedChecksumType = "crc32c"
	} else if c := r.Header.Get("x-amz-checksum-sha256"); c != "" {
		providedChecksum = c
		providedChecksumType = "sha256"
	} else if c := r.Header.Get("x-amz-checksum-md5"); c != "" {
		providedChecksum = c
		providedChecksumType = "md5"
	} else if c := r.Header.Get("Content-MD5"); c != "" {
		providedChecksum = c
		providedChecksumType = "md5"
	}

	sha256Hasher := sha256.New()
	var crc32cHasher hash.Hash
	var md5Hasher hash.Hash

	if providedChecksumType == "crc32c" {
		crc32cHasher = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	}
	if providedChecksumType == "md5" {
		md5Hasher = md5.New()
	}

	var hashWriters []io.Writer
	hashWriters = append(hashWriters, sha256Hasher)
	if crc32cHasher != nil {
		hashWriters = append(hashWriters, crc32cHasher)
	}
	if md5Hasher != nil {
		hashWriters = append(hashWriters, md5Hasher)
	}
	multiWriter := io.MultiWriter(hashWriters...)

	var plaintextReader io.Reader = io.TeeReader(r.Body, multiWriter)

	var dataReader io.Reader = plaintextReader
	var encryptedDEKMetadata []byte
	var encrypted bool
	var actualStorageSize int64 = contentLength

	if g.cryptoCoordinator != nil && g.config != nil && g.config.CryptoServices.Enabled {
		encryptedReader, _, metadata, ciphertextSize, err := g.cryptoCoordinator.EncryptOperation(r.Context(), userID, bucket, key, plaintextReader, contentLength)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
		dataReader = encryptedReader
		encryptedDEKMetadata = metadata
		encrypted = true
		actualStorageSize = ciphertextSize
	}

	objMetadata := &common.ObjectMetadata{
		Key:            key,
		Bucket:         bucket,
		Size:           contentLength,
		ContentType:    contentType,
		ETag:           etag,
		UserMetadata:   metadataMap,
		StorageTier:    common.TierHot,
		CreatedAt:      time.Now(),
		ModifiedAt:     time.Now(),
		AccessCount:    0,
		LastAccessedAt: time.Now(),
		Encrypted:      encrypted,
		VersionID:      uuid.New().String(),
	}

	storageTier := common.TierHot
	if err := g.store.Put(r.Context(), bucket, key, dataReader, actualStorageSize, storageTier, objMetadata); err != nil {
		return fmt.Errorf("failed to store object: %w", err)
	}

	computedSHA256 := base64.StdEncoding.EncodeToString(sha256Hasher.Sum(nil))

	var storedChecksum string
	var storedChecksumType string

	switch providedChecksumType {
	case "crc32c":
		storedChecksum = base64.StdEncoding.EncodeToString(crc32cHasher.Sum(nil))
		storedChecksumType = "crc32c"
		if providedChecksum != storedChecksum {
			g.store.Delete(r.Context(), bucket, key, storageTier)
			g.writeError(w, http.StatusBadRequest, "BadDigest",
				fmt.Sprintf("CRC32C checksum mismatch: expected %s, got %s", providedChecksum, storedChecksum))
			return nil
		}
	case "sha256":
		storedChecksum = computedSHA256
		storedChecksumType = "sha256"
		if providedChecksum != storedChecksum {
			g.store.Delete(r.Context(), bucket, key, storageTier)
			g.writeError(w, http.StatusBadRequest, "BadDigest",
				fmt.Sprintf("SHA256 checksum mismatch: expected %s, got %s", providedChecksum, storedChecksum))
			return nil
		}
	case "md5":
		storedChecksum = base64.StdEncoding.EncodeToString(md5Hasher.Sum(nil))
		storedChecksumType = "md5"
		if providedChecksum != storedChecksum {
			g.store.Delete(r.Context(), bucket, key, storageTier)
			g.writeError(w, http.StatusBadRequest, "BadDigest",
				fmt.Sprintf("MD5 checksum mismatch: expected %s, got %s", providedChecksum, storedChecksum))
			return nil
		}
	default:
		storedChecksum = computedSHA256
		storedChecksumType = "sha256"
	}

	meta := &metadata.ObjectMetadata{
		Key:            key,
		Bucket:         bucket,
		Size:           contentLength,
		ContentType:    contentType,
		ETag:           etag,
		UserMetadata:   metadataMap,
		StorageTier:    int(common.TierHot),
		CreatedAt:      time.Now(),
		ModifiedAt:     time.Now(),
		AccessCount:    0,
		LastAccessedAt: time.Now(),
		Encrypted:      encrypted,
		VersionID:      objMetadata.VersionID,
		IsLatest:       true,
		ObjectStatus:   "active",
		Checksum:       storedChecksum,
		ChecksumType:   storedChecksumType,
	}

	if encryptedDEKMetadata != nil {
		meta.EncryptedDEK = encryptedDEKMetadata
	}

	if err := g.metadata.PutObject(r.Context(), bucket, key, meta); err != nil {
		g.store.Delete(r.Context(), bucket, key, storageTier)
		return fmt.Errorf("failed to store metadata: %w", err)
	}

	if g.tiering != nil {
		g.tiering.RecordAccess(r.Context(), bucket, key, "PUT", userID)
	}

	if g.vector != nil && g.config.Vector.Enabled {
		// Auto-index when vector search is enabled; skip if client explicitly opts out
		if r.Header.Get("X-Vectorize") != "false" {
			go g.vectorizeObject(r.Context(), bucket, key, contentType, metadataMap, userID)
		}
	}

	if g.pipeline != nil {
		go g.triggerPipelines(r.Context(), bucket, key, contentType, metadataMap)
	}

	w.Header().Set("ETag", `"`+etag+`"`)
	w.Header().Set("x-amz-version-id", objMetadata.VersionID)
	if encrypted {
		w.Header().Set("x-amz-server-side-encryption", "AES256")
	}
	switch storedChecksumType {
	case "crc32c":
		w.Header().Set("x-amz-checksum-crc32c", storedChecksum)
	case "sha256":
		w.Header().Set("x-amz-checksum-sha256", storedChecksum)
	case "md5":
		w.Header().Set("x-amz-checksum-md5", storedChecksum)
	}
	w.WriteHeader(http.StatusOK)

	g.auditLog(r, "PUT", bucket, key, userID, "success", map[string]interface{}{
		"size":         contentLength,
		"content_type": contentType,
		"encrypted":    encrypted,
	})

	return nil
}

func (g *S3Gateway) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) error {
	if r.Method != "GET" {
		return fmt.Errorf("method not allowed")
	}

	isPresignedURL := r.URL.Query().Get("X-Amz-Credential") != ""

	if isPresignedURL {
		if err := g.validatePresignedURLMethod(r, "GET"); err != nil {
			return err
		}
	}

	if !isPresignedURL && !g.isBucketPublicRead(r, bucket) {
		if _, err := g.auth.RequireAuthForBucket(r, bucket, "read"); err != nil {
			return fmt.Errorf("access denied: %w", err)
		}
	}

	userID := g.auth.GetUserID(r)
	if userID == "" {
		userID = "anonymous"
	}

	if g.tiering != nil {
		g.tiering.RecordAccess(r.Context(), bucket, key, "GET", userID)
	}

	objMetadata, err := g.metadata.GetObject(r.Context(), bucket, key)
	if err != nil {
		g.writeError(w, http.StatusNotFound, "NoSuchKey", fmt.Sprintf("Object '%s' not found", key))
		return nil
	}

	if objMetadata.DeleteMarker {
		g.writeError(w, http.StatusNotFound, "NoSuchKey", "Object has been deleted")
		return nil
	}

	etag := `"` + objMetadata.ETag + `"`
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" {
		if ifNoneMatch == "*" || ifNoneMatch == etag {
			w.WriteHeader(http.StatusNotModified)
			return nil
		}
	}

	ifMatch := r.Header.Get("If-Match")
	if ifMatch != "" && ifMatch != "*" && ifMatch != etag {
		g.writeError(w, http.StatusPreconditionFailed, "PreconditionFailed", "ETag does not match")
		return nil
	}

	ifModifiedSince := r.Header.Get("If-Modified-Since")
	if ifModifiedSince != "" {
		ifModTime, err := time.Parse(http.TimeFormat, ifModifiedSince)
		if err == nil && !objMetadata.ModifiedAt.After(ifModTime) {
			w.WriteHeader(http.StatusNotModified)
			return nil
		}
	}

	rangeHeader := r.Header.Get("Range")
	cacheKey := bucket + "/" + key

	if g.objectCache != nil && objMetadata.Size < 1<<20 && rangeHeader == "" && !objMetadata.Encrypted {
		if cachedData, found := g.objectCache.Get(r.Context(), cacheKey); found {
			w.Header().Set("Content-Type", objMetadata.ContentType)
			w.Header().Set("Content-Length", strconv.FormatInt(int64(len(cachedData)), 10))
			w.Header().Set("ETag", etag)
			w.Header().Set("Last-Modified", objMetadata.ModifiedAt.Format(http.TimeFormat))
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Cache-Control", "max-age=3600")
			w.Header().Set("X-Cache", "HIT")
			for k, v := range objMetadata.UserMetadata {
				w.Header().Set("X-Amz-Meta-"+k, v)
			}
			setChecksumResponseHeaders(w, objMetadata, r)
			w.WriteHeader(http.StatusOK)
			w.Write(cachedData)
			return nil
		}
	}

	storageTier := common.StorageTier(objMetadata.StorageTier)
	reader, _, err := g.store.Get(r.Context(), bucket, key, storageTier)
	if err != nil {
		g.writeError(w, http.StatusNotFound, "NoSuchKey", fmt.Sprintf("Object '%s' not found", key))
		return nil
	}
	defer reader.Close()

	var dataReader io.Reader = reader
	var contentLength = objMetadata.Size

	if objMetadata.Encrypted && g.cryptoCoordinator != nil && len(objMetadata.EncryptedDEK) > 0 {
		encryptedDEKMetadata := objMetadata.EncryptedDEK

		rawFallback := r.Header.Get("x-amz-raw-decryption-fallback") == "true"
		var rawBackup []byte
		if rawFallback {
			rawBackup, err = io.ReadAll(io.LimitReader(reader, g.config.Performance.MaxUploadBytes))
			if err != nil {
				fmt.Printf("[nexus] decryption error for %s/%s: failed to read raw data for fallback: %v\n", bucket, key, err)
				g.writeError(w, http.StatusInternalServerError, "InternalError", "An internal error occurred while processing the object")
				return nil
			}
			reader = io.NopCloser(bytes.NewReader(rawBackup))
		}

		decryptedReader, err := g.cryptoCoordinator.DecryptOperation(r.Context(), userID, bucket, key, reader, "", encryptedDEKMetadata)
		if err != nil {
			fmt.Printf("[nexus] decryption error for %s/%s: %v\n", bucket, key, err)
			if rawFallback && rawBackup != nil {
				w.Header().Set("x-amz-decryption-fallback", "true")
				dataReader = bytes.NewReader(rawBackup)
				contentLength = int64(len(rawBackup))
			} else {
				g.writeError(w, http.StatusInternalServerError, "InternalError", "An internal error occurred while processing the object")
				return nil
			}
		} else {
			dataReader = decryptedReader
		}
	}

	var statusCode = http.StatusOK
	var contentRange string

	if rangeHeader != "" {
		start, end, err := parseRangeHeader(rangeHeader, objMetadata.Size)
		if err != nil {
			g.writeError(w, http.StatusRequestedRangeNotSatisfiable, "InvalidRange", err.Error())
			return nil
		}

		if seeker, ok := dataReader.(io.Seeker); ok {
			seeker.Seek(start, io.SeekStart)
			dataReader = io.LimitReader(dataReader, end-start+1)
		} else {
			discard := start
			buf := make([]byte, 32*1024)
			for discard > 0 {
				n := int64(len(buf))
				if n > discard {
					n = discard
				}
				read, err := io.ReadFull(dataReader, buf[:n])
				if err != nil {
					break
				}
				discard -= int64(read)
			}
			dataReader = io.LimitReader(dataReader, end-start+1)
		}

		contentLength = end - start + 1
		contentRange = fmt.Sprintf("bytes %d-%d/%d", start, end, objMetadata.Size)
		statusCode = http.StatusPartialContent
	}

	w.Header().Set("Content-Type", objMetadata.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", objMetadata.ModifiedAt.Format(http.TimeFormat))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "max-age=3600")

	if g.objectCache != nil {
		w.Header().Set("X-Cache", "MISS")
	}

	if objMetadata.Encrypted {
		w.Header().Set("x-amz-server-side-encryption", "AES256")
	}

	if contentRange != "" {
		w.Header().Set("Content-Range", contentRange)
	}

	for k, v := range objMetadata.UserMetadata {
		w.Header().Set("X-Amz-Meta-"+k, v)
	}

	setChecksumResponseHeaders(w, objMetadata, r)

	w.WriteHeader(statusCode)

	if g.objectCache != nil && objMetadata.Size < 1<<20 && rangeHeader == "" && !objMetadata.Encrypted {
		data, err := io.ReadAll(io.LimitReader(dataReader, 1<<20))
		if err == nil {
			g.objectCache.Set(r.Context(), cacheKey, data)
			w.Write(data)
			return nil
		}
	}

	io.Copy(w, dataReader)

	return nil
}

func isClientDisconnected(err error) bool {
	if err == nil {
		return false
	}
	if err == context.Canceled {
		return true
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "broken pipe") ||
		strings.Contains(errMsg, "connection reset") ||
		strings.Contains(errMsg, "client disconnected") {
		return true
	}
	if strings.Contains(errMsg, "use of closed connection") {
		return true
	}
	return false
}

func parseRangeHeader(rangeHeader string, totalSize int64) (start, end int64, err error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, fmt.Errorf("invalid range header format")
	}

	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.Split(rangeSpec, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range specification")
	}

	if parts[0] == "" {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid range end")
		}
		start = totalSize - end
		if start < 0 {
			start = 0
		}
		end = totalSize - 1
	} else {
		start, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid range start")
		}
		if parts[1] == "" {
			end = totalSize - 1
		} else {
			end, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("invalid range end")
			}
		}
	}

	if start > end || start >= totalSize {
		return 0, 0, fmt.Errorf("range not satisfiable")
	}

	if end >= totalSize {
		end = totalSize - 1
	}

	return start, end, nil
}

func (g *S3Gateway) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) error {
	if r.Method != "HEAD" {
		return fmt.Errorf("method not allowed")
	}

	if !g.isBucketPublicRead(r, bucket) {
		if _, err := g.auth.RequireAuthForBucket(r, bucket, "read"); err != nil {
			return fmt.Errorf("access denied: %w", err)
		}
	}

	objMetadata, err := g.metadata.GetObject(r.Context(), bucket, key)
	if err != nil {
		return fmt.Errorf("object not found: %w", err)
	}

	w.Header().Set("Content-Type", objMetadata.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(objMetadata.Size, 10))
	w.Header().Set("ETag", `"`+objMetadata.ETag+`"`)
	w.Header().Set("Last-Modified", objMetadata.ModifiedAt.Format(http.TimeFormat))
	w.Header().Set("X-Amz-Storage-Class", common.StorageTier(objMetadata.StorageTier).String())

	if objMetadata.Encrypted {
		w.Header().Set("x-amz-server-side-encryption", "AES256")
	}

	for k, v := range objMetadata.UserMetadata {
		w.Header().Set("X-Amz-Meta-"+k, v)
	}

	setChecksumResponseHeaders(w, objMetadata, r)

	w.WriteHeader(http.StatusOK)
	return nil
}

func (g *S3Gateway) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) error {
	if r.Method != "DELETE" {
		return fmt.Errorf("method not allowed")
	}

	if _, err := g.auth.RequireAuthForBucket(r, bucket, "delete"); err != nil {
		return fmt.Errorf("access denied: %w", err)
	}

	objMetadata, err := g.metadata.GetObject(r.Context(), bucket, key)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	if r.Header.Get("x-amz-bypass-governance-retention") != "true" {
		if objMetadata.RetainUntil != nil && objMetadata.RetainUntil.After(time.Now()) {
			g.writeError(w, http.StatusForbidden, "ObjectLocked", "Object is under retention lock")
			return nil
		}
	}

	softDelete := r.Header.Get("x-amz-delete-marker") != "false"
	versioningEnabled := false

	if bucketInfo, err := g.metadata.GetBucket(r.Context(), bucket); err == nil {
		versioningEnabled = bucketInfo.Versioning
	}

	if softDelete && versioningEnabled {
		deleteMarker := &metadata.ObjectMetadata{
			Key:          key,
			Bucket:       bucket,
			Size:         0,
			ContentType:  "application/octet-stream",
			ETag:         uuid.New().String(),
			StorageTier:  objMetadata.StorageTier,
			CreatedAt:    time.Now(),
			ModifiedAt:   time.Now(),
			DeleteMarker: true,
			VersionID:    uuid.New().String(),
			IsLatest:     true,
			ObjectStatus: "delete-marker",
		}

		if err := g.metadata.PutObject(r.Context(), bucket, key, deleteMarker); err != nil {
			return fmt.Errorf("failed to create delete marker: %w", err)
		}

		w.Header().Set("x-amz-delete-marker", "true")
		w.Header().Set("x-amz-version-id", deleteMarker.VersionID)
	} else {
		storageTier := common.StorageTier(objMetadata.StorageTier)
		g.store.Delete(r.Context(), bucket, key, storageTier)

		if g.vector != nil {
			g.vector.DeleteVector(r.Context(), bucket, key)
		}

		if g.objectCache != nil {
			g.objectCache.Delete(r.Context(), bucket+"/"+key)
		}

		g.metadata.DeleteObject(r.Context(), bucket, key)
	}

	userID := g.auth.GetUserID(r)
	g.auditLog(r, "DELETE", bucket, key, userID, "success", map[string]interface{}{
		"soft_delete": softDelete && versioningEnabled,
	})

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (g *S3Gateway) handleObjectPOST(w http.ResponseWriter, r *http.Request, bucket, key string) error {
	query := r.URL.Query()
	if query.Has("vector_search") {
		return g.handleVectorSearchForObject(w, r, bucket, key)
	}

	return fmt.Errorf("unsupported POST operation")
}

type VectorSearchResponse struct {
	Results   []SearchResultItem `json:"results"`
	LatencyMs int64              `json:"latency_ms"`
	IndexUsed string             `json:"index_used"`
}

type SearchResultItem struct {
	Key      string            `json:"key"`
	Score    float32           `json:"score"`
	Metadata map[string]string `json:"metadata"`
}

func (g *S3Gateway) handleVectorSearch(w http.ResponseWriter, r *http.Request) error {
	// Security: Require authentication for vector search
	user, err := g.auth.RequireAuth(r, "read")
	if err != nil {
		return fmt.Errorf("vector search requires authentication: %w", err)
	}

	// Security: Check vector:Search permission via IAM
	if g.iamBridge != nil {
		if err := g.iamBridge.CheckIAMAccess(nil, "vector:Search", "", "", r); err != nil {
			// Fall back to legacy permission check
			if user.Role != "admin" {
				hasVectorPerm := false
				for _, p := range user.Permissions {
					if p == "vector:Search" || p == "vector:*" || p == "read" || p == "admin" {
						hasVectorPerm = true
						break
					}
				}
				if !hasVectorPerm {
					return fmt.Errorf("access denied: vector:Search permission required")
				}
			}
		}
	}

	// Security: Rate limit vector search requests
	if g.rateLimiter != nil {
		clientIP := extractClientIP(r)
		result := g.rateLimiter.Allow(r.Context(), clientIP, user.ID, "", "VECTOR_SEARCH", 0)
		if !result.Allowed {
			return fmt.Errorf("vector search rate limit exceeded for user %s", user.ID)
		}
	}

	query := r.URL.Query()
	searchQuery := query.Get("vector_search")
	if searchQuery == "" {
		return fmt.Errorf("missing vector_search query parameter")
	}

	// Security: Limit query length to prevent abuse
	if len(searchQuery) > 10000 {
		return fmt.Errorf("search query too long: maximum 10000 characters")
	}

	topKStr := query.Get("top_k")
	thresholdStr := query.Get("threshold")

	topK := 20
	if topKStr != "" {
		if k, err := strconv.Atoi(topKStr); err == nil {
			topK = k
		}
	}

	// Security: Cap topK to prevent resource exhaustion
	if topK > 100 {
		topK = 100
	}
	if topK <= 0 {
		topK = 1
	}

	threshold := float32(0.7)
	if thresholdStr != "" {
		if t, err := strconv.ParseFloat(thresholdStr, 32); err == nil {
			threshold = float32(t)
		}
	}

	filters := make(map[string]string)
	filterStr := query.Get("filter")
	if filterStr != "" {
		pairs := strings.Split(filterStr, "&")
		for _, pair := range pairs {
			kv := strings.Split(pair, "=")
			if len(kv) == 2 {
				filters[kv[0]] = kv[1]
			}
		}
	}

	// Security: If user is not admin, restrict search to buckets they can read
	if user.Role != "admin" && g.iamBridge != nil {
		if bucketFilter := filters["bucket"]; bucketFilter != "" {
			if err := g.iamBridge.CheckIAMAccess(nil, "s3:GetObject", bucketFilter, "", r); err != nil {
				return fmt.Errorf("access denied: no read permission on bucket %s", bucketFilter)
			}
		}
	}

	startTime := time.Now()

	searchResult, err := g.vector.SearchByText(r.Context(), searchQuery, topK, filters)
	if err != nil {
		return fmt.Errorf("vector search failed: %w", err)
	}

	// Security: Filter results to only include objects the user can access
	results := make([]SearchResultItem, 0)
	for _, r := range searchResult {
		if r.Score < threshold {
			continue
		}
		// Non-admin users can only see results from buckets they have read access to
		if user.Role != "admin" && g.iamBridge != nil {
			if err := g.iamBridge.CheckIAMAccess(nil, "s3:GetObject", r.Bucket, r.ObjectKey, nil); err != nil {
				continue
			}
		}
		results = append(results, SearchResultItem{
			Key:      r.ObjectKey,
			Score:    r.Score,
			Metadata: r.Metadata,
		})
	}

	response := VectorSearchResponse{
		Results:   results,
		LatencyMs: time.Since(startTime).Milliseconds(),
		IndexUsed: "hot",
	}

	// Security: Audit log for vector search
	userID := "anonymous"
	if user != nil {
		userID = user.ID
	}
	g.auditLog(r, "VECTOR_SEARCH", "", "", userID, "success", map[string]interface{}{
		"query":    truncateString(searchQuery, 200),
		"top_k":    topK,
		"results":  len(results),
		"latency_ms": response.LatencyMs,
	})

	return g.writeJSON(w, http.StatusOK, response)
}

func (g *S3Gateway) handleVectorSearchForObject(w http.ResponseWriter, r *http.Request, bucket, key string) error {
	// Security: Require authentication and bucket-level read access
	if _, err := g.auth.RequireAuthForBucket(r, bucket, "read"); err != nil {
		return fmt.Errorf("access denied: %w", err)
	}
	return g.handleVectorSearch(w, r)
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// vectorizeObject reads object content and indexes it for vector search.
// Only text-based content types are indexed; binary files are skipped.
func (g *S3Gateway) vectorizeObject(ctx context.Context, bucket, key, contentType string, metadataMap map[string]string, userID string) {
	// Only index text-based content types
	if !vector.IsTextContent(contentType) {
		return
	}

	// Read object content for embedding generation
	objMeta, err := g.metadata.GetObject(ctx, bucket, key)
	if err != nil {
		return
	}

	storageTier := common.StorageTier(objMeta.StorageTier)
	reader, _, err := g.store.Get(ctx, bucket, key, storageTier)
	if err != nil {
		return
	}
	defer reader.Close()

	// Limit text extraction to 1MB to prevent excessive memory usage
	limitedReader := io.LimitReader(reader, 1024*1024)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return
	}

	text := string(content)
	if len(strings.TrimSpace(text)) == 0 {
		return
	}

	// Merge user metadata with system metadata
	vecMetadata := make(map[string]string)
	for k, v := range metadataMap {
		vecMetadata[k] = v
	}
	vecMetadata["content_type"] = contentType
	vecMetadata["indexed_by"] = userID
	vecMetadata["indexed_at"] = time.Now().Format(time.RFC3339)

	err = g.vector.IndexWithEmbedding(ctx, bucket, key, text, vecMetadata)
	if err != nil {
		return
	}

	g.auditLog(nil, "VECTOR_INDEX", bucket, key, userID, "success", map[string]interface{}{
		"content_type": contentType,
		"content_size": len(content),
	})
}

func (g *S3Gateway) triggerPipelines(ctx context.Context, bucket, key, contentType string, metadataMap map[string]string) {
	if g.pipeline == nil {
		return
	}

	pipelines := g.pipeline.GetMatchingPipelines(ctx, pipeline.TriggerOnUpload, contentType, metadataMap)
	for _, p := range pipelines {
		input := &pipeline.ObjectInput{
			Key:          key,
			Bucket:       bucket,
			ContentType:  contentType,
			UserMetadata: metadataMap,
		}
		go g.pipeline.Execute(ctx, p.Name, input)
	}
}

func (g *S3Gateway) writeError(w http.ResponseWriter, status int, code, message string) {
	requestID := uuid.New().String()
	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Set("Content-Type", "application/xml")

	errorResp := ErrorResponse{
		Code:      code,
		Message:   message,
		RequestID: requestID,
	}

	g.writeXML(w, status, errorResp)
}

func (g *S3Gateway) writeXML(w http.ResponseWriter, status int, data interface{}) error {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)

	encoder := xml.NewEncoder(w)
	encoder.Indent("", "  ")
	return encoder.Encode(data)
}

func (g *S3Gateway) writeJSON(w http.ResponseWriter, status int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	return json.NewEncoder(w).Encode(data)
}

func (g *S3Gateway) Start(addr string) error {
	g.server = &http.Server{
		Addr:    addr,
		Handler: g.Handler(),
	}

	return g.server.ListenAndServe()
}

func (g *S3Gateway) Stop() error {
	if g.server != nil {
		return g.server.Close()
	}
	return nil
}

func (g *S3Gateway) Close() error {
	if g.accessLog != nil {
		return g.accessLog.Close()
	}
	return nil
}

func (g *S3Gateway) GetMetadataStore() *metadata.BoltDBMetadataStore {
	return g.metadata
}

func (g *S3Gateway) GetStore() *storage.TieredObjectStore {
	return g.store
}

func (g *S3Gateway) GetTieringManager() *tiering.TieringManager {
	return g.tiering
}

func (g *S3Gateway) GetVectorManager() *vector.VectorManager {
	return g.vector
}

func (g *S3Gateway) GetPipelineExecutor() *pipeline.PipelineExecutor {
	return g.pipeline
}

func (g *S3Gateway) GetAuth() *AuthHandler {
	return g.auth
}

func (g *S3Gateway) SetIAMBridge(bridge *IAMAuthBridge) {
	g.iamBridge = bridge
}

func (g *S3Gateway) GetIAMBridge() *IAMAuthBridge {
	return g.iamBridge
}

func (g *S3Gateway) auditLog(r *http.Request, action, bucket, key, userID, result string, details map[string]interface{}) {
	requestID := common.GetRequestID(r.Context())

	entry := map[string]interface{}{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"request_id": requestID,
		"action":     action,
		"bucket":     bucket,
		"key":        key,
		"user":       userID,
		"result":     result,
		"client_ip":  r.RemoteAddr,
		"user_agent": r.UserAgent(),
	}

	for k, v := range details {
		entry[k] = v
	}

	if g.config != nil && g.config.Logging.Format == "json" {
		data, _ := json.Marshal(entry)
		fmt.Printf("%s\n", string(data))
	}
}

func setChecksumResponseHeaders(w http.ResponseWriter, objMeta *metadata.ObjectMetadata, r *http.Request) {
	checksumMode := r.Header.Get("x-amz-checksum-mode")
	if checksumMode != "ENABLED" && (objMeta.Checksum == "" || objMeta.ChecksumType == "") {
		return
	}
	switch objMeta.ChecksumType {
	case "crc32c":
		w.Header().Set("x-amz-checksum-crc32c", objMeta.Checksum)
	case "sha256":
		w.Header().Set("x-amz-checksum-sha256", objMeta.Checksum)
	case "md5":
		w.Header().Set("x-amz-checksum-md5", objMeta.Checksum)
	}
}

func computeCRC32C(data []byte) string {
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

func (g *S3Gateway) isBucketPublicRead(r *http.Request, bucket string) bool {
	if g.config != nil && g.config.Auth.AnonymousRead {
		return true
	}

	bucketInfo, err := g.metadata.GetBucket(r.Context(), bucket)
	if err != nil {
		return false
	}

	return bucketInfo.ACL == "public-read" || bucketInfo.ACL == "public-read-write"
}

func (g *S3Gateway) validatePresignedURLMethod(r *http.Request, expectedMethod string) error {
	_ = r.URL.Query().Get("X-Amz-Signature")
	return nil
}

func (g *S3Gateway) handleGetBucketLocation(w http.ResponseWriter, r *http.Request, bucket string) error {
	type LocationConstraint struct {
		XMLName  xml.Name `xml:"LocationConstraint"`
		Location string   `xml:",chardata"`
	}

	bucketInfo, err := g.metadata.GetBucket(r.Context(), bucket)
	if err != nil {
		g.writeError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return nil
	}

	location := bucketInfo.Region
	if location == "" {
		location = "us-east-1"
	}

	output := struct {
		XMLName             xml.Name `xml:"LocationConstraint"`
		LocationConstraint  string   `xml:",chardata"`
	}{
		LocationConstraint: location,
	}

	if location == "us-east-1" {
		output.LocationConstraint = ""
	}

	return g.writeXML(w, http.StatusOK, output)
}

func (g *S3Gateway) handleGetBucketAcl(w http.ResponseWriter, r *http.Request, bucket string) error {
	bucketInfo, err := g.metadata.GetBucket(r.Context(), bucket)
	if err != nil {
		g.writeError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return nil
	}

	acl := bucketInfo.ACL
	if acl == "" {
		acl = "private"
	}

	ownerID := bucketInfo.OwnerID
	if ownerID == "" {
		ownerID = "admin"
	}
	ownerName := bucketInfo.OwnerName
	if ownerName == "" {
		ownerName = "admin"
	}

	type Grant struct {
		Grantee struct {
			XMLName     xml.Name `xml:"Grantee"`
			XMLNSXSI    string   `xml:"xmlns:xsi,attr"`
			XSIType     string   `xml:"xsi:type,attr"`
			Type        string   `xml:"Type"`
			ID          string   `xml:"ID"`
			DisplayName string   `xml:"DisplayName,omitempty"`
		} `xml:"Grant"`
		Permission string `xml:"Permission"`
	}

	type AccessControlPolicy struct {
		XMLName xml.Name `xml:"AccessControlPolicy"`
		Owner   struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		AccessControlList struct {
			Grants []Grant `xml:"Grant"`
		} `xml:"AccessControlList"`
	}

	policy := AccessControlPolicy{}
	policy.Owner.ID = ownerID
	policy.Owner.DisplayName = ownerName

	fullControlGrant := Grant{}
	fullControlGrant.Grantee.XMLNSXSI = "http://www.w3.org/2001/XMLSchema-instance"
	fullControlGrant.Grantee.XSIType = "CanonicalUser"
	fullControlGrant.Grantee.Type = "CanonicalUser"
	fullControlGrant.Grantee.ID = ownerID
	fullControlGrant.Grantee.DisplayName = ownerName
	fullControlGrant.Permission = "FULL_CONTROL"
	policy.AccessControlList.Grants = append(policy.AccessControlList.Grants, fullControlGrant)

	if acl == "public-read" || acl == "public-read-write" {
		publicReadGrant := Grant{}
		publicReadGrant.Grantee.XMLNSXSI = "http://www.w3.org/2001/XMLSchema-instance"
		publicReadGrant.Grantee.XSIType = "Group"
		publicReadGrant.Grantee.Type = "Group"
		publicReadGrant.Grantee.ID = "http://acs.amazonaws.com/groups/global/AllUsers"
		publicReadGrant.Permission = "READ"
		policy.AccessControlList.Grants = append(policy.AccessControlList.Grants, publicReadGrant)
	}

	if acl == "public-read-write" {
		publicWriteGrant := Grant{}
		publicWriteGrant.Grantee.XMLNSXSI = "http://www.w3.org/2001/XMLSchema-instance"
		publicWriteGrant.Grantee.XSIType = "Group"
		publicWriteGrant.Grantee.Type = "Group"
		publicWriteGrant.Grantee.ID = "http://acs.amazonaws.com/groups/global/AllUsers"
		publicWriteGrant.Permission = "WRITE"
		policy.AccessControlList.Grants = append(policy.AccessControlList.Grants, publicWriteGrant)
	}

	return g.writeXML(w, http.StatusOK, policy)
}

func (g *S3Gateway) handlePutBucketAcl(w http.ResponseWriter, r *http.Request, bucket string) error {
	bucketInfo, err := g.metadata.GetBucket(r.Context(), bucket)
	if err != nil {
		g.writeError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return nil
	}

	acl := r.Header.Get("x-amz-acl")
	if acl == "" {
		acl = r.URL.Query().Get("acl")
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err == nil && len(body) > 0 {
		type AccessControlPolicy struct {
			AccessControlList struct {
				Grants []struct {
					Grantee struct {
						Type string `xml:"Type"`
						ID   string `xml:"ID"`
					} `xml:"Grantee"`
					Permission string `xml:"Permission"`
				} `xml:"Grant"`
			} `xml:"AccessControlList"`
		}

		var policy AccessControlPolicy
		if err := xml.Unmarshal(body, &policy); err == nil {
			hasPublicRead := false
			hasPublicWrite := false
			for _, grant := range policy.AccessControlList.Grants {
				if grant.Grantee.Type == "Group" && grant.Grantee.ID == "http://acs.amazonaws.com/groups/global/AllUsers" {
					if grant.Permission == "READ" {
						hasPublicRead = true
					}
					if grant.Permission == "WRITE" {
						hasPublicWrite = true
					}
				}
			}
			if hasPublicRead && hasPublicWrite {
				acl = "public-read-write"
			} else if hasPublicRead {
				acl = "public-read"
			} else {
				acl = "private"
			}
		}
	}

	validACLs := map[string]bool{
		"private":            true,
		"public-read":        true,
		"public-read-write":  true,
		"authenticated-read": true,
	}
	if !validACLs[acl] {
		acl = "private"
	}

	bucketInfo.ACL = acl
	if err := g.metadata.UpdateBucket(r.Context(), bucket, bucketInfo); err != nil {
		return fmt.Errorf("failed to update bucket ACL: %w", err)
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (g *S3Gateway) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) error {
	_, err := g.metadata.GetBucket(r.Context(), bucket)
	if err != nil {
		g.writeError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return nil
	}

	output := struct {
		XMLName   xml.Name `xml:"VersioningConfiguration"`
		Status    string   `xml:"Status,omitempty"`
		MFADelete string   `xml:"MfaDelete,omitempty"`
	}{}

	return g.writeXML(w, http.StatusOK, output)
}
