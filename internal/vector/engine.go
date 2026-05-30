package vector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

var globalRand = func() *rand.Rand {
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}()

var (
	ErrVectorNotFound     = errors.New("vector not found")
	ErrInvalidDimension  = errors.New("invalid vector dimension")
	ErrIndexNotInitialized = errors.New("index not initialized")
	ErrInvalidMetric     = errors.New("invalid metric type")
)

type MetricType string

const (
	MetricCosine     MetricType = "cosine"
	MetricEuclidean  MetricType = "euclidean"
	MetricDotProduct MetricType = "dot_product"
)

type VectorIndex interface {
	Insert(ctx context.Context, vectors []Vector) error
	Search(ctx context.Context, query Vector, topK int, filters map[string]string) ([]SearchResult, error)
	Delete(ctx context.Context, ids []string) error
	Build(ctx context.Context) error
	GetStats() IndexStats
}

type Vector struct {
	ID        string
	Values    []float32
	Metadata  map[string]string
	Bucket    string
	ObjectKey string
	Dimension int
	CreatedAt time.Time
	Checksum  string
}

type SearchResult struct {
	ID        string
	Score     float32
	Metadata  map[string]string
	Bucket    string
	ObjectKey string
}

type IndexStats struct {
	TotalVectors int64
	HotVectors   int64
	ColdVectors  int64
	MemoryUsageMB float64
	IndexType   string
	Dimension   int
	LastBuiltAt time.Time
	QueryCount  int64
	AvgLatencyMs float64
}

type HNSWIndex struct {
	mu             sync.RWMutex
	vectors        map[string]*Vector
	graph          map[string]*HNSWEntry
	dim            int
	maxLevel       int
	efConstruction int
	efSearch       int
	ml             float32
	metric         MetricType
	stats          IndexStats
}

type HNSWEntry struct {
	ID        string
	Level     int
	Neighbors []string
}

func NewHNSWIndex(dim int, metric MetricType) (*HNSWIndex, error) {
	if dim <= 0 || dim > 1536 {
		return nil, ErrInvalidDimension
	}

	if metric == "" {
		metric = MetricCosine
	}

	return &HNSWIndex{
		vectors:         make(map[string]*Vector),
		graph:           make(map[string]*HNSWEntry),
		dim:             dim,
		maxLevel:        16,
		efConstruction:  200,
		efSearch:        50,
		ml:              0.6931,
		metric:          metric,
		stats: IndexStats{
			Dimension:   dim,
			IndexType:   "HNSW",
			LastBuiltAt: time.Now(),
		},
	}, nil
}

func (h *HNSWIndex) Insert(ctx context.Context, vectors []Vector) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i := range vectors {
		v := &vectors[i]
		if v.ID == "" {
			v.ID = uuid.New().String()
		}
		if v.Dimension == 0 {
			v.Dimension = h.dim
		}
		if v.CreatedAt.IsZero() {
			v.CreatedAt = time.Now()
		}

		if len(v.Values) != h.dim {
			return fmt.Errorf("vector dimension mismatch: expected %d, got %d", h.dim, len(v.Values))
		}

		h.vectors[v.ID] = v

		level := h.randomLevel()
		entry := &HNSWEntry{
			ID:        v.ID,
			Level:     level,
			Neighbors: make([]string, level+1),
		}

		for l := 0; l <= level; l++ {
			entry.Neighbors[l] = ""
		}
		h.graph[v.ID] = entry

		h.stats.TotalVectors++
	}

	return nil
}

func (h *HNSWIndex) randomLevel() int {
	l := 0
	for {
		r := globalRand.Float64()
		if r < math.Exp(-float64(l)/float64(h.ml)) {
			break
		}
		l++
		if l > h.maxLevel {
			l = h.maxLevel
			break
		}
	}
	return l
}

func (h *HNSWIndex) Search(ctx context.Context, query Vector, topK int, filters map[string]string) ([]SearchResult, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	startTime := time.Now()

	if len(query.Values) != h.dim {
		return nil, ErrInvalidDimension
	}

	var searchResults []SearchResult

	for id, v := range h.vectors {
		if len(filters) > 0 {
			match := true
			for k, val := range filters {
				if v.Metadata == nil {
					match = false
					break
				}
				if v.Metadata[k] != val {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		score := h.calculateDistance(query.Values, v.Values)
		searchResults = append(searchResults, SearchResult{
			ID:        id,
			Score:     score,
			Metadata:  v.Metadata,
			Bucket:    v.Bucket,
			ObjectKey: v.ObjectKey,
		})
	}

	sort.Slice(searchResults, func(i, j int) bool {
		return searchResults[i].Score > searchResults[j].Score
	})

	if len(searchResults) > topK {
		searchResults = searchResults[:topK]
	}

	h.stats.QueryCount++
	latency := time.Since(startTime).Seconds() * 1000
	h.stats.AvgLatencyMs = (h.stats.AvgLatencyMs*float64(h.stats.QueryCount-1) + latency) / float64(h.stats.QueryCount)

	return searchResults, nil
}

func (h *HNSWIndex) calculateDistance(a, b []float32) float32 {
	switch h.metric {
	case MetricCosine:
		return cosineSimilarity(a, b)
	case MetricEuclidean:
		return euclideanDistance(a, b)
	case MetricDotProduct:
		return dotProduct(a, b)
	default:
		return cosineSimilarity(a, b)
	}
}

func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dotProd, normA, normB float32
	for i := range a {
		dotProd += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProd / (float32(math.Sqrt(float64(normA))) * float32(math.Sqrt(float64(normB))))
}

func euclideanDistance(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return float32(math.MaxFloat32)
	}

	var sum float32
	for i := range a {
		diff := a[i] - b[i]
		sum += diff * diff
	}
	return float32(math.Sqrt(float64(sum)))
}

func dotProduct(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var sum float32
	for i := range a {
		sum += a[i] * b[i]
	}
	return sum
}

func (h *HNSWIndex) Delete(ctx context.Context, ids []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, id := range ids {
		if _, ok := h.vectors[id]; ok {
			delete(h.vectors, id)
			delete(h.graph, id)
			h.stats.TotalVectors--
		}
	}

	return nil
}

func (h *HNSWIndex) Build(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.stats.LastBuiltAt = time.Now()

	return nil
}

func (h *HNSWIndex) GetStats() IndexStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	stats := h.stats
	stats.MemoryUsageMB = float64(len(h.vectors)) * float64(h.dim) * 4 / (1024 * 1024)

	return stats
}

type searchCandidate struct {
	ID    string
	Score float32
}

type IVFPQIndex struct {
	mu                sync.RWMutex
	vectors           map[string]*Vector
	clusters          []centroid
	clusterAssignments map[string]int
	codebooks         [][]float32
	dim               int
	numClusters       int
	productQuantization int
	metric            MetricType
	stats             IndexStats
}

type centroid struct {
	Center []float32
	Count  int
}

func NewIVFPQIndex(dim, numClusters, pqSize int, metric MetricType) (*IVFPQIndex, error) {
	if dim <= 0 || dim > 1536 {
		return nil, ErrInvalidDimension
	}

	if metric == "" {
		metric = MetricCosine
	}

	return &IVFPQIndex{
		vectors:            make(map[string]*Vector),
		clusters:           make([]centroid, numClusters),
		clusterAssignments: make(map[string]int),
		codebooks:          make([][]float32, pqSize),
		dim:                dim,
		numClusters:        numClusters,
		productQuantization: pqSize,
		metric:             metric,
		stats: IndexStats{
			Dimension: dim,
			IndexType: "IVF-PQ",
		},
	}, nil
}

func (ivf *IVFPQIndex) Insert(ctx context.Context, vectors []Vector) error {
	ivf.mu.Lock()
	defer ivf.mu.Unlock()

	for i := range vectors {
		v := &vectors[i]
		if v.ID == "" {
			v.ID = uuid.New().String()
		}
		if v.Dimension == 0 {
			v.Dimension = ivf.dim
		}
		if v.CreatedAt.IsZero() {
			v.CreatedAt = time.Now()
		}

		ivf.vectors[v.ID] = v

		clusterIdx := ivf.assignToNearestCluster(v.Values)
		ivf.clusterAssignments[v.ID] = clusterIdx
		ivf.clusters[clusterIdx].Count++

		ivf.stats.TotalVectors++
	}

	return nil
}

func (ivf *IVFPQIndex) assignToNearestCluster(values []float32) int {
	minDist := float32(math.MaxFloat32)
	bestCluster := 0

	for i, c := range ivf.clusters {
		if len(c.Center) == 0 {
			ivf.clusters[i].Center = make([]float32, len(values))
			copy(ivf.clusters[i].Center, values)
			return i
		}

		var dist float32
		switch ivf.metric {
		case MetricEuclidean:
			dist = euclideanDistance(values, c.Center)
		case MetricCosine:
			dist = 1 - cosineSimilarity(values, c.Center)
		case MetricDotProduct:
			dist = -dotProduct(values, c.Center)
		}

		if dist < minDist {
			minDist = dist
			bestCluster = i
		}
	}

	return bestCluster
}

func (ivf *IVFPQIndex) Search(ctx context.Context, query Vector, topK int, filters map[string]string) ([]SearchResult, error) {
	ivf.mu.RLock()
	defer ivf.mu.RUnlock()

	startTime := time.Now()

	if len(query.Values) != ivf.dim {
		return nil, ErrInvalidDimension
	}

	var results []SearchResult

	for id, v := range ivf.vectors {
		if len(filters) > 0 {
			match := true
			for k, val := range filters {
				if v.Metadata == nil {
					match = false
					break
				}
				if v.Metadata[k] != val {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		score := calculateDistance(ivf.metric, query.Values, v.Values)
		results = append(results, SearchResult{
			ID:        id,
			Score:     score,
			Metadata:  v.Metadata,
			Bucket:    v.Bucket,
			ObjectKey: v.ObjectKey,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if len(results) > topK {
		results = results[:topK]
	}

	ivf.stats.QueryCount++
	latency := time.Since(startTime).Seconds() * 1000
	ivf.stats.AvgLatencyMs = (ivf.stats.AvgLatencyMs*float64(ivf.stats.QueryCount-1) + latency) / float64(ivf.stats.QueryCount)

	return results, nil
}

func calculateDistance(metric MetricType, a, b []float32) float32 {
	switch metric {
	case MetricCosine:
		return cosineSimilarity(a, b)
	case MetricEuclidean:
		return euclideanDistance(a, b)
	case MetricDotProduct:
		return dotProduct(a, b)
	default:
		return cosineSimilarity(a, b)
	}
}

func (ivf *IVFPQIndex) Delete(ctx context.Context, ids []string) error {
	ivf.mu.Lock()
	defer ivf.mu.Unlock()

	for _, id := range ids {
		if clusterIdx, ok := ivf.clusterAssignments[id]; ok {
			ivf.clusters[clusterIdx].Count--
		}
		delete(ivf.vectors, id)
		delete(ivf.clusterAssignments, id)
		ivf.stats.TotalVectors--
	}

	return nil
}

func (ivf *IVFPQIndex) Build(ctx context.Context) error {
	ivf.mu.Lock()
	defer ivf.mu.Unlock()

	for i := range ivf.clusters {
		if ivf.clusters[i].Count > 0 && len(ivf.clusters[i].Center) > 0 {
			count := float32(ivf.clusters[i].Count)
			for j := range ivf.clusters[i].Center {
				ivf.clusters[i].Center[j] /= count
			}
		}
	}

	ivf.stats.LastBuiltAt = time.Now()

	return nil
}

func (ivf *IVFPQIndex) GetStats() IndexStats {
	ivf.mu.RLock()
	defer ivf.mu.RUnlock()

	return ivf.stats
}

type VectorManager struct {
	mu               sync.RWMutex
	hotIndex         VectorIndex
	coldIndex        VectorIndex
	dim              int
	metric           MetricType
	config           *VectorConfig
	vectorMap        map[string]*Vector
	cache            *QueryCache
	embeddingProvider EmbeddingProvider
}

type VectorConfig struct {
	Enabled        bool
	HotIndexSize   int64
	ColdIndexSize  int64
	Dimension      int
	IndexType      string
	MetricType     string
	MaxVectors     int64
	QueryCacheSize int
	QueryCacheTTL  time.Duration
	EmbeddingProvider string
	EmbeddingModelPath string
	EmbeddingAPIEndpoint string
	EmbeddingAPIKey     string
	EmbeddingModelName  string
}

type QueryCache struct {
	mu      sync.RWMutex
	cache   map[string]*cachedResult
	maxSize int
	ttl     time.Duration
}

type cachedResult struct {
	Results   []SearchResult
	CreatedAt time.Time
}

func NewQueryCache(maxSize int, ttl time.Duration) *QueryCache {
	return &QueryCache{
		cache:   make(map[string]*cachedResult),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func (qc *QueryCache) get(key string) ([]SearchResult, bool) {
	qc.mu.RLock()
	defer qc.mu.RUnlock()

	if result, ok := qc.cache[key]; ok {
		if time.Since(result.CreatedAt) < qc.ttl {
			return result.Results, true
		}
	}

	return nil, false
}

func (qc *QueryCache) set(key string, results []SearchResult) {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if len(qc.cache) >= qc.maxSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range qc.cache {
			if oldestTime.IsZero() || v.CreatedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.CreatedAt
			}
		}
		delete(qc.cache, oldestKey)
	}

	qc.cache[key] = &cachedResult{
		Results:   results,
		CreatedAt: time.Now(),
	}
}

func NewVectorManager(config *VectorConfig) (*VectorManager, error) {
	dim := config.Dimension
	if dim == 0 {
		dim = 768
	}

	metric := MetricType(config.MetricType)
	if metric == "" {
		metric = MetricCosine
	}

	var hotIndex, coldIndex VectorIndex
	var err error

	indexType := config.IndexType
	if indexType == "" {
		indexType = "hnsw"
	}

	if indexType == "hnsw" {
		hotIndex, err = NewHNSWIndex(dim, metric)
		if err != nil {
			return nil, err
		}
		coldIndex, err = NewHNSWIndex(dim, metric)
		if err != nil {
			return nil, err
		}
	} else {
		hotIndex, err = NewIVFPQIndex(dim, 1024, 64, metric)
		if err != nil {
			return nil, err
		}
		coldIndex, err = NewIVFPQIndex(dim, 1024, 64, metric)
		if err != nil {
			return nil, err
		}
	}

	cacheSize := config.QueryCacheSize
	if cacheSize == 0 {
		cacheSize = 10000
	}

	cacheTTL := config.QueryCacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	var embeddingProvider EmbeddingProvider
	if config.Enabled {
		embConfig := &EmbeddingConfig{
			Provider:      config.EmbeddingProvider,
			ModelPath:     config.EmbeddingModelPath,
			APIEndpoint:   config.EmbeddingAPIEndpoint,
			APIKey:        config.EmbeddingAPIKey,
			ModelName:     config.EmbeddingModelName,
			Dimension:     dim,
		}
		embeddingProvider, err = NewEmbeddingProvider(embConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create embedding provider: %w", err)
		}
	}

	return &VectorManager{
		hotIndex:          hotIndex,
		coldIndex:         coldIndex,
		dim:               dim,
		metric:            metric,
		config:            config,
		vectorMap:         make(map[string]*Vector),
		cache:             NewQueryCache(cacheSize, cacheTTL),
		embeddingProvider: embeddingProvider,
	}, nil
}

func (vm *VectorManager) IndexVector(ctx context.Context, v *Vector) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if v.ID == "" {
		v.ID = uuid.New().String()
	}
	if v.Dimension == 0 {
		v.Dimension = vm.dim
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}

	mapKey := v.Bucket + "/" + v.ObjectKey
	vm.vectorMap[mapKey] = v

	if v.CreatedAt.After(time.Now().Add(-7 * 24 * time.Hour)) {
		return vm.hotIndex.Insert(ctx, []Vector{*v})
	}

	return vm.coldIndex.Insert(ctx, []Vector{*v})
}

func (vm *VectorManager) IndexVectors(ctx context.Context, vectors []Vector) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	now := time.Now()
	sevenDaysAgo := now.Add(-7 * 24 * time.Hour)

	var hotVectors, coldVectors []Vector

	for i := range vectors {
		v := &vectors[i]
		if v.ID == "" {
			v.ID = uuid.New().String()
		}
		if v.Dimension == 0 {
			v.Dimension = vm.dim
		}
		if v.CreatedAt.IsZero() {
			v.CreatedAt = now
		}

		mapKey := v.Bucket + "/" + v.ObjectKey
		vm.vectorMap[mapKey] = v

		if v.CreatedAt.After(sevenDaysAgo) {
			hotVectors = append(hotVectors, *v)
		} else {
			coldVectors = append(coldVectors, *v)
		}
	}

	if len(hotVectors) > 0 {
		if err := vm.hotIndex.Insert(ctx, hotVectors); err != nil {
			return err
		}
	}

	if len(coldVectors) > 0 {
		return vm.coldIndex.Insert(ctx, coldVectors)
	}

	return nil
}

func (vm *VectorManager) Search(ctx context.Context, query Vector, topK int, filters map[string]string) ([]SearchResult, error) {
	cacheKey := vm.generateCacheKey(query, topK, filters)
	if results, ok := vm.cache.get(cacheKey); ok {
		return results, nil
	}

	vm.mu.RLock()
	hotIdx := vm.hotIndex
	coldIdx := vm.coldIndex
	vm.mu.RUnlock()

	hotResults, err := hotIdx.Search(ctx, query, topK, filters)
	if err != nil {
		return nil, fmt.Errorf("hot index search failed: %w", err)
	}

	coldResults, err := coldIdx.Search(ctx, query, topK, filters)
	if err != nil {
		return nil, fmt.Errorf("cold index search failed: %w", err)
	}

	results := append(hotResults, coldResults...)

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if len(results) > topK {
		results = results[:topK]
	}

	vm.cache.set(cacheKey, results)

	return results, nil
}

func (vm *VectorManager) generateCacheKey(query Vector, topK int, filters map[string]string) string {
	key := fmt.Sprintf("%v:%d", query.Values[:minInt(10, len(query.Values))], topK)
	for k, v := range filters {
		key += fmt.Sprintf(":%s=%s", k, v)
	}
	return key
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (vm *VectorManager) DeleteVector(ctx context.Context, bucket, objectKey string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	mapKey := bucket + "/" + objectKey
	v, ok := vm.vectorMap[mapKey]
	if !ok {
		return ErrVectorNotFound
	}

	delete(vm.vectorMap, mapKey)

	if err := vm.hotIndex.Delete(ctx, []string{v.ID}); err != nil {
		return err
	}
	if err := vm.coldIndex.Delete(ctx, []string{v.ID}); err != nil {
		return err
	}

	return nil
}

func (vm *VectorManager) GetVector(ctx context.Context, bucket, objectKey string) (*Vector, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	mapKey := bucket + "/" + objectKey
	v, ok := vm.vectorMap[mapKey]
	if !ok {
		return nil, ErrVectorNotFound
	}

	return v, nil
}

func (vm *VectorManager) RebuildIndex(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if err := vm.hotIndex.Build(ctx); err != nil {
		return fmt.Errorf("failed to build hot index: %w", err)
	}

	if err := vm.coldIndex.Build(ctx); err != nil {
		return fmt.Errorf("failed to build cold index: %w", err)
	}

	return nil
}

func (vm *VectorManager) GetStats() map[string]IndexStats {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return map[string]IndexStats{
		"hot":  vm.hotIndex.GetStats(),
		"cold": vm.coldIndex.GetStats(),
	}
}

func (vm *VectorManager) GenerateEmbedding(ctx context.Context, input string) ([]float32, error) {
	if vm.embeddingProvider != nil {
		return vm.embeddingProvider.GenerateEmbedding(ctx, input)
	}
	return GenerateEmbedding(input, vm.dim), nil
}

func (vm *VectorManager) GenerateEmbeddingBatch(ctx context.Context, inputs []string) ([][]float32, error) {
	if vm.embeddingProvider != nil {
		return vm.embeddingProvider.GenerateEmbeddingBatch(ctx, inputs)
	}

	results := make([][]float32, len(inputs))
	for i, input := range inputs {
		results[i] = GenerateEmbedding(input, vm.dim)
	}
	return results, nil
}

func (vm *VectorManager) IndexWithEmbedding(ctx context.Context, bucket, objectKey, text string, metadata map[string]string) error {
	embedding, err := vm.GenerateEmbedding(ctx, text)
	if err != nil {
		return fmt.Errorf("failed to generate embedding: %w", err)
	}

	vector := &Vector{
		ID:        uuid.New().String(),
		Values:    embedding,
		Metadata:  metadata,
		Bucket:    bucket,
		ObjectKey: objectKey,
		Dimension: vm.dim,
		CreatedAt: time.Now(),
	}

	return vm.IndexVector(ctx, vector)
}

func (vm *VectorManager) SearchByText(ctx context.Context, queryText string, topK int, filters map[string]string) ([]SearchResult, error) {
	embedding, err := vm.GenerateEmbedding(ctx, queryText)
	if err != nil {
		return nil, fmt.Errorf("failed to generate query embedding: %w", err)
	}

	query := Vector{
		Values:    embedding,
		Dimension: vm.dim,
	}

	return vm.Search(ctx, query, topK, filters)
}

func (vm *VectorManager) Close() error {
	if vm.embeddingProvider != nil {
		return vm.embeddingProvider.Close()
	}
	return nil
}

func EncodeVector(v []float32) []byte {
	if len(v) == 0 {
		return nil
	}

	data := make([]byte, 4+len(v)*4)
	binary.LittleEndian.PutUint32(data[:4], uint32(len(v)))
	for i, f := range v {
		bits := math.Float32bits(f)
		binary.LittleEndian.PutUint32(data[4+i*4:4+i*4+4], bits)
	}

	return data
}

func DecodeVector(data []byte) []float32 {
	if len(data) < 4 {
		return nil
	}

	dim := binary.LittleEndian.Uint32(data[:4])
	if int(dim)*4+4 != len(data) {
		return nil
	}

	v := make([]float32, dim)
	for i := uint32(0); i < dim; i++ {
		bits := binary.LittleEndian.Uint32(data[4+i*4 : 4+i*4+4])
		v[i] = math.Float32frombits(bits)
	}

	return v
}

func GenerateEmbedding(text string, dim int) []float32 {
	v := make([]float32, dim)
	hash := uint32(0)
	for i, c := range text {
		hash = hash*31 + uint32(c) + uint32(i)
	}

	for i := 0; i < dim; i++ {
		v[i] = float32(hash%1000) / 1000.0
		hash = hash*1103515245 + 12345
	}

	return v
}
