package vector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
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
	entryPoint     string
	M              int
	maxM0          int
	stats          IndexStats
}

type HNSWEntry struct {
	ID        string
	Level     int
	Neighbors [][]string // Neighbors[layer] = list of neighbor IDs at that layer
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
		entryPoint:      "",
		M:               16,
		maxM0:           32,
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
			Neighbors: make([][]string, level+1),
		}
		for l := 0; l <= level; l++ {
			entry.Neighbors[l] = make([]string, 0)
		}
		h.graph[v.ID] = entry

		if h.entryPoint == "" {
			h.entryPoint = v.ID
			h.stats.TotalVectors++
			continue
		}

		h.insertIntoGraph(v.ID, v.Values, level)
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

	if h.entryPoint == "" || len(h.vectors) == 0 {
		return nil, nil
	}

	// Phase 1: greedy descent from top layer to layer 1
	ep := h.entryPoint
	epEntry := h.graph[ep]
	for l := epEntry.Level; l >= 1; l-- {
		ep = h.greedyClosest(query.Values, ep, l)
	}

	// Phase 2: searchLayer at layer 0 with ef=max(efSearch, topK)
	ef := h.efSearch
	if topK > ef {
		ef = topK
	}
	candidates := h.searchLayer(query.Values, ep, ef, 0)

	// Apply metadata filters and convert to results
	var searchResults []SearchResult
	for _, c := range candidates {
		v, ok := h.vectors[c.ID]
		if !ok {
			continue
		}
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

		score := h.similarityScore(c.Score)
		searchResults = append(searchResults, SearchResult{
			ID:        c.ID,
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

// hnswDistance returns a distance where lower = more similar.
func (h *HNSWIndex) hnswDistance(a, b []float32) float32 {
	switch h.metric {
	case MetricCosine:
		return 1 - cosineSimilarity(a, b)
	case MetricEuclidean:
		return euclideanDistance(a, b)
	case MetricDotProduct:
		return -dotProduct(a, b)
	default:
		return 1 - cosineSimilarity(a, b)
	}
}

// similarityScore converts distance to similarity (higher = more similar).
func (h *HNSWIndex) similarityScore(dist float32) float32 {
	switch h.metric {
	case MetricCosine:
		return 1 - dist
	case MetricEuclidean:
		return 1 / (1 + dist)
	case MetricDotProduct:
		return -dist
	default:
		return 1 - dist
	}
}

// greedyClosest does greedy search to find closest node at a given layer.
func (h *HNSWIndex) greedyClosest(query []float32, ep string, layer int) string {
	cur := ep
	curDist := h.hnswDistance(query, h.vectors[cur].Values)
	changed := true
	for changed {
		changed = false
		entry := h.graph[cur]
		if layer < len(entry.Neighbors) {
			for _, nID := range entry.Neighbors[layer] {
				if nVec, ok := h.vectors[nID]; ok {
					d := h.hnswDistance(query, nVec.Values)
					if d < curDist {
						curDist = d
						cur = nID
						changed = true
					}
				}
			}
		}
	}
	return cur
}

// searchLayer performs beam search at a layer, returns ef closest candidates sorted by distance ascending.
func (h *HNSWIndex) searchLayer(query []float32, entryPoint string, ef int, layer int) []searchCandidate {
	epDist := h.hnswDistance(query, h.vectors[entryPoint].Values)

	visited := map[string]bool{entryPoint: true}
	candidates := []searchCandidate{{ID: entryPoint, Score: epDist}}
	resultSet := []searchCandidate{{ID: entryPoint, Score: epDist}}

	for len(candidates) > 0 {
		// pop closest candidate
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].Score < candidates[j].Score })
		c := candidates[0]
		candidates = candidates[1:]

		// get furthest in result set
		sort.Slice(resultSet, func(i, j int) bool { return resultSet[i].Score < resultSet[j].Score })
		furthest := resultSet[len(resultSet)-1]

		if c.Score > furthest.Score {
			break
		}

		entry := h.graph[c.ID]
		if layer < len(entry.Neighbors) {
			for _, nID := range entry.Neighbors[layer] {
				if visited[nID] {
					continue
				}
				visited[nID] = true

				if nVec, ok := h.vectors[nID]; ok {
					d := h.hnswDistance(query, nVec.Values)

					sort.Slice(resultSet, func(i, j int) bool { return resultSet[i].Score < resultSet[j].Score })
					if d < resultSet[len(resultSet)-1].Score || len(resultSet) < ef {
						resultSet = append(resultSet, searchCandidate{ID: nID, Score: d})
						candidates = append(candidates, searchCandidate{ID: nID, Score: d})

						if len(resultSet) > ef {
							sort.Slice(resultSet, func(i, j int) bool { return resultSet[i].Score < resultSet[j].Score })
							resultSet = resultSet[:ef]
						}
					}
				}
			}
		}
	}

	sort.Slice(resultSet, func(i, j int) bool { return resultSet[i].Score < resultSet[j].Score })
	return resultSet
}

// selectNeighbors selects top M neighbors from candidates.
func (h *HNSWIndex) selectNeighbors(queryValues []float32, candidates []searchCandidate, M int) []string {
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Score < candidates[j].Score })
	if len(candidates) > M {
		candidates = candidates[:M]
	}
	result := make([]string, len(candidates))
	for i, c := range candidates {
		result[i] = c.ID
	}
	return result
}

// makeCandidates creates candidate list from IDs.
func (h *HNSWIndex) makeCandidates(neighborIDs []string, queryValues []float32) []searchCandidate {
	candidates := make([]searchCandidate, 0, len(neighborIDs))
	for _, id := range neighborIDs {
		if v, ok := h.vectors[id]; ok {
			candidates = append(candidates, searchCandidate{
				ID:    id,
				Score: h.hnswDistance(queryValues, v.Values),
			})
		}
	}
	return candidates
}

// insertIntoGraph is the core HNSW insert algorithm.
func (h *HNSWIndex) insertIntoGraph(id string, values []float32, level int) {
	ep := h.entryPoint
	epEntry := h.graph[ep]
	L := epEntry.Level

	// Phase 1: greedy descent from top layer to level+1
	for l := L; l > level; l-- {
		ep = h.greedyClosest(values, ep, l)
	}

	// Phase 2: search and connect from min(level, L) down to 0
	for l := minInt(level, L); l >= 0; l-- {
		candidates := h.searchLayer(values, ep, h.efConstruction, l)

		maxConn := h.M
		if l == 0 {
			maxConn = h.maxM0
		}

		neighbors := h.selectNeighbors(values, candidates, maxConn)

		// Set neighbors for new node at this layer
		h.graph[id].Neighbors[l] = neighbors

		// Add bidirectional connections
		for _, nID := range neighbors {
			nEntry := h.graph[nID]
			if l < len(nEntry.Neighbors) {
				nEntry.Neighbors[l] = append(nEntry.Neighbors[l], id)

				// Prune if exceeds max connections
				if len(nEntry.Neighbors[l]) > maxConn {
					nCands := h.makeCandidates(nEntry.Neighbors[l], h.vectors[nID].Values)
					nEntry.Neighbors[l] = h.selectNeighbors(h.vectors[nID].Values, nCands, maxConn)
				}
			}
		}

		// Update entry point for next layer
		if len(candidates) > 0 {
			ep = candidates[0].ID
		}
	}

	// Update entry point if new node has higher level
	if level > L {
		h.entryPoint = id
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
			// Remove from all neighbor lists of other nodes
			entry := h.graph[id]
			for l := 0; l <= entry.Level; l++ {
				for _, nID := range entry.Neighbors[l] {
					if nEntry, ok := h.graph[nID]; ok {
						if l < len(nEntry.Neighbors) {
							filtered := make([]string, 0, len(nEntry.Neighbors[l]))
							for _, nid := range nEntry.Neighbors[l] {
								if nid != id {
									filtered = append(filtered, nid)
								}
							}
							nEntry.Neighbors[l] = filtered
						}
					}
				}
			}

			delete(h.vectors, id)
			delete(h.graph, id)
			h.stats.TotalVectors--

			// If was entry point, find new entry point (highest level node)
			if h.entryPoint == id {
				h.entryPoint = ""
				maxL := -1
				for nid, nEntry := range h.graph {
					if nEntry.Level > maxL {
						maxL = nEntry.Level
						h.entryPoint = nid
					}
				}
			}
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
	mu                 sync.RWMutex
	vectors            map[string]*Vector
	clusters           []centroid
	clusterAssignments map[string]int   // vector ID -> cluster index
	invertedLists      map[int][]string // cluster index -> list of vector IDs
	codebooks          [][][]float32    // [subquantizer][256][subDim] PQ codebooks
	pqCodes            map[string][]uint8 // vector ID -> PQ codes
	dim                int
	numClusters        int
	numSubquantizers   int
	subDim             int // dim / numSubquantizers
	nprobe             int // number of clusters to search
	metric             MetricType
	trained            bool
	stats              IndexStats
}

type centroid struct {
	Center []float32
	Count  int
	IDs    []string // vector IDs in this cluster
}

func NewIVFPQIndex(dim, numClusters, pqSize int, metric MetricType) (*IVFPQIndex, error) {
	if dim <= 0 || dim > 1536 {
		return nil, ErrInvalidDimension
	}

	if metric == "" {
		metric = MetricCosine
	}

	subDim := dim / pqSize
	if subDim < 1 {
		subDim = 1
	}

	nprobe := numClusters
	if nprobe > 10 {
		nprobe = 10
	}
	if nprobe < 1 {
		nprobe = 1
	}

	return &IVFPQIndex{
		vectors:            make(map[string]*Vector),
		clusters:           make([]centroid, numClusters),
		clusterAssignments: make(map[string]int),
		invertedLists:      make(map[int][]string),
		codebooks:          make([][][]float32, pqSize),
		pqCodes:            make(map[string][]uint8),
		dim:                dim,
		numClusters:        numClusters,
		numSubquantizers:   pqSize,
		subDim:             subDim,
		nprobe:             nprobe,
		metric:             metric,
		trained:            false,
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

		if len(v.Values) != ivf.dim {
			return fmt.Errorf("vector dimension mismatch: expected %d, got %d", ivf.dim, len(v.Values))
		}

		ivf.vectors[v.ID] = v

		if ivf.trained {
			clusterIdx := ivf.assignToCluster(v.Values)
			ivf.clusterAssignments[v.ID] = clusterIdx
			ivf.invertedLists[clusterIdx] = append(ivf.invertedLists[clusterIdx], v.ID)
			ivf.clusters[clusterIdx].IDs = append(ivf.clusters[clusterIdx].IDs, v.ID)
			ivf.clusters[clusterIdx].Count++
			codes := ivf.encodePQ(v.Values)
			ivf.pqCodes[v.ID] = codes
		}

		ivf.stats.TotalVectors++
	}

	return nil
}

func (ivf *IVFPQIndex) Search(ctx context.Context, query Vector, topK int, filters map[string]string) ([]SearchResult, error) {
	ivf.mu.RLock()
	defer ivf.mu.RUnlock()

	startTime := time.Now()

	if len(query.Values) != ivf.dim {
		return nil, ErrInvalidDimension
	}

	if !ivf.trained || len(ivf.vectors) == 0 {
		// Fall back to brute-force search
		return ivf.bruteForceSearch(query, topK, filters, startTime)
	}

	// Find nprobe nearest clusters to query
	type clusterDist struct {
		idx  int
		dist float32
	}
	clusterDists := make([]clusterDist, 0, len(ivf.clusters))
	for i, c := range ivf.clusters {
		if len(c.Center) == 0 {
			continue
		}
		dist := ivf.ivfDistance(query.Values, c.Center)
		clusterDists = append(clusterDists, clusterDist{idx: i, dist: dist})
	}

	sort.Slice(clusterDists, func(i, j int) bool {
		return clusterDists[i].dist < clusterDists[j].dist
	})

	if len(clusterDists) > ivf.nprobe {
		clusterDists = clusterDists[:ivf.nprobe]
	}

	// Precompute PQ distance tables if PQ is trained
	pqReady := len(ivf.codebooks) > 0 && len(ivf.codebooks[0]) > 0
	var distTables [][]float32 // [subquantizer][256]
	if pqReady {
		distTables = make([][]float32, ivf.numSubquantizers)
		for s := 0; s < ivf.numSubquantizers; s++ {
			distTables[s] = make([]float32, 256)
			start := s * ivf.subDim
			end := start + ivf.subDim
			if end > len(query.Values) {
				end = len(query.Values)
			}
			querySub := query.Values[start:end]
			for c := 0; c < len(ivf.codebooks[s]); c++ {
				distTables[s][c] = ivf.ivfDistance(querySub, ivf.codebooks[s][c])
			}
		}
	}

	// Collect candidates from nprobe clusters
	type candidate struct {
		id    string
		dist  float32
		vec   *Vector
	}
	candidates := make([]candidate, 0)
	seen := make(map[string]bool)

	for _, cd := range clusterDists {
		ids, ok := ivf.invertedLists[cd.idx]
		if !ok {
			continue
		}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true

			v, ok := ivf.vectors[id]
			if !ok {
				continue
			}

			// Apply metadata filters
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

			var dist float32
			if pqReady {
				codes, hasCode := ivf.pqCodes[id]
				if hasCode {
					dist = ivf.pqApproximateDistance(distTables, codes)
				} else {
					dist = ivf.ivfDistance(query.Values, v.Values)
				}
			} else {
				dist = ivf.ivfDistance(query.Values, v.Values)
			}

			candidates = append(candidates, candidate{id: id, dist: dist, vec: v})
		}
	}

	// If we got fewer candidates than topK, also scan remaining clusters
	if len(candidates) < topK {
		for id, v := range ivf.vectors {
			if seen[id] {
				continue
			}

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

			dist := ivf.ivfDistance(query.Values, v.Values)
			candidates = append(candidates, candidate{id: id, dist: dist, vec: v})
		}
	}

	// Convert distances to similarity scores and sort
	results := make([]SearchResult, 0, len(candidates))
	for _, c := range candidates {
		score := ivf.ivfSimilarityScore(c.dist)
		results = append(results, SearchResult{
			ID:        c.id,
			Score:     score,
			Metadata:  c.vec.Metadata,
			Bucket:    c.vec.Bucket,
			ObjectKey: c.vec.ObjectKey,
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

func (ivf *IVFPQIndex) bruteForceSearch(query Vector, topK int, filters map[string]string, startTime time.Time) ([]SearchResult, error) {
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

		dist := ivf.ivfDistance(query.Values, v.Values)
		score := ivf.ivfSimilarityScore(dist)
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

func (ivf *IVFPQIndex) Delete(ctx context.Context, ids []string) error {
	ivf.mu.Lock()
	defer ivf.mu.Unlock()

	for _, id := range ids {
		if clusterIdx, ok := ivf.clusterAssignments[id]; ok {
			// Remove from invertedLists
			il := ivf.invertedLists[clusterIdx]
			for j, vid := range il {
				if vid == id {
					ivf.invertedLists[clusterIdx] = append(il[:j], il[j+1:]...)
					break
				}
			}
			// Remove from cluster IDs
			cids := ivf.clusters[clusterIdx].IDs
			for j, cid := range cids {
				if cid == id {
					ivf.clusters[clusterIdx].IDs = append(cids[:j], cids[j+1:]...)
					break
				}
			}
			ivf.clusters[clusterIdx].Count--
			delete(ivf.clusterAssignments, id)
		}
		delete(ivf.pqCodes, id)
		if _, ok := ivf.vectors[id]; ok {
			delete(ivf.vectors, id)
			ivf.stats.TotalVectors--
		}
	}

	return nil
}

func (ivf *IVFPQIndex) Build(ctx context.Context) error {
	ivf.mu.Lock()
	defer ivf.mu.Unlock()

	if len(ivf.vectors) == 0 {
		ivf.stats.LastBuiltAt = time.Now()
		return nil
	}

	// Collect all vectors
	allIDs := make([]string, 0, len(ivf.vectors))
	allVecs := make([][]float32, 0, len(ivf.vectors))
	for id, v := range ivf.vectors {
		allIDs = append(allIDs, id)
		allVecs = append(allVecs, v.Values)
	}

	numVecs := len(allVecs)
	k := ivf.numClusters
	if k > numVecs {
		k = numVecs
	}

	// K-Means training for cluster centers
	centers := ivf.kmeansTrain(allVecs, k, 20)

	// Assign each vector to nearest cluster center
	ivf.clusters = make([]centroid, k)
	for i := range ivf.clusters {
		ivf.clusters[i].Center = centers[i]
		ivf.clusters[i].IDs = make([]string, 0)
	}

	ivf.clusterAssignments = make(map[string]int)
	ivf.invertedLists = make(map[int][]string)

	for i, id := range allIDs {
		vec := allVecs[i]
		bestCluster := 0
		bestDist := float32(math.MaxFloat32)
		for ci, c := range ivf.clusters {
			d := ivf.ivfDistance(vec, c.Center)
			if d < bestDist {
				bestDist = d
				bestCluster = ci
			}
		}
		ivf.clusterAssignments[id] = bestCluster
		ivf.invertedLists[bestCluster] = append(ivf.invertedLists[bestCluster], id)
		ivf.clusters[bestCluster].IDs = append(ivf.clusters[bestCluster].IDs, id)
		ivf.clusters[bestCluster].Count++
	}

	// PQ training
	pqK := 256
	if numVecs < pqK {
		pqK = numVecs
	}

	ivf.codebooks = make([][][]float32, ivf.numSubquantizers)
	for s := 0; s < ivf.numSubquantizers; s++ {
		start := s * ivf.subDim
		end := start + ivf.subDim
		if end > ivf.dim {
			end = ivf.dim
		}

		// Extract sub-vectors
		subVecs := make([][]float32, numVecs)
		for j, vec := range allVecs {
			subVecs[j] = vec[start:end]
		}

		// Run K-Means on sub-vectors
		codebook := ivf.kmeansTrain(subVecs, pqK, 20)
		ivf.codebooks[s] = codebook
	}

	// Encode all vectors into PQ codes
	ivf.pqCodes = make(map[string][]uint8)
	for i, id := range allIDs {
		ivf.pqCodes[id] = ivf.encodePQ(allVecs[i])
	}

	ivf.trained = true
	ivf.stats.LastBuiltAt = time.Now()

	return nil
}

func (ivf *IVFPQIndex) GetStats() IndexStats {
	ivf.mu.RLock()
	defer ivf.mu.RUnlock()

	return ivf.stats
}

// ivfDistance computes a distance where lower = more similar.
// For cosine: 1 - cosineSimilarity
// For euclidean: euclidean distance
// For dot_product: -dotProduct
func (ivf *IVFPQIndex) ivfDistance(a, b []float32) float32 {
	switch ivf.metric {
	case MetricCosine:
		return 1 - cosineSimilarity(a, b)
	case MetricEuclidean:
		return euclideanDistance(a, b)
	case MetricDotProduct:
		return -dotProduct(a, b)
	default:
		return 1 - cosineSimilarity(a, b)
	}
}

// ivfSimilarityScore converts a distance (lower = more similar) to a similarity score (higher = more similar).
func (ivf *IVFPQIndex) ivfSimilarityScore(dist float32) float32 {
	switch ivf.metric {
	case MetricCosine:
		return 1 - dist // back to cosine similarity
	case MetricEuclidean:
		return 1 / (1 + dist) // inverse distance
	case MetricDotProduct:
		return -dist // back to dot product
	default:
		return 1 - dist
	}
}

// assignToCluster finds the nearest cluster for a given vector.
func (ivf *IVFPQIndex) assignToCluster(values []float32) int {
	bestCluster := 0
	bestDist := float32(math.MaxFloat32)
	for i, c := range ivf.clusters {
		if len(c.Center) == 0 {
			continue
		}
		d := ivf.ivfDistance(values, c.Center)
		if d < bestDist {
			bestDist = d
			bestCluster = i
		}
	}
	return bestCluster
}

// encodePQ encodes a vector into PQ codes.
func (ivf *IVFPQIndex) encodePQ(values []float32) []uint8 {
	codes := make([]uint8, ivf.numSubquantizers)
	for s := 0; s < ivf.numSubquantizers; s++ {
		start := s * ivf.subDim
		end := start + ivf.subDim
		if end > len(values) {
			end = len(values)
		}
		subVec := values[start:end]

		bestCode := uint8(0)
		bestDist := float32(math.MaxFloat32)
		for c, centroid := range ivf.codebooks[s] {
			d := ivf.ivfDistance(subVec, centroid)
			if d < bestDist {
				bestDist = d
				bestCode = uint8(c)
			}
		}
		codes[s] = bestCode
	}
	return codes
}

// pqApproximateDistance computes approximate distance using precomputed PQ distance tables.
func (ivf *IVFPQIndex) pqApproximateDistance(distTables [][]float32, codes []uint8) float32 {
	var totalDist float32
	for s := 0; s < ivf.numSubquantizers && s < len(codes); s++ {
		if int(codes[s]) < len(distTables[s]) {
			totalDist += distTables[s][codes[s]]
		}
	}
	return totalDist
}

// kmeansTrain runs K-Means clustering and returns cluster centers.
func (ivf *IVFPQIndex) kmeansTrain(data [][]float32, k int, maxIter int) [][]float32 {
	n := len(data)
	if n == 0 || k <= 0 {
		return nil
	}
	if k > n {
		k = n
	}

	dim := len(data[0])

	// Initialize centers by picking k random vectors
	perm := globalRand.Perm(n)
	centers := make([][]float32, k)
	for i := 0; i < k; i++ {
		centers[i] = make([]float32, dim)
		copy(centers[i], data[perm[i]])
	}

	assignments := make([]int, n)

	for iter := 0; iter < maxIter; iter++ {
		// Assignment step
		changed := false
		for i, vec := range data {
			bestCluster := 0
			bestDist := float32(math.MaxFloat32)
			for ci, center := range centers {
				d := ivf.ivfDistance(vec, center)
				if d < bestDist {
					bestDist = d
					bestCluster = ci
				}
			}
			if assignments[i] != bestCluster {
				assignments[i] = bestCluster
				changed = true
			}
		}

		if !changed {
			break
		}

		// Update step: recompute centers
		counts := make([]int, k)
		sums := make([][]float32, k)
		for i := range sums {
			sums[i] = make([]float32, dim)
		}

		for i, vec := range data {
			c := assignments[i]
			counts[c]++
			for j := range vec {
				sums[c][j] += vec[j]
			}
		}

		for i := 0; i < k; i++ {
			if counts[i] > 0 {
				for j := range centers[i] {
					centers[i][j] = sums[i][j] / float32(counts[i])
				}
			}
			// If a cluster has no members, keep its center unchanged
		}
	}

	return centers
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
	mmapEnabled      bool
	bucketManager    *BucketIndexManager
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
	// Security settings
	AutoIndex           bool
	MaxSearchTopK       int
	MaxQueryLength      int
	RequireAuth         bool
	AllowedContentTypes []string
	MaxIndexContentSize int64
	// MMap/disk-based index settings
	MMapEnabled      bool
	QuantizationType string // "none", "sq", "pq"
	PQSubquantizers  int
	IndexDataDir     string
	RebuildInterval  string
	FallbackMinutes  int
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
		mmapEnabled:       config.MMapEnabled,
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
	// Flush mmap indexes to disk if dirty
	if vm.mmapEnabled && vm.bucketManager != nil {
		FlushDirtyIndexes(vm.bucketManager)
		vm.bucketManager.CloseAll()
	}

	if vm.embeddingProvider != nil {
		return vm.embeddingProvider.Close()
	}
	return nil
}

// InitMMap initializes the mmap-based bucket index manager.
// Should be called after NewVectorManager when mmap is enabled.
func (vm *VectorManager) InitMMap(dataDir string) error {
	if !vm.mmapEnabled {
		return nil
	}

	bm, err := NewBucketIndexManager(dataDir, vm.dim)
	if err != nil {
		return fmt.Errorf("failed to create bucket index manager: %w", err)
	}
	vm.bucketManager = bm

	// Load existing mmap indexes
	if err := LoadExistingIndexes(bm); err != nil {
		return fmt.Errorf("failed to load existing indexes: %w", err)
	}

	return nil
}

// BucketManager returns the bucket index manager (nil if mmap not enabled).
func (vm *VectorManager) BucketManager() *BucketIndexManager {
	return vm.bucketManager
}

// IsMMapEnabled returns whether mmap-based indexing is enabled.
func (vm *VectorManager) IsMMapEnabled() bool {
	return vm.mmapEnabled
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

// IsTextContent checks if a content type is suitable for text-based embedding.
// Exported for use in gateway and tests.
func IsTextContent(contentType string) bool {
	textPrefixes := []string{
		"text/",
		"application/json",
		"application/xml",
		"application/javascript",
		"application/x-yaml",
		"application/markdown",
	}
	for _, prefix := range textPrefixes {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	textSuffixes := []string{"+json", "+xml", "+yaml"}
	for _, suffix := range textSuffixes {
		if strings.Contains(contentType, suffix) {
			return true
		}
	}
	return false
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
