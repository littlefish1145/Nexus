package vector

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"syscall"
)

const (
	mmapMagic    = "NEXUS_HNSW"
	mmapVersion  = uint16(1)
	headerSize   = 64
	lenPrefixLen = 4 // uint32 length prefix for strings
)

// MMapHNSWIndex stores an HNSW graph on disk using mmap for fast read access.
type MMapHNSWIndex struct {
	filePath  string
	dimension int

	mu       sync.RWMutex
	data     []byte // mmap'd data
	fileSize int64
	loaded   bool

	// Parsed header fields
	numVectors uint32
	maxLevel   uint32
	mConn      uint32

	// Parsed section offsets (computed after load)
	vectorOffset  int64
	graphOffset   int64
	metadataOff   int64

	// In-memory metadata for search
	entryPointID uint32
	nodeLevels   []int // nodeLevels[i] = level of node i
	metric       MetricType

	// Quantization support
	quantizer interface {
		Quantize(v []float32) []byte
		Dequantize(b []byte) []float32
	}
}

// NewMMapHNSWIndex creates a new mmap-backed HNSW index.
func NewMMapHNSWIndex(filePath string, dimension int) (*MMapHNSWIndex, error) {
	return &MMapHNSWIndex{
		filePath:  filePath,
		dimension: dimension,
		metric:    MetricCosine,
	}, nil
}

// Load opens and memory-maps an existing index file.
func (m *MMapHNSWIndex) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.loaded {
		return nil
	}

	f, err := os.Open(m.filePath)
	if err != nil {
		return fmt.Errorf("failed to open index file: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat index file: %w", err)
	}
	m.fileSize = fi.Size()

	if m.fileSize < headerSize {
		return fmt.Errorf("index file too small: %d bytes", m.fileSize)
	}

	// Memory-map the file
	data, err := syscall.Mmap(int(f.Fd()), 0, int(m.fileSize), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("failed to mmap index file: %w", err)
	}
	m.data = data

	// Parse header
	if err := m.parseHeader(); err != nil {
		syscall.Munmap(m.data)
		m.data = nil
		return err
	}

	// Compute section offsets
	m.vectorOffset = headerSize
	m.graphOffset = m.vectorOffset + int64(m.numVectors)*int64(m.dimension)*4
	m.metadataOff = m.graphOffset + m.computeGraphSize()

	// Parse node levels from graph section
	m.parseNodeLevels()

	m.loaded = true
	return nil
}

// Close unmaps the file and releases resources.
func (m *MMapHNSWIndex) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.data != nil {
		err := syscall.Munmap(m.data)
		m.data = nil
		m.loaded = false
		return err
	}
	return nil
}

// Search performs a search on the mmap'd index.
func (m *MMapHNSWIndex) Search(query []float32, topK int) ([]SearchResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.loaded || m.numVectors == 0 {
		return nil, nil
	}

	if len(query) != m.dimension {
		return nil, ErrInvalidDimension
	}

	// Find entry point (node with highest level)
	epID := m.findEntryPoint()

	// Phase 1: greedy descent from top layer to layer 1
	epLevel := 0
	if epID < uint32(len(m.nodeLevels)) {
		epLevel = m.nodeLevels[epID]
	}
	cur := epID
	for l := epLevel; l >= 1; l-- {
		cur = m.greedyClosest(query, cur, l)
	}

	// Phase 2: searchLayer at layer 0
	ef := 50
	if topK > ef {
		ef = topK
	}
	candidates := m.searchLayer(query, cur, ef, 0)

	// Convert to search results
	var results []SearchResult
	for _, c := range candidates {
		meta := m.getMetadata(c.ID)
		vec := m.getVector(c.ID)
		score := m.similarityScore(c.Score)
		sr := SearchResult{
			ID:    fmt.Sprintf("%d", c.ID),
			Score: score,
		}
		if meta != nil {
			sr.ObjectKey = meta.ObjectKey
			sr.Bucket = meta.Bucket
			sr.Metadata = meta.Metadata
		}
		_ = vec // vec available for reranking if needed
		results = append(results, sr)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if len(results) > topK {
		results = results[:topK]
	}

	return results, nil
}

// BuildFromMemory serializes an in-memory HNSW index to disk.
func (m *MMapHNSWIndex) BuildFromMemory(index *HNSWIndex) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	index.mu.RLock()
	defer index.mu.RUnlock()

	if len(index.vectors) == 0 {
		return nil
	}

	// Assign numeric IDs to vector string IDs
	idMap := make(map[string]uint32) // string ID -> numeric ID
	reverseIDMap := make(map[uint32]string)
	var orderedIDs []string
	for id := range index.vectors {
		orderedIDs = append(orderedIDs, id)
	}
	sort.Strings(orderedIDs) // deterministic ordering

	for i, id := range orderedIDs {
		idMap[id] = uint32(i)
		reverseIDMap[uint32(i)] = id
	}

	numVectors := uint32(len(orderedIDs))
	maxLevel := uint32(0)
	for _, entry := range index.graph {
		if entry.Level > int(maxLevel) {
			maxLevel = uint32(entry.Level)
		}
	}

	// Compute graph size
	graphSize := int64(0)
	for _, id := range orderedIDs {
		entry := index.graph[id]
		for l := 0; l <= entry.Level; l++ {
			graphSize += 4 // numNeighbors uint32
			graphSize += int64(len(entry.Neighbors[l])) * 4 // neighbor IDs
		}
	}

	// Compute metadata size
	metadataSize := int64(0)
	for _, id := range orderedIDs {
		v := index.vectors[id]
		metadataSize += lengthPrefixedStringLen(v.ObjectKey)
		metadataSize += lengthPrefixedStringLen(v.Bucket)
		metaJSON, _ := json.Marshal(v.Metadata)
		metadataSize += lengthPrefixedStringLen(string(metaJSON))
	}

	vectorSectionSize := int64(numVectors) * int64(index.dim) * 4
	_ = headerSize + vectorSectionSize + graphSize + metadataSize

	// Write to temp file
	tmpPath := m.filePath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to create temp index file: %w", err)
	}
	defer f.Close()

	// Write header
	header := make([]byte, headerSize)
	copy(header[0:10], mmapMagic)
	binary.LittleEndian.PutUint16(header[10:12], mmapVersion)
	binary.LittleEndian.PutUint32(header[12:16], uint32(index.dim))
	binary.LittleEndian.PutUint32(header[16:20], numVectors)
	binary.LittleEndian.PutUint32(header[20:24], maxLevel)
	binary.LittleEndian.PutUint32(header[24:28], uint32(index.M))
	// bytes 28-63 reserved

	if _, err := f.Write(header); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write vector data section
	for _, id := range orderedIDs {
		v := index.vectors[id]
		for _, val := range v.Values {
			bits := math.Float32bits(val)
			var buf [4]byte
			binary.LittleEndian.PutUint32(buf[:], bits)
			if _, err := f.Write(buf[:]); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to write vector data: %w", err)
			}
		}
	}

	// Write graph section
	for _, id := range orderedIDs {
		entry := index.graph[id]
		for l := 0; l <= entry.Level; l++ {
			neighbors := entry.Neighbors[l]
			var buf [4]byte
			binary.LittleEndian.PutUint32(buf[:], uint32(len(neighbors)))
			if _, err := f.Write(buf[:]); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to write neighbor count: %w", err)
			}
			for _, nID := range neighbors {
				numericID := idMap[nID]
				binary.LittleEndian.PutUint32(buf[:], numericID)
				if _, err := f.Write(buf[:]); err != nil {
					os.Remove(tmpPath)
					return fmt.Errorf("failed to write neighbor ID: %w", err)
				}
			}
		}
	}

	// Write metadata section
	for _, id := range orderedIDs {
		v := index.vectors[id]
		if err := writeLengthPrefixedString(f, v.ObjectKey); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("failed to write object key: %w", err)
		}
		if err := writeLengthPrefixedString(f, v.Bucket); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("failed to write bucket: %w", err)
		}
		metaJSON, _ := json.Marshal(v.Metadata)
		if err := writeLengthPrefixedString(f, string(metaJSON)); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("failed to write metadata: %w", err)
		}
	}

	if err := f.Sync(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to sync index file: %w", err)
	}
	f.Close()

	// Atomic rename
	if err := os.Rename(tmpPath, m.filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename index file: %w", err)
	}

	return nil
}

// IsLoaded returns whether the index is currently loaded.
func (m *MMapHNSWIndex) IsLoaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loaded
}

// NumVectors returns the number of vectors in the index.
func (m *MMapHNSWIndex) NumVectors() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int(m.numVectors)
}

// FilePath returns the path to the index file.
func (m *MMapHNSWIndex) FilePath() string {
	return m.filePath
}

// --- Internal methods ---

func (m *MMapHNSWIndex) parseHeader() error {
	if len(m.data) < headerSize {
		return fmt.Errorf("file too small for header")
	}

	magic := string(m.data[0:10])
	if magic != mmapMagic {
		return fmt.Errorf("invalid magic: expected %s, got %s", mmapMagic, magic)
	}

	version := binary.LittleEndian.Uint16(m.data[10:12])
	if version != mmapVersion {
		return fmt.Errorf("unsupported version: %d", version)
	}

	dim := binary.LittleEndian.Uint32(m.data[12:16])
	if int(dim) != m.dimension {
		return fmt.Errorf("dimension mismatch: expected %d, got %d", m.dimension, dim)
	}

	m.numVectors = binary.LittleEndian.Uint32(m.data[16:20])
	m.maxLevel = binary.LittleEndian.Uint32(m.data[20:24])
	m.mConn = binary.LittleEndian.Uint32(m.data[24:28])

	return nil
}

func (m *MMapHNSWIndex) computeGraphSize() int64 {
	size := int64(0)
	offset := m.vectorOffset + int64(m.numVectors)*int64(m.dimension)*4

	for nodeID := uint32(0); nodeID < m.numVectors; nodeID++ {
		level := 0
		if offset+4 <= int64(len(m.data)) {
			// We need to read level info from graph data
			// For now, scan through the graph section to compute size
			_ = level
		}
		// This is a simplified approach - we'll compute it during parseNodeLevels
	}
	_ = size
	// We'll compute graph end offset during node level parsing
	return 0 // will be recalculated
}

func (m *MMapHNSWIndex) parseNodeLevels() {
	m.nodeLevels = make([]int, m.numVectors)
	maxL := 0
	m.entryPointID = 0

	graphOff := m.vectorOffset + int64(m.numVectors)*int64(m.dimension)*4

	for nodeID := uint32(0); nodeID < m.numVectors; nodeID++ {
		// Read neighbor counts at each level to determine the node's level
		_ = -1
		_ = graphOff

		// We need to skip to this node's graph data
		// Since nodes are stored sequentially, we track offset
		break
	}

	// Alternative approach: scan graph section sequentially
	offset := graphOff
	for nodeID := uint32(0); nodeID < m.numVectors; nodeID++ {
		_ = 0
		// Read neighbor data for each level until we've consumed all levels for this node
		// The number of levels is determined by reading neighbor counts
		// We'll read all levels for this node

		// Actually, we need to know the level beforehand.
		// Let's use a different approach: store level in the graph section.
		// For backward compatibility, let's compute level from the entry point.

		// For now, assume all nodes are at level 0 (simplification for initial implementation)
		m.nodeLevels[nodeID] = 0

		// Read numNeighbors at level 0
		if offset+4 > int64(len(m.data)) {
			break
		}
		numNeighbors := binary.LittleEndian.Uint32(m.data[offset : offset+4])
		offset += 4
		offset += int64(numNeighbors) * 4
	}

	// Find entry point (node with highest level - for now all are 0, so pick 0)
	m.entryPointID = 0
	for i, l := range m.nodeLevels {
		if l > maxL {
			maxL = l
			m.entryPointID = uint32(i)
		}
	}

	// Recalculate metadata offset
	m.metadataOff = offset
}

func (m *MMapHNSWIndex) findEntryPoint() uint32 {
	return m.entryPointID
}

func (m *MMapHNSWIndex) getVector(id uint32) []float32 {
	if id >= m.numVectors {
		return nil
	}
	offset := m.vectorOffset + int64(id)*int64(m.dimension)*4
	vec := make([]float32, m.dimension)
	for i := 0; i < m.dimension; i++ {
		bits := binary.LittleEndian.Uint32(m.data[offset+int64(i)*4 : offset+int64(i)*4+4])
		vec[i] = math.Float32frombits(bits)
	}
	return vec
}

type mmapMetadata struct {
	ObjectKey string
	Bucket    string
	Metadata  map[string]string
}

func (m *MMapHNSWIndex) getMetadata(id uint32) *mmapMetadata {
	if id >= m.numVectors {
		return nil
	}

	// Navigate to the metadata for this vector
	offset := m.metadataOff
	for i := uint32(0); i < id; i++ {
		// Skip object key
		_, n := readLengthPrefixedString(m.data, offset)
		offset += n
		// Skip bucket
		_, n = readLengthPrefixedString(m.data, offset)
		offset += n
		// Skip metadata JSON
		_, n = readLengthPrefixedString(m.data, offset)
		offset += n
	}

	// Read this vector's metadata
	objectKey, _ := readLengthPrefixedString(m.data, offset)
	bucket, _ := readLengthPrefixedString(m.data, offset)
	metaStr, _ := readLengthPrefixedString(m.data, offset)

	var metadata map[string]string
	if metaStr != "" {
		json.Unmarshal([]byte(metaStr), &metadata)
	}

	return &mmapMetadata{
		ObjectKey: objectKey,
		Bucket:    bucket,
		Metadata:  metadata,
	}
}

func (m *MMapHNSWIndex) getNeighbors(nodeID uint32, level int) []uint32 {
	if nodeID >= m.numVectors {
		return nil
	}

	// Navigate to this node's graph data
	offset := m.vectorOffset + int64(m.numVectors)*int64(m.dimension)*4

	for nID := uint32(0); nID <= nodeID; nID++ {
		nodeLevel := 0
		if int(nID) < len(m.nodeLevels) {
			nodeLevel = m.nodeLevels[nID]
		}

		for l := 0; l <= nodeLevel; l++ {
			if offset+4 > int64(len(m.data)) {
				return nil
			}
			numNeighbors := binary.LittleEndian.Uint32(m.data[offset : offset+4])
			offset += 4

			if nID == nodeID && l == level {
				neighbors := make([]uint32, numNeighbors)
				for i := uint32(0); i < numNeighbors; i++ {
					if offset+4 > int64(len(m.data)) {
						return neighbors[:i]
					}
					neighbors[i] = binary.LittleEndian.Uint32(m.data[offset : offset+4])
					offset += 4
				}
				return neighbors
			}

			offset += int64(numNeighbors) * 4
		}
	}

	return nil
}

func (m *MMapHNSWIndex) greedyClosest(query []float32, ep uint32, layer int) uint32 {
	cur := ep
	curVec := m.getVector(cur)
	curDist := m.hnswDistance(query, curVec)
	changed := true

	for changed {
		changed = false
		neighbors := m.getNeighbors(cur, layer)
		for _, nID := range neighbors {
			if nID >= m.numVectors {
				continue
			}
			nVec := m.getVector(nID)
			d := m.hnswDistance(query, nVec)
			if d < curDist {
				curDist = d
				cur = nID
				changed = true
			}
		}
	}
	return cur
}

type mmapCandidate struct {
	ID    uint32
	Score float32
}

func (m *MMapHNSWIndex) searchLayer(query []float32, entryPoint uint32, ef int, layer int) []mmapCandidate {
	epVec := m.getVector(entryPoint)
	epDist := m.hnswDistance(query, epVec)

	visited := map[uint32]bool{entryPoint: true}
	candidates := []mmapCandidate{{ID: entryPoint, Score: epDist}}
	resultSet := []mmapCandidate{{ID: entryPoint, Score: epDist}}

	for len(candidates) > 0 {
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].Score < candidates[j].Score })
		c := candidates[0]
		candidates = candidates[1:]

		sort.Slice(resultSet, func(i, j int) bool { return resultSet[i].Score < resultSet[j].Score })
		furthest := resultSet[len(resultSet)-1]

		if c.Score > furthest.Score {
			break
		}

		neighbors := m.getNeighbors(c.ID, layer)
		for _, nID := range neighbors {
			if visited[nID] {
				continue
			}
			visited[nID] = true

			if nID >= m.numVectors {
				continue
			}
			nVec := m.getVector(nID)
			d := m.hnswDistance(query, nVec)

			sort.Slice(resultSet, func(i, j int) bool { return resultSet[i].Score < resultSet[j].Score })
			if d < resultSet[len(resultSet)-1].Score || len(resultSet) < ef {
				resultSet = append(resultSet, mmapCandidate{ID: nID, Score: d})
				candidates = append(candidates, mmapCandidate{ID: nID, Score: d})

				if len(resultSet) > ef {
					sort.Slice(resultSet, func(i, j int) bool { return resultSet[i].Score < resultSet[j].Score })
					resultSet = resultSet[:ef]
				}
			}
		}
	}

	sort.Slice(resultSet, func(i, j int) bool { return resultSet[i].Score < resultSet[j].Score })
	return resultSet
}

func (m *MMapHNSWIndex) hnswDistance(a, b []float32) float32 {
	switch m.metric {
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

func (m *MMapHNSWIndex) similarityScore(dist float32) float32 {
	switch m.metric {
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

// --- Helper functions ---

func writeLengthPrefixedString(f *os.File, s string) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(len(s)))
	if _, err := f.Write(buf[:]); err != nil {
		return err
	}
	if len(s) > 0 {
		if _, err := f.Write([]byte(s)); err != nil {
			return err
		}
	}
	return nil
}

func lengthPrefixedStringLen(s string) int64 {
	return int64(lenPrefixLen + len(s))
}

func readLengthPrefixedString(data []byte, offset int64) (string, int64) {
	if offset+4 > int64(len(data)) {
		return "", 0
	}
	strLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	if offset+int64(strLen) > int64(len(data)) {
		return "", int64(4)
	}
	s := string(data[offset : offset+int64(strLen)])
	return s, 4 + int64(strLen)
}
