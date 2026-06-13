package vector

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// BucketIndexManager manages per-bucket HNSW index files.
type BucketIndexManager struct {
	dataDir   string
	dimension int
	indexes   map[string]*MMapHNSWIndex // bucket -> index
	mu        sync.RWMutex
}

// NewBucketIndexManager creates a new bucket index manager.
func NewBucketIndexManager(dataDir string, dimension int) (*BucketIndexManager, error) {
	vectorDir := filepath.Join(dataDir, "vector")
	if err := os.MkdirAll(vectorDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create vector index directory: %w", err)
	}

	return &BucketIndexManager{
		dataDir:   dataDir,
		dimension: dimension,
		indexes:   make(map[string]*MMapHNSWIndex),
	}, nil
}

// GetOrCreateIndex returns the mmap index for a bucket, creating one if needed.
func (b *BucketIndexManager) GetOrCreateIndex(bucket string) (*MMapHNSWIndex, error) {
	b.mu.RLock()
	if idx, ok := b.indexes[bucket]; ok {
		b.mu.RUnlock()
		return idx, nil
	}
	b.mu.RUnlock()

	b.mu.Lock()
	defer b.mu.Unlock()

	// Double-check after acquiring write lock
	if idx, ok := b.indexes[bucket]; ok {
		return idx, nil
	}

	filePath := b.indexFilePath(bucket)
	idx, err := NewMMapHNSWIndex(filePath, b.dimension)
	if err != nil {
		return nil, fmt.Errorf("failed to create mmap index for bucket %s: %w", bucket, err)
	}

	// Try to load existing index file
	if _, err := os.Stat(filePath); err == nil {
		if err := idx.Load(); err != nil {
			// Failed to load, create a fresh index
			idx, err = NewMMapHNSWIndex(filePath, b.dimension)
			if err != nil {
				return nil, err
			}
		}
	}

	b.indexes[bucket] = idx
	return idx, nil
}

// DeleteIndex removes the index for a bucket.
func (b *BucketIndexManager) DeleteIndex(bucket string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if idx, ok := b.indexes[bucket]; ok {
		idx.Close()
		delete(b.indexes, bucket)
	}

	filePath := b.indexFilePath(bucket)
	sha256Path := filePath + ".sha256"

	// Remove index file
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove index file: %w", err)
	}

	// Remove checksum sidecar
	if err := os.Remove(sha256Path); err != nil && !os.IsNotExist(err) {
		// Non-fatal
	}

	return nil
}

// ListBuckets returns the names of buckets that have index files on disk.
func (b *BucketIndexManager) ListBuckets() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	vectorDir := filepath.Join(b.dataDir, "vector")
	entries, err := os.ReadDir(vectorDir)
	if err != nil {
		// Return in-memory buckets as fallback
		buckets := make([]string, 0, len(b.indexes))
		for bucket := range b.indexes {
			buckets = append(buckets, bucket)
		}
		sort.Strings(buckets)
		return buckets
	}

	buckets := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) == ".hnsw" {
			bucket := name[:len(name)-5] // strip .hnsw
			buckets = append(buckets, bucket)
		}
	}
	sort.Strings(buckets)
	return buckets
}

// CloseAll closes all open indexes.
func (b *BucketIndexManager) CloseAll() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var firstErr error
	for bucket, idx := range b.indexes {
		if err := idx.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(b.indexes, bucket)
	}
	return firstErr
}

// GetIndex returns the loaded index for a bucket, or nil if not loaded.
func (b *BucketIndexManager) GetIndex(bucket string) *MMapHNSWIndex {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.indexes[bucket]
}

// indexFilePath returns the file path for a bucket's index.
func (b *BucketIndexManager) indexFilePath(bucket string) string {
	return filepath.Join(b.dataDir, "vector", bucket+".hnsw")
}
