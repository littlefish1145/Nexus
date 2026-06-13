package vector

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"nexus/internal/metadata"
	"nexus/internal/storage"
)

// RebuildManager handles index rebuild operations.
type RebuildManager struct {
	bucketManager *BucketIndexManager
	metaStore     metadata.MetadataStore
	store         *storage.TieredObjectStore
	dimension     int
	fallbackMin   int

	mu     sync.Mutex
	queue  []string // buckets waiting for rebuild
	active bool
}

// NewRebuildManager creates a new rebuild manager.
func NewRebuildManager(
	bucketManager *BucketIndexManager,
	metaStore metadata.MetadataStore,
	store *storage.TieredObjectStore,
	dimension int,
	fallbackMin int,
) *RebuildManager {
	if fallbackMin <= 0 {
		fallbackMin = 5
	}
	return &RebuildManager{
		bucketManager: bucketManager,
		metaStore:     metaStore,
		store:         store,
		dimension:     dimension,
		fallbackMin:   fallbackMin,
	}
}

// RebuildIndex rebuilds the vector index for a specific bucket.
func RebuildIndex(ctx context.Context, bucket string, metaStore metadata.MetadataStore, store *storage.TieredObjectStore, bucketManager *BucketIndexManager, dimension int, fallbackMin int) error {
	if fallbackMin <= 0 {
		fallbackMin = 5
	}

	// List all objects in bucket
	objects, err := metaStore.ListObjects(ctx, bucket, "", 100000)
	if err != nil {
		return fmt.Errorf("failed to list objects: %w", err)
	}

	// Filter text objects and generate embeddings
	var vectors []Vector
	for _, obj := range objects {
		if !IsTextContent(obj.ContentType) {
			continue
		}

		// Read object content
		if store == nil {
			continue
		}

		backend, ok := store.GetTierBackend(0) // hot tier
		if !ok {
			continue
		}

		reader, err := backend.Get(ctx, bucket+"/"+obj.Key)
		if err != nil {
			continue
		}

		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			continue
		}

		// Limit content size
		const maxContentLen = 1 << 20 // 1MB
		if len(data) > maxContentLen {
			data = data[:maxContentLen]
		}

		// Generate embedding
		embedding := GenerateEmbedding(string(data), dimension)

		v := Vector{
			ID:        obj.Key,
			Values:    embedding,
			Bucket:    bucket,
			ObjectKey: obj.Key,
			Dimension: dimension,
			CreatedAt: time.Now(),
			Metadata:  obj.UserMetadata,
		}
		if v.Metadata == nil {
			v.Metadata = make(map[string]string)
		}
		v.Metadata["content_type"] = obj.ContentType
		vectors = append(vectors, v)
	}

	if len(vectors) == 0 {
		return nil
	}

	// Build new HNSW index in memory
	memIndex, err := NewHNSWIndex(dimension, MetricCosine)
	if err != nil {
		return fmt.Errorf("failed to create in-memory index: %w", err)
	}

	if err := memIndex.Insert(ctx, vectors); err != nil {
		return fmt.Errorf("failed to insert vectors: %w", err)
	}

	// Get or create mmap index
	mmapIndex, err := bucketManager.GetOrCreateIndex(bucket)
	if err != nil {
		return fmt.Errorf("failed to get mmap index: %w", err)
	}

	// Keep old index file as fallback
	oldPath := mmapIndex.FilePath()
	backupPath := oldPath + ".bak." + fmt.Sprintf("%d", time.Now().Unix())
	if _, err := os.Stat(oldPath); err == nil {
		os.Rename(oldPath, backupPath)

		// Schedule cleanup of backup after fallback period
		go func() {
			time.Sleep(time.Duration(fallbackMin) * time.Minute)
			os.Remove(backupPath)
		}()
	}

	// Serialize to disk
	if err := mmapIndex.BuildFromMemory(memIndex); err != nil {
		// Try to restore backup
		os.Rename(backupPath, oldPath)
		return fmt.Errorf("failed to build mmap index: %w", err)
	}

	// Load the new index
	if err := mmapIndex.Load(); err != nil {
		return fmt.Errorf("failed to load rebuilt index: %w", err)
	}

	return nil
}

// ScheduleRebuild queues a bucket for index rebuild.
func (r *RebuildManager) ScheduleRebuild(bucket string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Avoid duplicate entries
	for _, b := range r.queue {
		if b == bucket {
			return
		}
	}
	r.queue = append(r.queue, bucket)

	if !r.active {
		r.active = true
		go r.processQueue()
	}
}

// processQueue processes rebuild requests serially.
func (r *RebuildManager) processQueue() {
	for {
		r.mu.Lock()
		if len(r.queue) == 0 {
			r.active = false
			r.mu.Unlock()
			return
		}
		bucket := r.queue[0]
		r.queue = r.queue[1:]
		r.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		err := RebuildIndex(ctx, bucket, r.metaStore, r.store, r.bucketManager, r.dimension, r.fallbackMin)
		cancel()

		if err != nil {
			fmt.Fprintf(os.Stderr, "rebuild failed for bucket %s: %v\n", bucket, err)
		}
	}
}

// RebuildAll rebuilds indexes for all buckets.
func (r *RebuildManager) RebuildAll(ctx context.Context) error {
	buckets := r.bucketManager.ListBuckets()
	for _, bucket := range buckets {
		if err := RebuildIndex(ctx, bucket, r.metaStore, r.store, r.bucketManager, r.dimension, r.fallbackMin); err != nil {
			return fmt.Errorf("failed to rebuild index for bucket %s: %w", bucket, err)
		}
	}
	return nil
}

// LoadExistingIndexes loads all existing mmap indexes on startup.
func LoadExistingIndexes(bucketManager *BucketIndexManager) error {
	buckets := bucketManager.ListBuckets()
	for _, bucket := range buckets {
		idx, err := bucketManager.GetOrCreateIndex(bucket)
		if err != nil {
			continue // skip buckets with corrupt indexes
		}
		if !idx.IsLoaded() {
			idx.Load()
		}
	}
	return nil
}

// FlushDirtyIndexes flushes in-memory indexes to disk.
func FlushDirtyIndexes(bucketManager *BucketIndexManager) error {
	// This is a no-op for mmap indexes since BuildFromMemory already writes to disk.
	// Kept for interface compatibility.
	return nil
}

// Ensure data directory exists for index files.
func ensureDataDir(dataDir string) error {
	vectorDir := filepath.Join(dataDir, "vector")
	return os.MkdirAll(vectorDir, 0755)
}
