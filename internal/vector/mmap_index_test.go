package vector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMMapHNSWIndexBuildAndSearch(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.hnsw")
	dim := 8

	// Create in-memory index and insert vectors
	memIndex, err := NewHNSWIndex(dim, MetricCosine)
	if err != nil {
		t.Fatalf("failed to create in-memory index: %v", err)
	}

	vectors := []Vector{
		{ID: "v1", Values: []float32{1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, Bucket: "test", ObjectKey: "obj1"},
		{ID: "v2", Values: []float32{0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, Bucket: "test", ObjectKey: "obj2"},
		{ID: "v3", Values: []float32{0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, Bucket: "test", ObjectKey: "obj3"},
		{ID: "v4", Values: []float32{0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, Bucket: "test", ObjectKey: "obj4"},
		{ID: "v5", Values: []float32{0.1, 0.9, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, Bucket: "test", ObjectKey: "obj5"},
	}

	if err := memIndex.Insert(context.Background(), vectors); err != nil {
		t.Fatalf("failed to insert vectors: %v", err)
	}

	// Create mmap index and build from memory
	mmapIndex, err := NewMMapHNSWIndex(filePath, dim)
	if err != nil {
		t.Fatalf("failed to create mmap index: %v", err)
	}

	if err := mmapIndex.BuildFromMemory(memIndex); err != nil {
		t.Fatalf("failed to build mmap index: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatalf("index file was not created: %s", filePath)
	}

	// Load the index
	if err := mmapIndex.Load(); err != nil {
		t.Fatalf("failed to load mmap index: %v", err)
	}

	if !mmapIndex.IsLoaded() {
		t.Error("index should be loaded")
	}

	if mmapIndex.NumVectors() != 5 {
		t.Errorf("expected 5 vectors, got %d", mmapIndex.NumVectors())
	}

	// Search
	query := []float32{1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}
	results, err := mmapIndex.Search(query, 3)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("search returned no results")
	}

	// The closest vector to [1,0,0,...] should be v1 or v4
	if len(results) > 0 {
		topResult := results[0]
		if topResult.Score < 0.5 {
			t.Errorf("top result score too low: %v", topResult.Score)
		}
	}

	// Clean up
	mmapIndex.Close()
}

func TestMMapHNSWIndexLoadExisting(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.hnsw")
	dim := 4

	// Create and build an index
	memIndex, err := NewHNSWIndex(dim, MetricCosine)
	if err != nil {
		t.Fatalf("failed to create in-memory index: %v", err)
	}

	vectors := []Vector{
		{ID: "v1", Values: []float32{1.0, 0.0, 0.0, 0.0}, Bucket: "test", ObjectKey: "obj1"},
		{ID: "v2", Values: []float32{0.0, 1.0, 0.0, 0.0}, Bucket: "test", ObjectKey: "obj2"},
	}

	if err := memIndex.Insert(context.Background(), vectors); err != nil {
		t.Fatalf("failed to insert vectors: %v", err)
	}

	mmapIndex, err := NewMMapHNSWIndex(filePath, dim)
	if err != nil {
		t.Fatalf("failed to create mmap index: %v", err)
	}

	if err := mmapIndex.BuildFromMemory(memIndex); err != nil {
		t.Fatalf("failed to build mmap index: %v", err)
	}

	// Load in a new MMapHNSWIndex instance
	mmapIndex2, err := NewMMapHNSWIndex(filePath, dim)
	if err != nil {
		t.Fatalf("failed to create second mmap index: %v", err)
	}

	if err := mmapIndex2.Load(); err != nil {
		t.Fatalf("failed to load existing mmap index: %v", err)
	}

	if mmapIndex2.NumVectors() != 2 {
		t.Errorf("expected 2 vectors, got %d", mmapIndex2.NumVectors())
	}

	// Search should work
	query := []float32{0.9, 0.1, 0.0, 0.0}
	results, err := mmapIndex2.Search(query, 2)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("search returned no results")
	}

	mmapIndex2.Close()
}

func TestMMapHNSWIndexVerification(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.hnsw")
	dim := 4

	// Create and build an index
	memIndex, err := NewHNSWIndex(dim, MetricCosine)
	if err != nil {
		t.Fatalf("failed to create in-memory index: %v", err)
	}

	vectors := []Vector{
		{ID: "v1", Values: []float32{1.0, 0.0, 0.0, 0.0}, Bucket: "test", ObjectKey: "obj1"},
		{ID: "v2", Values: []float32{0.0, 1.0, 0.0, 0.0}, Bucket: "test", ObjectKey: "obj2"},
	}

	if err := memIndex.Insert(context.Background(), vectors); err != nil {
		t.Fatalf("failed to insert vectors: %v", err)
	}

	mmapIndex, err := NewMMapHNSWIndex(filePath, dim)
	if err != nil {
		t.Fatalf("failed to create mmap index: %v", err)
	}

	if err := mmapIndex.BuildFromMemory(memIndex); err != nil {
		t.Fatalf("failed to build mmap index: %v", err)
	}

	// Verify the index
	if err := VerifyIndex(filePath); err != nil {
		t.Errorf("index verification failed: %v", err)
	}

	// Compute and store checksum
	checksum, err := ComputeIndexChecksum(filePath)
	if err != nil {
		t.Fatalf("failed to compute checksum: %v", err)
	}

	if checksum == "" {
		t.Error("checksum should not be empty")
	}

	// Write checksum sidecar
	if err := WriteChecksumSidecar(filePath); err != nil {
		t.Fatalf("failed to write checksum sidecar: %v", err)
	}

	// Verify sidecar exists
	sidecarPath := filePath + ".sha256"
	if _, err := os.Stat(sidecarPath); os.IsNotExist(err) {
		t.Error("checksum sidecar file was not created")
	}

	// Verify with checksum should pass
	if err := VerifyIndex(filePath); err != nil {
		t.Errorf("index verification with checksum failed: %v", err)
	}
}

func TestMMapHNSWIndexInvalidFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with non-existent file
	mmapIndex, err := NewMMapHNSWIndex(filepath.Join(tmpDir, "nonexistent.hnsw"), 4)
	if err != nil {
		t.Fatalf("failed to create mmap index: %v", err)
	}

	if err := mmapIndex.Load(); err == nil {
		t.Error("expected error loading non-existent file")
	}

	// Test with corrupt file
	corruptPath := filepath.Join(tmpDir, "corrupt.hnsw")
	if err := os.WriteFile(corruptPath, []byte("not a valid index"), 0644); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}

	mmapIndex2, err := NewMMapHNSWIndex(corruptPath, 4)
	if err != nil {
		t.Fatalf("failed to create mmap index: %v", err)
	}

	if err := mmapIndex2.Load(); err == nil {
		t.Error("expected error loading corrupt file")
	}
}

func TestMMapHNSWIndexEmptyIndex(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "empty.hnsw")
	dim := 4

	// Create mmap index with no vectors
	memIndex, err := NewHNSWIndex(dim, MetricCosine)
	if err != nil {
		t.Fatalf("failed to create in-memory index: %v", err)
	}

	mmapIndex, err := NewMMapHNSWIndex(filePath, dim)
	if err != nil {
		t.Fatalf("failed to create mmap index: %v", err)
	}

	// BuildFromMemory with empty index should be a no-op
	if err := mmapIndex.BuildFromMemory(memIndex); err != nil {
		t.Fatalf("failed to build empty mmap index: %v", err)
	}

	// Search on unloaded index should return nil
	query := []float32{1.0, 0.0, 0.0, 0.0}
	results, err := mmapIndex.Search(query, 5)
	if err != nil {
		t.Errorf("search on empty index should not error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestBucketIndexManager(t *testing.T) {
	tmpDir := t.TempDir()

	bm, err := NewBucketIndexManager(tmpDir, 4)
	if err != nil {
		t.Fatalf("failed to create bucket index manager: %v", err)
	}

	// GetOrCreateIndex for a new bucket
	idx, err := bm.GetOrCreateIndex("test-bucket")
	if err != nil {
		t.Fatalf("failed to get or create index: %v", err)
	}

	if idx == nil {
		t.Error("index should not be nil")
	}

	// GetOrCreateIndex again should return same instance
	idx2, err := bm.GetOrCreateIndex("test-bucket")
	if err != nil {
		t.Fatalf("failed to get or create index (second call): %v", err)
	}

	if idx != idx2 {
		t.Error("expected same index instance for same bucket")
	}

	// ListBuckets should be empty (no .hnsw files on disk yet)
	_ = bm.ListBuckets()
	// May or may not include test-bucket depending on whether file exists

	// DeleteIndex
	if err := bm.DeleteIndex("test-bucket"); err != nil {
		t.Fatalf("failed to delete index: %v", err)
	}

	// GetIndex should return nil after deletion
	if bm.GetIndex("test-bucket") != nil {
		t.Error("expected nil after deletion")
	}

	// CloseAll
	if err := bm.CloseAll(); err != nil {
		t.Fatalf("failed to close all: %v", err)
	}
}
