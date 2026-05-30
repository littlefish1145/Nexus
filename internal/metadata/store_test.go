package metadata

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBoltDBMetadataStore(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	store, err := NewBoltDBMetadataStore(dbPath)
	require.NoError(t, err)
	require.NotNil(t, store)

	err = store.Close()
	assert.NoError(t, err)
}

func TestBoltDBMetadataStore_CreateBucket(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	store, err := NewBoltDBMetadataStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	bucket := &BucketInfo{
		Name:      "test-bucket",
		OwnerID:   "user-001",
		OwnerName: "test-user",
		Region:    "us-east-1",
	}

	err = store.CreateBucket(ctx, "test-bucket", bucket)
	assert.NoError(t, err)

	retrieved, err := store.GetBucket(ctx, "test-bucket")
	assert.NoError(t, err)
	assert.Equal(t, "test-bucket", retrieved.Name)
	assert.Equal(t, "user-001", retrieved.OwnerID)
}

func TestBoltDBMetadataStore_DeleteBucket(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	store, err := NewBoltDBMetadataStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	bucket := &BucketInfo{
		Name:      "test-bucket",
		OwnerID:   "user-001",
		OwnerName: "test-user",
		Region:    "us-east-1",
	}

	err = store.CreateBucket(ctx, "test-bucket", bucket)
	require.NoError(t, err)

	err = store.DeleteBucket(ctx, "test-bucket")
	assert.NoError(t, err)

	_, err = store.GetBucket(ctx, "test-bucket")
	assert.Error(t, err)
}

func TestBoltDBMetadataStore_PutObject(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	store, err := NewBoltDBMetadataStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	bucket := &BucketInfo{Name: "test-bucket", OwnerID: "user-001"}
	err = store.CreateBucket(ctx, "test-bucket", bucket)
	require.NoError(t, err)

	obj := &ObjectMetadata{
		Key:         "test/key.txt",
		Bucket:      "test-bucket",
		Size:        1024,
		ContentType: "text/plain",
		ETag:        "abc123",
	}

	err = store.PutObject(ctx, "test-bucket", "test/key.txt", obj)
	assert.NoError(t, err)
}

func TestBoltDBMetadataStore_GetObject(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	store, err := NewBoltDBMetadataStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	bucket := &BucketInfo{Name: "test-bucket", OwnerID: "user-001"}
	err = store.CreateBucket(ctx, "test-bucket", bucket)
	require.NoError(t, err)

	obj := &ObjectMetadata{
		Key:         "test/key.txt",
		Bucket:      "test-bucket",
		Size:        1024,
		ContentType: "text/plain",
		ETag:        "abc123",
	}
	err = store.PutObject(ctx, "test-bucket", "test/key.txt", obj)
	require.NoError(t, err)

	retrieved, err := store.GetObject(ctx, "test-bucket", "test/key.txt")
	assert.NoError(t, err)
	assert.Equal(t, "test/key.txt", retrieved.Key)
	assert.Equal(t, int64(1024), retrieved.Size)
}

func TestBoltDBMetadataStore_DeleteObject(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	store, err := NewBoltDBMetadataStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	bucket := &BucketInfo{Name: "test-bucket", OwnerID: "user-001"}
	err = store.CreateBucket(ctx, "test-bucket", bucket)
	require.NoError(t, err)

	obj := &ObjectMetadata{
		Key:    "test/key.txt",
		Bucket: "test-bucket",
		Size:   1024,
	}
	err = store.PutObject(ctx, "test-bucket", "test/key.txt", obj)
	require.NoError(t, err)

	err = store.DeleteObject(ctx, "test-bucket", "test/key.txt")
	assert.NoError(t, err)

	_, err = store.GetObject(ctx, "test-bucket", "test/key.txt")
	assert.Error(t, err)
}

func TestBoltDBMetadataStore_Stats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	store, err := NewBoltDBMetadataStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	bucket := &BucketInfo{Name: "test-bucket", OwnerID: "user-001"}
	err = store.CreateBucket(ctx, "test-bucket", bucket)
	require.NoError(t, err)

	stats := store.GetStats()
	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.BucketCount, int64(1))
}

func TestBoltDBMetadataStore_ObjectNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	store, err := NewBoltDBMetadataStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	_, err = store.GetObject(ctx, "nonexistent-bucket", "nonexistent-key")
	assert.Error(t, err)
}

func TestBoltDBMetadataStore_BucketNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	store, err := NewBoltDBMetadataStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	_, err = store.GetBucket(ctx, "nonexistent-bucket")
	assert.Error(t, err)
}

func BenchmarkBoltDBMetadataStore_PutObject(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := tmpDir + "/bench.db"

	store, err := NewBoltDBMetadataStore(dbPath)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	store.CreateBucket(ctx, "bench-bucket", &BucketInfo{Name: "bench-bucket", OwnerID: "user-001"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		obj := &ObjectMetadata{
			Key:    "bench/key" + string(rune(i)),
			Bucket: "bench-bucket",
			Size:   1024,
		}
		store.PutObject(ctx, "bench-bucket", obj.Key, obj)
	}
}
