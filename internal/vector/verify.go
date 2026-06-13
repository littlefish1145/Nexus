package vector

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// VerifyIndex verifies the integrity of an mmap index file.
func VerifyIndex(filePath string) error {
	// Check file exists
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open index file: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat index file: %w", err)
	}

	if fi.Size() < headerSize {
		return fmt.Errorf("file too small for header: %d bytes", fi.Size())
	}

	// Read and verify header
	header := make([]byte, headerSize)
	if _, err := f.ReadAt(header, 0); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Check magic
	magic := string(header[0:10])
	if magic != mmapMagic {
		return fmt.Errorf("invalid magic: expected %s, got %s", mmapMagic, magic)
	}

	// Check version
	version := binary.LittleEndian.Uint16(header[10:12])
	if version != mmapVersion {
		return fmt.Errorf("unsupported version: %d", version)
	}

	// Read header fields
	dimension := binary.LittleEndian.Uint32(header[12:16])
	numVectors := binary.LittleEndian.Uint32(header[16:20])
	maxLevel := binary.LittleEndian.Uint32(header[20:24])

	// Verify dimension is reasonable
	if dimension == 0 || dimension > 1536 {
		return fmt.Errorf("invalid dimension: %d", dimension)
	}

	// Verify checksum
	storedChecksum, err := readChecksumSidecar(filePath)
	if err == nil && storedChecksum != "" {
		computedChecksum, err := ComputeIndexChecksum(filePath)
		if err != nil {
			return fmt.Errorf("failed to compute checksum: %w", err)
		}
		if computedChecksum != storedChecksum {
			return fmt.Errorf("checksum mismatch: stored=%s computed=%s", storedChecksum, computedChecksum)
		}
	}

	// Check graph connectivity
	if err := verifyGraphConnectivity(filePath, dimension, numVectors, maxLevel); err != nil {
		return fmt.Errorf("graph connectivity check failed: %w", err)
	}

	return nil
}

// ComputeIndexChecksum computes SHA-256 of the entire index file.
func ComputeIndexChecksum(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open index file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to read index file: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteChecksumSidecar writes the SHA-256 checksum to a .sha256 sidecar file.
func WriteChecksumSidecar(filePath string) error {
	checksum, err := ComputeIndexChecksum(filePath)
	if err != nil {
		return fmt.Errorf("failed to compute checksum: %w", err)
	}

	sidecarPath := filePath + ".sha256"
	if err := os.WriteFile(sidecarPath, []byte(checksum), 0644); err != nil {
		return fmt.Errorf("failed to write checksum sidecar: %w", err)
	}

	return nil
}

// readChecksumSidecar reads the stored checksum from the sidecar file.
func readChecksumSidecar(filePath string) (string, error) {
	sidecarPath := filePath + ".sha256"
	data, err := os.ReadFile(sidecarPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// verifyGraphConnectivity checks that each node's neighbors exist.
func verifyGraphConnectivity(filePath string, dimension, numVectors, maxLevel uint32) error {
	if numVectors == 0 {
		return nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open index file: %w", err)
	}
	defer f.Close()

	// Read the entire file for graph parsing
	fi, err := f.Stat()
	if err != nil {
		return err
	}

	data := make([]byte, fi.Size())
	if _, err := f.ReadAt(data, 0); err != nil {
		return fmt.Errorf("failed to read index data: %w", err)
	}

	// Navigate to graph section
	graphOffset := headerSize + int64(numVectors)*int64(dimension)*4
	offset := graphOffset

	for nodeID := uint32(0); nodeID < numVectors; nodeID++ {
		// Read neighbor data for level 0 (simplified - all nodes at level 0)
		if offset+4 > int64(len(data)) {
			return fmt.Errorf("unexpected end of graph section at node %d", nodeID)
		}

		numNeighbors := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4

		if numNeighbors > 1000 {
			return fmt.Errorf("node %d has too many neighbors: %d", nodeID, numNeighbors)
		}

		for i := uint32(0); i < numNeighbors; i++ {
			if offset+4 > int64(len(data)) {
				return fmt.Errorf("unexpected end of neighbor list at node %d, neighbor %d", nodeID, i)
			}
			neighborID := binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4

			if neighborID >= numVectors {
				return fmt.Errorf("node %d references non-existent neighbor %d (total vectors: %d)", nodeID, neighborID, numVectors)
			}
		}
	}

	return nil
}

// VerifyBucketIndex verifies the index for a specific bucket.
func VerifyBucketIndex(dataDir, bucket string) error {
	filePath := filepath.Join(dataDir, "vector", bucket+".hnsw")
	return VerifyIndex(filePath)
}
