package metadata

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChecksumType(t *testing.T) {
	assert.Equal(t, ChecksumType(""), ChecksumNone)
	assert.Equal(t, ChecksumType("CRC32C"), ChecksumCRC32C)
	assert.Equal(t, ChecksumType("CRC64"), ChecksumCRC64)
	assert.Equal(t, ChecksumType("SHA256"), ChecksumSHA256)
}

func TestNewIntegrityChecker(t *testing.T) {
	checker := NewIntegrityChecker(nil)
	assert.NotNil(t, checker)
	assert.True(t, checker.enabled)
}

func TestIntegrityChecker_ComputeChecksum(t *testing.T) {
	checker := NewIntegrityChecker(&ScrubConfig{Enabled: true})

	tests := []struct {
		name     string
		data     []byte
		checksum ChecksumType
	}{
		{"CRC32C empty", []byte{}, ChecksumCRC32C},
		{"CRC32C content", []byte("hello world"), ChecksumCRC32C},
		{"CRC64 empty", []byte{}, ChecksumCRC64},
		{"CRC64 content", []byte("hello world"), ChecksumCRC64},
		{"SHA256 empty", []byte{}, ChecksumSHA256},
		{"SHA256 content", []byte("hello world"), ChecksumSHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.ComputeChecksum(tt.data, tt.checksum)
			assert.NotEmpty(t, result)
		})
	}
}

func TestIntegrityChecker_ComputeChecksum_Consistency(t *testing.T) {
	checker := NewIntegrityChecker(&ScrubConfig{Enabled: true})
	data := []byte("test data for consistency check")

	result1 := checker.ComputeChecksum(data, ChecksumCRC32C)
	result2 := checker.ComputeChecksum(data, ChecksumCRC32C)

	assert.Equal(t, result1, result2)
}

func TestIntegrityChecker_DifferentData(t *testing.T) {
	checker := NewIntegrityChecker(&ScrubConfig{Enabled: true})
	data1 := []byte("first data")
	data2 := []byte("second data")

	result1 := checker.ComputeChecksum(data1, ChecksumCRC32C)
	result2 := checker.ComputeChecksum(data2, ChecksumCRC32C)

	assert.NotEqual(t, result1, result2)
}

func TestScrubConfig(t *testing.T) {
	config := &ScrubConfig{
		Enabled:      true,
		Interval:     24 * 3600 * 1000000000,
		BatchSize:    100,
		Parallelism:  4,
	}

	assert.True(t, config.Enabled)
	assert.Equal(t, 100, config.BatchSize)
	assert.Equal(t, 4, config.Parallelism)
}

func TestScrubState(t *testing.T) {
	state := &ScrubState{
		InProgress:     true,
		ObjectsChecked: 1000,
		ObjectsCorrupt: 5,
		Errors:         10,
	}

	assert.True(t, state.InProgress)
	assert.Equal(t, int64(1000), state.ObjectsChecked)
	assert.Equal(t, int64(5), state.ObjectsCorrupt)
	assert.Equal(t, int64(10), state.Errors)
}

func TestIntegrityStats(t *testing.T) {
	stats := &IntegrityStats{
		ChecksPerformed:      10000,
		ChecksFailed:         50,
		CorruptionsDetected:  5,
		CorruptionsRepaired:  3,
	}

	assert.Equal(t, int64(10000), stats.ChecksPerformed)
	assert.Equal(t, int64(50), stats.ChecksFailed)
	assert.Equal(t, int64(5), stats.CorruptionsDetected)
	assert.Equal(t, int64(3), stats.CorruptionsRepaired)
}

func BenchmarkIntegrityChecker_ComputeChecksum_CRC32C(b *testing.B) {
	data := make([]byte, 1024*1024)
	checker := NewIntegrityChecker(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.ComputeChecksum(data, ChecksumCRC32C)
	}
}

func BenchmarkIntegrityChecker_ComputeChecksum_SHA256(b *testing.B) {
	data := make([]byte, 1024*1024)
	checker := NewIntegrityChecker(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.ComputeChecksum(data, ChecksumSHA256)
	}
}
