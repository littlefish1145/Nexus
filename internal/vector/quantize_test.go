package vector

import (
	"math"
	"testing"
)

func TestScalarQuantizerRoundTrip(t *testing.T) {
	vectors := [][]float32{
		{0.1, 0.2, 0.3, 0.4, 0.5},
		{0.5, 0.4, 0.3, 0.2, 0.1},
		{0.0, 0.25, 0.5, 0.75, 1.0},
		{-0.5, 0.0, 0.5, 1.0, 1.5},
	}

	sq := TrainScalarQuantizer(vectors)

	for i, v := range vectors {
		quantized := sq.Quantize(v)
		dequantized := sq.Dequantize(quantized)

		if len(quantized) != len(v) {
			t.Errorf("vector %d: quantized length mismatch: got %d, want %d", i, len(quantized), len(v))
			continue
		}

		if len(dequantized) != len(v) {
			t.Errorf("vector %d: dequantized length mismatch: got %d, want %d", i, len(dequantized), len(v))
			continue
		}

		// Check error is within acceptable bounds for int8 quantization
		// For SQ with 256 levels, worst-case error is scale/2 which for small values
		// can be a few percent relative error. Use 5% threshold.
		for j := range v {
			if v[j] == 0 {
				if math.Abs(float64(dequantized[j])) > 0.01 {
					t.Errorf("vector %d dim %d: dequantized %v, expected near 0", i, j, dequantized[j])
				}
				continue
			}
			errorRate := math.Abs(float64(dequantized[j]-v[j]) / float64(v[j]))
			if errorRate > 0.05 {
				t.Errorf("vector %d dim %d: round-trip error %.4f > 5%% (original=%v, dequantized=%v)",
					i, j, errorRate, v[j], dequantized[j])
			}
		}
	}
}

func TestScalarQuantizerTraining(t *testing.T) {
	vectors := [][]float32{
		{1.0, 2.0, 3.0},
		{4.0, 5.0, 6.0},
		{7.0, 8.0, 9.0},
	}

	sq := TrainScalarQuantizer(vectors)

	if sq.Scale <= 0 {
		t.Errorf("scale should be positive, got %v", sq.Scale)
	}

	if sq.Min != 1.0 {
		t.Errorf("min should be 1.0, got %v", sq.Min)
	}

	// Scale should be (9.0 - 1.0) / 255
	expectedScale := float32(8.0 / 255.0)
	if math.Abs(float64(sq.Scale-expectedScale)) > 0.001 {
		t.Errorf("scale should be ~%v, got %v", expectedScale, sq.Scale)
	}
}

func TestScalarQuantizerEmptyInput(t *testing.T) {
	sq := TrainScalarQuantizer(nil)
	if sq == nil {
		t.Error("should return a valid quantizer for nil input")
	}

	sq2 := TrainScalarQuantizer([][]float32{})
	if sq2 == nil {
		t.Error("should return a valid quantizer for empty input")
	}
}

func TestScalarQuantizerClamping(t *testing.T) {
	sq := &ScalarQuantizer{Min: 0, Scale: 1.0 / 255.0}

	// Value below min should clamp to 0
	v := []float32{-1.0}
	quantized := sq.Quantize(v)
	if quantized[0] != 0 {
		t.Errorf("value below min should clamp to 0, got %d", quantized[0])
	}

	// Value above max should clamp to 255
	v = []float32{2.0}
	quantized = sq.Quantize(v)
	if quantized[0] != 255 {
		t.Errorf("value above max should clamp to 255, got %d", quantized[0])
	}
}

func TestProductQuantizerRoundTrip(t *testing.T) {
	dim := 8
	numSub := 2
	numVectors := 300 // Need enough for k-means to work

	// Generate synthetic data
	vectors := make([][]float32, numVectors)
	for i := 0; i < numVectors; i++ {
		v := make([]float32, dim)
		for j := 0; j < dim; j++ {
			v[j] = float32(i%100) / 100.0 + float32(j)*0.1
		}
		vectors[i] = v
	}

	pq, err := TrainProductQuantizer(vectors, numSub)
	if err != nil {
		t.Fatalf("failed to train PQ: %v", err)
	}

	if pq.NumSubquantizers != numSub {
		t.Errorf("numSubquantizers: got %d, want %d", pq.NumSubquantizers, numSub)
	}

	if pq.SubDim != dim/numSub {
		t.Errorf("subDim: got %d, want %d", pq.SubDim, dim/numSub)
	}

	// Test round-trip for a few vectors
	for i := 0; i < 10; i++ {
		v := vectors[i]
		codes := pq.Quantize(v)
		if len(codes) != numSub {
			t.Errorf("vector %d: codes length %d, want %d", i, len(codes), numSub)
			continue
		}

		reconstructed := pq.Dequantize(codes)
		if len(reconstructed) != dim {
			t.Errorf("vector %d: reconstructed length %d, want %d", i, len(reconstructed), dim)
			continue
		}

		// PQ has more error than SQ, but should be within reasonable bounds
		var totalError float64
		for j := range v {
			diff := float64(reconstructed[j] - v[j])
			totalError += diff * diff
		}
		rmse := math.Sqrt(totalError / float64(dim))
		if rmse > 1.0 {
			t.Errorf("vector %d: RMSE too high: %.4f", i, rmse)
		}
	}
}

func TestProductQuantizerTraining(t *testing.T) {
	dim := 16
	numSub := 4
	numVectors := 500

	vectors := make([][]float32, numVectors)
	for i := 0; i < numVectors; i++ {
		v := make([]float32, dim)
		for j := 0; j < dim; j++ {
			v[j] = float32(i%100) / 100.0 + float32(j)*0.05
		}
		vectors[i] = v
	}

	pq, err := TrainProductQuantizer(vectors, numSub)
	if err != nil {
		t.Fatalf("failed to train PQ: %v", err)
	}

	// Verify centroids are populated
	for s := 0; s < numSub; s++ {
		hasNonZero := false
		for c := 0; c < pq.NumCentroids; c++ {
			centroid := pq.Centroids[s*pq.NumCentroids+c]
			if centroid != nil {
				for _, val := range centroid {
					if val != 0 {
						hasNonZero = true
						break
					}
				}
			}
			if hasNonZero {
				break
			}
		}
		if !hasNonZero {
			t.Errorf("subquantizer %d: all centroids are zero", s)
		}
	}
}

func TestProductQuantizerInvalidDim(t *testing.T) {
	vectors := [][]float32{
		{1.0, 2.0, 3.0}, // dim=3, not divisible by numSub=2
	}

	_, err := TrainProductQuantizer(vectors, 2)
	if err == nil {
		t.Error("expected error for dimension not divisible by numSubquantizers")
	}
}

func TestProductQuantizerEmptyInput(t *testing.T) {
	_, err := TrainProductQuantizer(nil, 2)
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestSQQuantizeDequantizeConsistency(t *testing.T) {
	// Test that quantize->dequantize is consistent across multiple calls
	vectors := [][]float32{
		{0.1, 0.5, 0.9},
		{0.2, 0.4, 0.6},
	}

	sq := TrainScalarQuantizer(vectors)

	for _, v := range vectors {
		q1 := sq.Quantize(v)
		d1 := sq.Dequantize(q1)

		q2 := sq.Quantize(v)
		d2 := sq.Dequantize(q2)

		for j := range d1 {
			if d1[j] != d2[j] {
				t.Errorf("inconsistent dequantization: %v vs %v", d1[j], d2[j])
			}
		}
	}
}
