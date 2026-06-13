package vector

import (
	"fmt"
	"math"
	"math/rand"
)

// ScalarQuantizer quantizes float32 vectors to int8 for compact storage.
type ScalarQuantizer struct {
	Min   float32
	Scale float32
}

// TrainScalarQuantizer learns min and scale from a set of vectors.
func TrainScalarQuantizer(vectors [][]float32) *ScalarQuantizer {
	if len(vectors) == 0 {
		return &ScalarQuantizer{Min: 0, Scale: 1}
	}

	var globalMin, globalMax float32
	globalMin = math.MaxFloat32
	globalMax = -math.MaxFloat32

	for _, v := range vectors {
		for _, val := range v {
			if val < globalMin {
				globalMin = val
			}
			if val > globalMax {
				globalMax = val
			}
		}
	}

	var scale float32
	if globalMax-globalMin > 0 {
		scale = (globalMax - globalMin) / 255.0
	} else {
		scale = 1.0 / 255.0
	}

	return &ScalarQuantizer{
		Min:   globalMin,
		Scale: scale,
	}
}

// Quantize converts a float32 vector to int8 bytes.
func (sq *ScalarQuantizer) Quantize(v []float32) []byte {
	result := make([]byte, len(v))
	for i, val := range v {
		normalized := (val - sq.Min) / sq.Scale
		if normalized < 0 {
			normalized = 0
		}
		if normalized > 255 {
			normalized = 255
		}
		result[i] = byte(normalized)
	}
	return result
}

// Dequantize converts int8 bytes back to float32 vector.
func (sq *ScalarQuantizer) Dequantize(b []byte) []float32 {
	result := make([]float32, len(b))
	for i, val := range b {
		result[i] = float32(val)*sq.Scale + sq.Min
	}
	return result
}

// ProductQuantizer splits vectors into subvectors and quantizes each independently.
type ProductQuantizer struct {
	NumSubquantizers int         // default 8
	NumCentroids     int         // default 256
	Centroids        [][]float32 // numSubquantizers * numCentroids centroids, flattened
	SubDim           int         // dimension / numSubquantizers
}

// TrainProductQuantizer trains a product quantizer from training vectors.
func TrainProductQuantizer(vectors [][]float32, numSub int) (*ProductQuantizer, error) {
	if len(vectors) == 0 {
		return nil, fmt.Errorf("no training vectors provided")
	}

	dim := len(vectors[0])
	if dim%numSub != 0 {
		return nil, fmt.Errorf("dimension %d not divisible by numSubquantizers %d", dim, numSub)
	}

	subDim := dim / numSub
	numCentroids := 256

	pq := &ProductQuantizer{
		NumSubquantizers: numSub,
		NumCentroids:     numCentroids,
		SubDim:           subDim,
		Centroids:        make([][]float32, numSub*numCentroids),
	}

	for s := 0; s < numSub; s++ {
		start := s * subDim
		end := start + subDim

		// Extract sub-vectors
		subVecs := make([][]float32, len(vectors))
		for j, vec := range vectors {
			subVecs[j] = vec[start:end]
		}

		// Run k-means on sub-vectors
		k := numCentroids
		if len(subVecs) < k {
			k = len(subVecs)
		}
		centroids := pqKMeans(subVecs, k, 20)

		// Store centroids
		for c, centroid := range centroids {
			pq.Centroids[s*numCentroids+c] = centroid
		}
		// Fill remaining centroids with zeros if we had fewer vectors than 256
		for c := len(centroids); c < numCentroids; c++ {
			pq.Centroids[s*numCentroids+c] = make([]float32, subDim)
		}
	}

	return pq, nil
}

// Quantize encodes a vector into PQ codes (one byte per subquantizer).
func (pq *ProductQuantizer) Quantize(v []float32) []byte {
	codes := make([]byte, pq.NumSubquantizers)
	for s := 0; s < pq.NumSubquantizers; s++ {
		start := s * pq.SubDim
		end := start + pq.SubDim
		if end > len(v) {
			end = len(v)
		}
		subVec := v[start:end]

		bestCode := uint8(0)
		bestDist := float32(math.MaxFloat32)
		for c := 0; c < pq.NumCentroids; c++ {
			centroid := pq.Centroids[s*pq.NumCentroids+c]
			if centroid == nil {
				continue
			}
			d := euclideanDistSq(subVec, centroid)
			if d < bestDist {
				bestDist = d
				bestCode = uint8(c)
			}
		}
		codes[s] = bestCode
	}
	return codes
}

// Dequantize reconstructs an approximate vector from PQ codes.
func (pq *ProductQuantizer) Dequantize(codes []byte) []float32 {
	result := make([]float32, pq.NumSubquantizers*pq.SubDim)
	for s := 0; s < pq.NumSubquantizers && s < len(codes); s++ {
		centroid := pq.Centroids[s*pq.NumCentroids+int(codes[s])]
		if centroid == nil {
			continue
		}
		start := s * pq.SubDim
		for j, val := range centroid {
			if start+j < len(result) {
				result[start+j] = val
			}
		}
	}
	return result
}

// euclideanDistSq computes squared Euclidean distance between two vectors.
func euclideanDistSq(a, b []float32) float32 {
	var sum float32
	for i := range a {
		if i < len(b) {
			diff := a[i] - b[i]
			sum += diff * diff
		}
	}
	return sum
}

// pqKMeans runs k-means clustering and returns cluster centers.
func pqKMeans(data [][]float32, k int, maxIter int) [][]float32 {
	n := len(data)
	if n == 0 || k <= 0 {
		return nil
	}
	if k > n {
		k = n
	}

	dim := len(data[0])

	// Initialize centers by picking k random vectors
	perm := rand.Perm(n)
	centers := make([][]float32, k)
	for i := 0; i < k; i++ {
		centers[i] = make([]float32, dim)
		copy(centers[i], data[perm[i]])
	}

	assignments := make([]int, n)

	for iter := 0; iter < maxIter; iter++ {
		changed := false

		// Assignment step
		for i, vec := range data {
			bestCluster := 0
			bestDist := float32(math.MaxFloat32)
			for ci, center := range centers {
				d := euclideanDistSq(vec, center)
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

		// Update step
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
		}
	}

	return centers
}
