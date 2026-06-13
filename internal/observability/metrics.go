package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace = "nexus"
)

// MetricsRegistry holds all Prometheus metrics for the Nexus system.
type MetricsRegistry struct {
	ObjectPutTotal          *prometheus.CounterVec
	ObjectGetTotal          *prometheus.CounterVec
	ObjectGetBytesTotal     *prometheus.CounterVec
	EncryptDuration         *prometheus.HistogramVec
	DecryptDuration         *prometheus.HistogramVec
	VectorSearchDuration    *prometheus.HistogramVec
	VectorIndexSizeVectors  prometheus.Gauge
	StorageIOBytesTotal     *prometheus.CounterVec
	ReplicationLagSeconds   *prometheus.GaugeVec
	EventDeliveryTotal      *prometheus.CounterVec
	IAMPolicyEvalDuration   prometheus.Histogram
	HTTPRequestDuration     *prometheus.HistogramVec
	GRPCRequestDuration     *prometheus.HistogramVec
	Up                      prometheus.Gauge
}

var defaultBuckets = []float64{.005, .01, .025, .05, .1, .25, .5}

// NewMetricsRegistry creates and registers all Prometheus metrics.
func NewMetricsRegistry() *MetricsRegistry {
	r := &MetricsRegistry{}

	r.ObjectPutTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "object_put_total",
			Help:      "Total number of object put operations",
		},
		[]string{"bucket", "status"},
	)

	r.ObjectGetTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "object_get_total",
			Help:      "Total number of object get operations",
		},
		[]string{"bucket", "status"},
	)

	r.ObjectGetBytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "object_get_bytes_total",
			Help:      "Total bytes retrieved by object get operations",
		},
		[]string{"bucket"},
	)

	r.EncryptDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "encrypt_duration_seconds",
			Help:      "Duration of encryption operations",
			Buckets:   defaultBuckets,
		},
		[]string{"service"},
	)

	r.DecryptDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "decrypt_duration_seconds",
			Help:      "Duration of decryption operations",
			Buckets:   defaultBuckets,
		},
		[]string{"service"},
	)

	r.VectorSearchDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "vector_search_duration_seconds",
			Help:      "Duration of vector search operations",
			Buckets:   defaultBuckets,
		},
		[]string{"index_type"},
	)

	r.VectorIndexSizeVectors = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "vector_index_size_vectors",
			Help:      "Current number of vectors in the index",
		},
	)

	r.StorageIOBytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "storage_io_bytes_total",
			Help:      "Total bytes of storage I/O operations",
		},
		[]string{"op", "backend"},
	)

	r.ReplicationLagSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "replication_lag_seconds",
			Help:      "Replication lag in seconds per rule",
		},
		[]string{"rule"},
	)

	r.EventDeliveryTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "event_delivery_total",
			Help:      "Total number of event deliveries",
		},
		[]string{"status"},
	)

	r.IAMPolicyEvalDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "iam_policy_eval_duration_seconds",
			Help:      "Duration of IAM policy evaluations",
			Buckets:   defaultBuckets,
		},
	)

	r.HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "Duration of HTTP requests",
			Buckets:   []float64{.005, .01, .025, .05, .1, .25, .5},
		},
		[]string{"method", "path", "status"},
	)

	r.GRPCRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "grpc_request_duration_seconds",
			Help:      "Duration of gRPC requests",
			Buckets:   defaultBuckets,
		},
		[]string{"method", "status"},
	)

	r.Up = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "up",
			Help:      "Indicates if the Nexus service is up (1 = up)",
		},
	)

	prometheus.MustRegister(
		r.ObjectPutTotal,
		r.ObjectGetTotal,
		r.ObjectGetBytesTotal,
		r.EncryptDuration,
		r.DecryptDuration,
		r.VectorSearchDuration,
		r.VectorIndexSizeVectors,
		r.StorageIOBytesTotal,
		r.ReplicationLagSeconds,
		r.EventDeliveryTotal,
		r.IAMPolicyEvalDuration,
		r.HTTPRequestDuration,
		r.GRPCRequestDuration,
		r.Up,
	)

	r.Up.Set(1)

	return r
}

// RecordPutObject records a put object operation.
func (m *MetricsRegistry) RecordPutObject(bucket string, status string) {
	if m != nil {
		m.ObjectPutTotal.WithLabelValues(bucket, status).Inc()
	}
}

// RecordGetObject records a get object operation.
func (m *MetricsRegistry) RecordGetObject(bucket string, status string, bytes int64) {
	if m != nil {
		m.ObjectGetTotal.WithLabelValues(bucket, status).Inc()
		m.ObjectGetBytesTotal.WithLabelValues(bucket).Add(float64(bytes))
	}
}

// RecordEncryptDuration records an encryption operation duration.
func (m *MetricsRegistry) RecordEncryptDuration(service string, duration time.Duration) {
	if m != nil {
		m.EncryptDuration.WithLabelValues(service).Observe(duration.Seconds())
	}
}

// RecordDecryptDuration records a decryption operation duration.
func (m *MetricsRegistry) RecordDecryptDuration(service string, duration time.Duration) {
	if m != nil {
		m.DecryptDuration.WithLabelValues(service).Observe(duration.Seconds())
	}
}

// RecordVectorSearch records a vector search operation duration.
func (m *MetricsRegistry) RecordVectorSearch(indexType string, duration time.Duration) {
	if m != nil {
		m.VectorSearchDuration.WithLabelValues(indexType).Observe(duration.Seconds())
	}
}

// RecordStorageIO records a storage I/O operation.
func (m *MetricsRegistry) RecordStorageIO(op, backend string, bytes int64) {
	if m != nil {
		m.StorageIOBytesTotal.WithLabelValues(op, backend).Add(float64(bytes))
	}
}

// RecordEventDelivery records an event delivery.
func (m *MetricsRegistry) RecordEventDelivery(status string) {
	if m != nil {
		m.EventDeliveryTotal.WithLabelValues(status).Inc()
	}
}

// RecordIAMPolicyEval records an IAM policy evaluation duration.
func (m *MetricsRegistry) RecordIAMPolicyEval(duration time.Duration) {
	if m != nil {
		m.IAMPolicyEvalDuration.Observe(duration.Seconds())
	}
}

// HTTPMiddleware returns an HTTP middleware that records request duration and status.
func (m *MetricsRegistry) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start)
		if m != nil {
			m.HTTPRequestDuration.WithLabelValues(
				r.Method,
				r.URL.Path,
				httpStatusClass(wrapped.statusCode),
			).Observe(duration.Seconds())
		}
	})
}

// MetricsHandler returns an HTTP handler that serves Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func httpStatusClass(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "1xx"
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}
