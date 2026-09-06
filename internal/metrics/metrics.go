package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "toolgate_requests_total",
			Help: "Total number of MCP requests processed",
		},
		[]string{"method", "decision"},
	)

	Latency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "toolgate_request_duration_seconds",
			Help:    "Latency of MCP requests",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)

	RedactionsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "toolgate_redactions_total",
			Help: "Total number of sensitive fields redacted",
		},
	)
)
