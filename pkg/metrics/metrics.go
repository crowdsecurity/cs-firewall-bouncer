package metrics

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

const CollectionInterval = time.Second * 10

type metricName string

const (
	DroppedPackets   metricName = "fw_bouncer_dropped_packets"
	DroppedBytes     metricName = "fw_bouncer_dropped_bytes"
	ProcessedPackets metricName = "fw_bouncer_processed_packets"
	ProcessedBytes   metricName = "fw_bouncer_processed_bytes"
	ActiveBannedIPs  metricName = "fw_bouncer_banned_ips"
	HealthStatus     metricName = "fw_bouncer_health_status"
)

// HealthCheckFailure counter tracks when health checks detect missing infrastructure.
var HealthCheckFailure = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "fw_bouncer_health_check_failure_total",
	Help: "Total number of health check failures detected",
}, []string{"backend"})

func RegisterHealthCounters() {
	prometheus.MustRegister(HealthCheckFailure)
}

type backendCollector interface {
	CollectMetrics()
}

type Handler struct {
	Backend backendCollector
}

type metricConfig struct {
	Name         string
	Unit         string
	Gauge        *prometheus.GaugeVec
	LabelKeys    []string
	LastValueMap map[string]float64 // keep last value to send deltas -- nil if absolute
	KeyFunc      func(labels []*io_prometheus_client.LabelPair) string
}

type metricMap map[metricName]*metricConfig

func (m metricMap) MustRegisterAll() {
	for _, met := range m {
		prometheus.MustRegister(met.Gauge)
	}
}

var Map = metricMap{
	ActiveBannedIPs: {
		Name: "active_decisions",
		Unit: "ip",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(ActiveBannedIPs),
			Help: "Denotes the number of IPs which are currently banned",
		}, []string{"origin", "ip_type"}),
		LabelKeys:    []string{"origin", "ip_type"},
		LastValueMap: nil,
		KeyFunc:      func([]*io_prometheus_client.LabelPair) string { return "" },
	},
	DroppedBytes: {
		Name: "dropped",
		Unit: "byte",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(DroppedBytes),
			Help: "Denotes the number of total dropped bytes because of rule(s) created by crowdsec",
		}, []string{"origin", "ip_type"}),
		LabelKeys:    []string{"origin", "ip_type"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "origin") + getLabelValue(labels, "ip_type")
		},
	},
	DroppedPackets: {
		Name: "dropped",
		Unit: "packet",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(DroppedPackets),
			Help: "Denotes the number of total dropped packets because of rule(s) created by crowdsec",
		}, []string{"origin", "ip_type"}),
		LabelKeys:    []string{"origin", "ip_type"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "origin") + getLabelValue(labels, "ip_type")
		},
	},
	ProcessedBytes: {
		Name: "processed",
		Unit: "byte",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(ProcessedBytes),
			Help: "Denotes the number of total processed bytes by the rules created by crowdsec",
		}, []string{"ip_type"}),
		LabelKeys:    []string{"ip_type"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "ip_type")
		},
	},
	ProcessedPackets: {
		Name: "processed",
		Unit: "packet",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(ProcessedPackets),
			Help: "Denotes the number of total processed packets by the rules created by crowdsec",
		}, []string{"ip_type"}),
		LabelKeys:    []string{"ip_type"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "ip_type")
		},
	},
	HealthStatus: {
		Name: "health_status",
		Unit: "boolean",
		Gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: string(HealthStatus),
			Help: "Current health status of the firewall backend (1=healthy, 0=unhealthy)",
		}, []string{"backend", "component"}),
		LabelKeys:    []string{"backend", "component"},
		LastValueMap: nil,
		KeyFunc:      func([]*io_prometheus_client.LabelPair) string { return "" },
	},
}

func getLabelValue(labels []*io_prometheus_client.LabelPair, key string) string {
	for _, label := range labels {
		if label.GetName() == key {
			return label.GetValue()
		}
	}

	return ""
}

// MetricsUpdater receives a metrics struct with basic data and populates it with the current metrics.
func (m Handler) MetricsUpdater(met *models.RemediationComponentsMetrics, updateInterval time.Duration) {
	log.Debugf("Updating metrics")

	m.Backend.CollectMetrics()

	// Most of the common fields are set automatically by the metrics provider
	// We only need to care about the metrics themselves

	promMetrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		log.Errorf("unable to gather prometheus metrics: %s", err)
		return
	}

	met.Metrics = append(met.Metrics, &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   ptr.Of(time.Now().Unix()),
			WindowSizeSeconds: ptr.Of(int64(updateInterval.Seconds())),
		},
		Items: make([]*models.MetricsDetailItem, 0),
	})

	for _, metricFamily := range promMetrics {
		cfg, ok := Map[metricName(metricFamily.GetName())]
		if !ok {
			continue
		}

		for _, metric := range metricFamily.GetMetric() {
			labels := metric.GetLabel()
			value := metric.GetGauge().GetValue()

			labelMap := make(map[string]string)
			for _, key := range cfg.LabelKeys {
				labelMap[key] = getLabelValue(labels, key)
			}

			finalValue := value

			if cfg.LastValueMap == nil {
				// always send absolute values
				log.Debugf("Sending %s for %+v %f", cfg.Name, labelMap, finalValue)
			} else {
				// the final value to send must be relative, and never negative
				// because the firewall counter may have been reset since last collection.
				key := cfg.KeyFunc(labels)

				// no need to guard access to LastValueMap, as we are in the main thread -- it's
				// the gauge that is updated by the requests
				finalValue = value - cfg.LastValueMap[key]

				if finalValue < 0 {
					finalValue = -finalValue

					log.Warningf("metric value for %s %+v is negative, assuming external counter was reset", cfg.Name, labelMap)
				}

				cfg.LastValueMap[key] = value
				log.Debugf("Sending %s for %+v %f | current value: %f | previous value: %f", cfg.Name, labelMap, finalValue, value, cfg.LastValueMap[key])
			}

			met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
				Name:   ptr.Of(cfg.Name),
				Value:  &finalValue,
				Labels: labelMap,
				Unit:   ptr.Of(cfg.Unit),
			})
		}
	}
}

func (m Handler) ComputeMetricsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.Backend.CollectMetrics()
		next.ServeHTTP(w, r)
	})
}

// HealthResponse is the JSON response for the /health endpoint.
type HealthResponse struct {
	Status    string          `json:"status"`
	Backend   string          `json:"backend"`
	Details   map[string]bool `json:"details"`
	Timestamp time.Time       `json:"timestamp"`
}

// HealthHandler returns an HTTP handler for the /health endpoint.
func HealthHandler(healthChecker func() types.HealthStatus, backendMode string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		health := healthChecker()

		status := "healthy"
		httpStatus := http.StatusOK
		if !health.Healthy {
			status = "unhealthy"
			httpStatus = http.StatusServiceUnavailable
		}

		response := HealthResponse{
			Status:    status,
			Backend:   backendMode,
			Details:   health.Details,
			Timestamp: health.LastChecked,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpStatus)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Errorf("failed to encode health response: %s", err)
		}
	})
}

// UpdateHealthMetrics updates the Prometheus health metrics based on the health status.
func UpdateHealthMetrics(health types.HealthStatus, backendMode string) {
	overall := float64(0)
	if health.Healthy {
		overall = 1
	}
	Map[HealthStatus].Gauge.WithLabelValues(backendMode, "overall").Set(overall)

	for component, healthy := range health.Details {
		val := float64(0)
		if healthy {
			val = 1
		}
		Map[HealthStatus].Gauge.WithLabelValues(backendMode, component).Set(val)
	}
}
