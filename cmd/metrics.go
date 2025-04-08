package cmd

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/backend"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
)

type metricsHandler struct {
	backend *backend.BackendCTX
}

type metricConfig struct {
	Name         string
	Unit         string
	LabelKeys    []string
	LastValueMap map[string]float64 // keep last value to send deltas -- nil if absolute
	KeyFunc      func(labels []*io_prometheus_client.LabelPair) string
}

var metricMap = map[string]metricConfig{
	metrics.ActiveBannedIPsMetricName: {
		Name:         "active_decisions",
		Unit:         "ip",
		LabelKeys:    []string{"origin", "ip_type"},
		LastValueMap: nil,
		KeyFunc:      func([]*io_prometheus_client.LabelPair) string { return "" },
	},
	metrics.DroppedBytesMetricName: {
		Name:         "dropped",
		Unit:         "byte",
		LabelKeys:    []string{"origin", "ip_type"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "origin") + getLabelValue(labels, "ip_type")
		},
	},
	metrics.DroppedPacketsMetricName: {
		Name:         "dropped",
		Unit:         "packet",
		LabelKeys:    []string{"origin", "ip_type"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "origin") + getLabelValue(labels, "ip_type")
		},
	},
	metrics.ProcessedBytesMetricName: {
		Name:         "processed",
		Unit:         "byte",
		LabelKeys:    []string{"ip_type"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "ip_type")
		},
	},
	metrics.ProcessedPacketsMetricName: {
		Name:         "processed",
		Unit:         "packet",
		LabelKeys:    []string{"ip_type"},
		LastValueMap: make(map[string]float64),
		KeyFunc: func(labels []*io_prometheus_client.LabelPair) string {
			return getLabelValue(labels, "ip_type")
		},
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

// metricsUpdater receives a metrics struct with basic data and populates it with the current metrics.
func (m metricsHandler) metricsUpdater(met *models.RemediationComponentsMetrics, updateInterval time.Duration) {
	log.Debugf("Updating metrics")

	m.backend.CollectMetrics()

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
		cfg, ok := metricMap[metricFamily.GetName()]
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

func (m metricsHandler) computeMetricsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.backend.CollectMetrics()
		next.ServeHTTP(w, r)
	})
}
