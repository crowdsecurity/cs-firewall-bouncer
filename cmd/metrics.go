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

	//Most of the common fields are set automatically by the metrics provider
	//We only need to care about the metrics themselves

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
		for _, metric := range metricFamily.GetMetric() {
			switch metricFamily.GetName() {
			case metrics.ActiveBannedIPsMetricName:
				//We send the absolute value, as it makes no sense to try to sum them crowdsec side
				labels := metric.GetLabel()
				value := metric.GetGauge().GetValue()
				origin := getLabelValue(labels, "origin")
				ipType := getLabelValue(labels, "ip_type")
				log.Debugf("Sending active decisions for %s %s | current value: %f", origin, ipType, value)
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("active_decisions"),
					Value: ptr.Of(value),
					Labels: map[string]string{
						"origin":  origin,
						"ip_type": ipType,
					},
					Unit: ptr.Of("ip"),
				})
			case metrics.DroppedBytesMetricName:
				labels := metric.GetLabel()
				value := metric.GetGauge().GetValue()
				origin := getLabelValue(labels, "origin")
				ipType := getLabelValue(labels, "ip_type")
				key := origin + ipType
				// The firewall counter may have been reset since laste collection.
				// In this case, don't register a negative value.
				newValue := max(0, value-metrics.LastDroppedBytesValue[key])
				log.Debugf("Sending dropped bytes for %s %s %f | current value: %f | previous value: %f\n", origin, ipType, newValue, value, metrics.LastDroppedBytesValue[key])
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("dropped"),
					Value: &newValue,
					Labels: map[string]string{
						"origin":  origin,
						"ip_type": ipType,
					},
					Unit: ptr.Of("byte"),
				})
				metrics.LastDroppedBytesValue[key] = value
			case metrics.DroppedPacketsMetricName:
				labels := metric.GetLabel()
				value := metric.GetGauge().GetValue()
				origin := getLabelValue(labels, "origin")
				ipType := getLabelValue(labels, "ip_type")
				key := origin + ipType
				newValue := max(0, value-metrics.LastDroppedPacketsValue[key])
				log.Debugf("Sending dropped packets for %s %s %f | current value: %f | previous value: %f\n", origin, ipType, newValue, value, metrics.LastDroppedPacketsValue[key])
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("dropped"),
					Value: &newValue,
					Labels: map[string]string{
						"origin":  origin,
						"ip_type": ipType,
					},
					Unit: ptr.Of("packet"),
				})
				metrics.LastDroppedPacketsValue[key] = value
			case metrics.ProcessedBytesMetricName:
				labels := metric.GetLabel()
				value := metric.GetGauge().GetValue()
				ipType := getLabelValue(labels, "ip_type")
				newValue := max(0, value-metrics.LastProcessedBytesValue[ipType])
				log.Debugf("Sending processed bytes for %s %f | current value: %f | previous value: %f\n", ipType, newValue, value, metrics.LastProcessedBytesValue[ipType])
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("processed"),
					Value: &newValue,
					Labels: map[string]string{
						"ip_type": ipType,
					},
					Unit: ptr.Of("byte"),
				})
				metrics.LastProcessedBytesValue[ipType] = value
			case metrics.ProcessedPacketsMetricName:
				labels := metric.GetLabel()
				value := metric.GetGauge().GetValue()
				ipType := getLabelValue(labels, "ip_type")
				newValue := max(0, value-metrics.LastProcessedPacketsValue[ipType])
				log.Debugf("Sending processed packets for %s %f | current value: %f | previous value: %f\n", ipType, newValue, value, metrics.LastProcessedPacketsValue[ipType])
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("processed"),
					Value: &newValue,
					Labels: map[string]string{
						"ip_type": ipType,
					},
					Unit: ptr.Of("packet"),
				})
				metrics.LastProcessedPacketsValue[ipType] = value
			}
		}
	}
}

func (m metricsHandler) computeMetricsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.backend.CollectMetrics()
		next.ServeHTTP(w, r)
	})
}
