package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const MetricCollectionInterval = time.Second * 10

const (
	DroppedPacketsMetricName   = "fw_bouncer_dropped_packets"
	DroppedBytesMetricName     = "fw_bouncer_dropped_bytes"
	ProcessedPacketsMetricName = "fw_bouncer_processed_packets"
	ProcessedBytesMetricName   = "fw_bouncer_processed_bytes"
	ActiveBannedIPsMetricName  = "fw_bouncer_banned_ips"
)

var TotalDroppedPackets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: DroppedPacketsMetricName,
	Help: "Denotes the number of total dropped packets because of rule(s) created by crowdsec",
}, []string{"origin", "ip_type"})
var LastDroppedPacketsValue map[string]float64 = make(map[string]float64)

var TotalDroppedBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: DroppedBytesMetricName,
	Help: "Denotes the number of total dropped bytes because of rule(s) created by crowdsec",
}, []string{"origin", "ip_type"})
var LastDroppedBytesValue map[string]float64 = make(map[string]float64)

var TotalActiveBannedIPs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: ActiveBannedIPsMetricName,
	Help: "Denotes the number of IPs which are currently banned",
}, []string{"origin", "ip_type"})
var LastActiveBannedIPsValue map[string]float64 = make(map[string]float64)

var TotalProcessedPackets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: ProcessedPacketsMetricName,
	Help: "Denotes the number of total processed packets by the rules created by crowdsec",
}, []string{"ip_type"})
var LastProcessedPacketsValue map[string]float64 = make(map[string]float64)

var TotalProcessedBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: ProcessedBytesMetricName,
	Help: "Denotes the number of total processed bytes by the rules created by crowdsec",
}, []string{"ip_type"})
var LastProcessedBytesValue map[string]float64 = make(map[string]float64)
