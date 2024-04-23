package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const MetricCollectionInterval = time.Second * 10

const (
	DroppedPacketsMetricName  = "fw_bouncer_dropped_packets"
	DroppedBytesMetricName    = "fw_bouncer_dropped_bytes"
	ActiveBannedIPsMetricName = "fw_bouncer_banned_ips"
)

var TotalDroppedPackets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: DroppedPacketsMetricName,
	Help: "Denotes the number of total dropped packets because of rule(s) created by crowdsec",
}, []string{"origin", "ip_type"})

var TotalDroppedBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: DroppedBytesMetricName,
	Help: "Denotes the number of total dropped bytes because of rule(s) created by crowdsec",
}, []string{"origin", "ip_type"})

var TotalActiveBannedIPs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: ActiveBannedIPsMetricName,
	Help: "Denotes the number of IPs which are currently banned",
}, []string{"origin", "ip_type"})
