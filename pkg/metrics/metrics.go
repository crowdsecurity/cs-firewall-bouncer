package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const MetricCollectionInterval = time.Second * 10

var TotalDroppedPackets = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "fw_bouncer_dropped_packets",
	Help: "Denotes the number of total dropped packets because of rule(s) created by crowdsec",
})

var TotalDroppedBytes = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "fw_bouncer_dropped_bytes",
	Help: "Denotes the number of total dropped bytes because of rule(s) created by crowdsec",
})

var TotalActiveBannedIPs = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "fw_bouncer_banned_ips",
	Help: "Denotes the number of IPs which are currently banned",
})
