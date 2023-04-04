//go:build !linux
// +build !linux

package iptables

func NewIPTables(config *BouncerConfig) (backend, error) {
	return nil, nil
}
