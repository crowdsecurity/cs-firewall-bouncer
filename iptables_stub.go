//go:build !linux
// +build !linux

package main

func newIPTables(config *BouncerConfig) (backend, error) {
	return nil, nil
}
