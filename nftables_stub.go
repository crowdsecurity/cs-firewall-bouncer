//go:build !linux
// +build !linux

package main

func newNFTables(config *bouncerConfig) (backend, error) {
	return nil, nil
}
