//go:build !linux
// +build !linux

package main

func newNFTables(config *BouncerConfig) (backend, error) {
	return nil, nil
}
