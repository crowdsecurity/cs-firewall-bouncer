// +build !linux

package main

func newNFTables(config *bouncerConfig) (interface{}, error) {
	return nil, nil
}
