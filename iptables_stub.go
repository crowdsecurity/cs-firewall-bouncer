// +build !linux

package main

func newIPTables(config *bouncerConfig) (interface{}, error) {
	return nil, nil
}
