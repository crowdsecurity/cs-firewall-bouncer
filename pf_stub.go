// +build !openbsd

package main

func newPF(config *bouncerConfig) (interface{}, error) {
	return nil, nil
}
