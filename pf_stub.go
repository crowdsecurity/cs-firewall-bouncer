// +build !openbsd,!freebsd

package main

func newPF(config *bouncerConfig) (backend, error) {
	return nil, nil
}
