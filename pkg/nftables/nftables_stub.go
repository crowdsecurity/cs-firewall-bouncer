//go:build !linux
// +build !linux

package nftables

func NewNFTables(config *BouncerConfig) (backend, error) {
	return nil, nil
}
