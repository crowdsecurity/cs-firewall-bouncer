package iputils

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// IPRange is a range of IP addresses, both ends included.
type IPRange struct {
	First netip.Addr
	Last  netip.Addr
}

// ParseIPRange returns the range covered by an IP address or by a CIDR range.
// An IPv4 address written in the IPv6 notation is returned as IPv4.
func ParseIPRange(value string) (IPRange, error) {
	if !strings.Contains(value, "/") {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return IPRange{}, fmt.Errorf("can't parse IP address '%s': %w", value, err)
		}

		addr = addr.Unmap()

		return IPRange{
			First: addr,
			Last:  addr,
		}, nil
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return IPRange{}, fmt.Errorf("can't parse IP range '%s': %w", value, err)
	}

	prefix = prefix.Masked()
	first, bits := prefix.Addr(), prefix.Bits()

	if unmapped := first.Unmap(); unmapped != first {
		bits -= first.BitLen() - unmapped.BitLen()
		first = unmapped
	}

	host := first.AsSlice()
	for i, mask := range net.CIDRMask(bits, len(host)*8) {
		host[i] |= ^mask
	}

	last, _ := netip.AddrFromSlice(host)

	return IPRange{
		First: first,
		Last:  last,
	}, nil
}

// Extend grows the range so that it also covers other.
func (r *IPRange) Extend(other IPRange) {
	if other.First.Less(r.First) {
		r.First = other.First
	}

	if r.Last.Less(other.Last) {
		r.Last = other.Last
	}
}
