package iputils

import (
	"net/netip"
	"testing"
)

func TestParseIPRange(t *testing.T) {
	for _, tc := range []struct {
		value string
		first string
		last  string
	}{
		{value: "10.0.0.1", first: "10.0.0.1", last: "10.0.0.1"},
		{value: "10.0.0.1/32", first: "10.0.0.1", last: "10.0.0.1"},
		{value: "10.0.0.0/24", first: "10.0.0.0", last: "10.0.0.255"},
		{value: "0.0.0.0/0", first: "0.0.0.0", last: "255.255.255.255"},
		{value: "10.0.0.42/24", first: "10.0.0.0", last: "10.0.0.255"},
		{value: "::ffff:10.0.0.1", first: "10.0.0.1", last: "10.0.0.1"},
		{value: "::ffff:10.0.0.0/120", first: "10.0.0.0", last: "10.0.0.255"},
		{value: "::ffff:10.0.0.0/100", first: "0.0.0.0", last: "15.255.255.255"},
		{value: "::ffff:0.0.0.0/96", first: "0.0.0.0", last: "255.255.255.255"},
		{value: "2001:db8::1", first: "2001:db8::1", last: "2001:db8::1"},
		{value: "2001:db8::1/128", first: "2001:db8::1", last: "2001:db8::1"},
		{value: "2001:db8::/48", first: "2001:db8::", last: "2001:db8:0:ffff:ffff:ffff:ffff:ffff"},
		{value: "::/0", first: "::", last: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			rng, err := ParseIPRange(tc.value)
			if err != nil {
				t.Fatalf("ParseIPRange(%s) failed: %s", tc.value, err)
			}

			expected := IPRange{
				First: netip.MustParseAddr(tc.first),
				Last:  netip.MustParseAddr(tc.last),
			}
			if rng != expected {
				t.Errorf("ParseIPRange(%s) = %s-%s, expected %s-%s", tc.value, rng.First, rng.Last, tc.first, tc.last)
			}
		})
	}
}

func TestParseIPRangeErrors(t *testing.T) {
	for _, value := range []string{
		"",
		"not an ip",
		"10.0.0.0/33",
		"10.0.0.0/",
		"2001:db8::/129",
		"10.0.0.256",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseIPRange(value); err == nil {
				t.Errorf("ParseIPRange(%s) should have failed", value)
			}
		})
	}
}
