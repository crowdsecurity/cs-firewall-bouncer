package ipsetcmd

import "testing"

func TestParseIPSetLen(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want int
	}{
		{
			name: "modern ipset with Number of entries header",
			out: `Name: crowdsec-blacklists-0
Type: hash:net
Revision: 7
Header: family inet hashsize 8192 maxelem 131072 timeout 300
Size in memory: 769856
References: 1
Number of entries: 3
Members:
1.2.3.4 timeout 290
5.6.7.8 timeout 100
9.10.11.12 timeout 50
`,
			want: 3,
		},
		{
			name: "protocol v6 kernel without Number of entries header",
			out: `Name: crowdsec-blacklists-0
Type: hash:net
Revision: 6
Header: family inet hashsize 8192 maxelem 131072 timeout 300
Size in memory: 760832
References: 1
Members:
5.11.143.72 timeout 590431
91.92.42.120 timeout 10034
20.64.105.88 timeout 6299
`,
			want: 3,
		},
		{
			name: "empty set without header",
			out: `Name: crowdsec-blacklists-1
Type: hash:net
Revision: 6
Header: family inet hashsize 1024 maxelem 131072 timeout 300
Size in memory: 4192
References: 1
Members:
`,
			want: 0,
		},
		{
			name: "garbage output",
			out:  "some error happened\n",
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseIPSetLen(tc.out); got != tc.want {
				t.Errorf("parseIPSetLen() = %d, want %d", got, tc.want)
			}
		})
	}
}
