package coordinator

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestRemoteAddr(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16"), netip.MustParsePrefix("fd00::/8")}
	tests := []struct {
		name      string
		peer      string
		forwarded []string
		want      string
	}{
		{"reached directly", "203.0.113.7:51234", nil, "203.0.113.7"},
		{"a direct sender cannot name itself", "203.0.113.7:51234", []string{"198.51.100.1"}, "203.0.113.7"},
		{"behind the ingress", "10.244.1.167:40000", []string{"198.51.100.9"}, "198.51.100.9"},
		{"the sender's own claim is to the left, and ignored", "10.244.1.167:40000", []string{"1.2.3.4, 198.51.100.9"}, "198.51.100.9"},
		{"two trusted hops", "10.244.1.167:40000", []string{"198.51.100.9, 10.244.6.2"}, "198.51.100.9"},
		{"split over several headers", "10.244.1.167:40000", []string{"1.2.3.4", "198.51.100.9", "10.244.6.2"}, "198.51.100.9"},
		{"an entry with a port", "10.244.1.167:40000", []string{"198.51.100.9:443"}, "198.51.100.9"},
		{"from inside the cluster, through the ingress", "10.244.1.167:40000", []string{"10.244.3.3"}, "10.244.1.167"},
		{"a proxy that sent no header", "10.244.1.167:40000", nil, "10.244.1.167"},
		{"junk stops the walk", "10.244.1.167:40000", []string{"198.51.100.9, not-an-address"}, "10.244.1.167"},
		{"ipv6", "[fd00::1]:40000", []string{"2001:db8::7"}, "2001:db8::7"},
		{"ipv4 mapped in ipv6", "[::ffff:10.244.1.167]:40000", []string{"198.51.100.9"}, "198.51.100.9"},
	}
	for _, tt := range tests {
		r := &http.Request{RemoteAddr: tt.peer, Header: http.Header{}}
		for _, v := range tt.forwarded {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := remoteAddr(r, trusted); got != tt.want {
			t.Errorf("%s: remoteAddr = %q, want %q", tt.name, got, tt.want)
		}
	}
	// With no trusted proxies the header is never read.
	r := &http.Request{RemoteAddr: "10.244.1.167:40000", Header: http.Header{"X-Forwarded-For": {"198.51.100.9"}}}
	if got := remoteAddr(r, nil); got != "10.244.1.167" {
		t.Errorf("no trusted proxies: remoteAddr = %q", got)
	}
}

func TestTrustedProxiesConfig(t *testing.T) {
	cfg := &Config{OIDC: OIDCConfig{Issuer: "i", ClientID: "c"}, SessionTTL: 1, TrustedProxies: []string{"10.244.0.0/16", "192.168.1.9/24"}}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.trustedProxies[1].String(); got != "192.168.1.0/24" {
		t.Errorf("a network given with host bits = %s, want it masked", got)
	}
	cfg.TrustedProxies = []string{"10.244.1.167"}
	if err := cfg.validate(); err == nil {
		t.Error("an address that is not a network should be refused")
	}
}
