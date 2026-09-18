package coordinator

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// remoteAddr returns the address of whoever sent r, for logs and the audit
// trail. Behind a load balancer or an ingress, the connection's own address
// is the proxy's, and the sender's is in X-Forwarded-For, which anyone can
// write. So the header is believed only on a connection that comes from one
// of the trusted proxies, and read from the right: each proxy appends the
// address it saw, so the rightmost entry that is not itself a trusted proxy
// is the nearest address that a trusted party vouches for. Whatever lies to
// its left is the sender's own claim.
func remoteAddr(r *http.Request, trusted []netip.Prefix) string {
	peer := hostOf(r.RemoteAddr)
	if !isTrusted(peer, trusted) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop := hostOf(strings.TrimSpace(hops[i]))
		if _, err := netip.ParseAddr(hop); err != nil {
			break // not an address: stop believing the header here
		}
		if !isTrusted(hop, trusted) {
			return hop
		}
	}
	return peer // the header named nothing but proxies, or nothing at all
}

func isTrusted(host string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// hostOf strips a port, if there is one.
func hostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
