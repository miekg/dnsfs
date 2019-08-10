package dnsutil

import "github.com/miekg/dns"

func Join(a, b string) string {
	if b == "." {
		return dns.Fqdn(a)
	}
	return dns.Fqdn(a + b) // a must be fully qualified.
}
