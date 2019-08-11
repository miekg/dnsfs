package dnsutil

import "github.com/miekg/dns"

// Join joins the labels a and b.
func Join(a, b string) string {
	if b == "." {
		return dns.Fqdn(a)
	}
	return dns.Fqdn(a + b) // a must be fully qualified.
}
