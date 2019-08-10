package resolv

import (
	"github.com/miekg/dns"
)

type R struct {
	servers []string
	c       *dns.Client
}

// New returns a new R.
func New() R {
	return R{servers: []string{"8.8.8.8:53", "8.8.4.4:53"}, c: &dns.Client{}}
}

// Do queries for qname/qtype and returns the RRs when found.
func (r R) Do(qname string, qtype uint16) (rrs []dns.RR, rcode int, dnssec bool, err error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(4096, true)
	var repl *dns.Msg

	for _, s := range r.servers {
		repl, _, err = r.c.Exchange(m, s)
		if err != nil {
			continue
		}
		rrs := []dns.RR{}
		for _, a := range repl.Answer {
			if a.Header().Rrtype == qtype {
				rrs = append(rrs, a)
			}
			if a.Header().Rrtype == dns.TypeRRSIG {
				dnssec = true
			}
		}
		return rrs, repl.Rcode, dnssec, nil
	}

	return nil, dns.RcodeServerFailure, false, err
}
