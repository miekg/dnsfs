package resolv

import (
	"path"
	"strings"

	"bazil.org/fuse"
	"github.com/miekg/dns"
)

// The Resolver interface ...
type Resolver interface {
	Do(string, uint16, fuse.DirentType) ([]dns.RR, Info, error)
}

// R implements the Resolver interface and queries the DNS.
type R struct {
	servers []string
	c       *dns.Client
}

// New returns a new R.
func New() R {
	return R{servers: []string{"8.8.8.8:53", "8.8.4.4:53"}, c: &dns.Client{}}
}

// Info contains some metadata on the queries executed.
type Info struct {
	Rcode  int
	Dnssec bool
	Exists bool
	Target string // target as path.
}

// Do queries for qname/qtype and returns the RRs when found.
func (r R) Do(qname string, qtype uint16, typ fuse.DirentType) (rrs []dns.RR, info Info, err error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(4096, true)
	var repl *dns.Msg

	info = Info{Rcode: dns.RcodeServerFailure}
	for _, s := range r.servers {
		repl, _, err = r.c.Exchange(m, s)
		if err != nil {
			continue
		}

		info.Rcode = repl.Rcode
		if repl.Rcode != dns.RcodeSuccess {
			return nil, info, nil
		}
		rrs := []dns.RR{}
		for _, a := range repl.Answer {
			a.Header().Ttl = 3600

			// CNAME handling, only for directory query.
			if a.Header().Rrtype == dns.TypeCNAME && typ == fuse.DT_Dir {
				info.Target = dnsToTarget(a.(*dns.CNAME).Target)
				info.Exists = true
				return []dns.RR{a}, info, nil
			}

			if qtype == dns.TypeANY {
				rrs = append(rrs, a)
			}
			if a.Header().Rrtype == qtype {
				rrs = append(rrs, a)
			}

			if a.Header().Rrtype == dns.TypeRRSIG {
				info.Dnssec = true
			}
			info.Exists = true
		}
		if !info.Exists && len(repl.Ns) > 0 && typ == fuse.DT_Dir { // nodata, but only for dirs
			info.Exists = true
			for _, n := range repl.Ns {
				if n.Header().Rrtype == dns.TypeRRSIG {
					info.Dnssec = true
					break
				}
			}
		}

		return rrs, info, nil
	}

	return nil, info, err
}

// dnsToTarget converts a DNS name into a path.
func dnsToTarget(s string) string {
	l := strings.Split(s, ".")
	for left, right := 0, len(l)-1; left < right; left, right = left+1, right-1 {
		l[left], l[right] = l[right], l[left]
	}
	return path.Join(l...)
}

// T implements the Resolver interface and is used for testing.
type T struct{}

func (t T) Do(qname string, qtype uint16, typ fuse.DirentType) (rrs []dns.RR, info Info, err error) {
	return nil, Info{}, nil
}
