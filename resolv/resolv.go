package resolv

import (
	"bazil.org/fuse"
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

type Info struct {
	Rcode  int
	Dnssec bool
	Exists bool
}

// Do queries for qname/qtype and returns the RRs when found.
func (r R) Do(qname string, qtype uint16, typ fuse.DirentType) (rrs []dns.RR, info Info, err error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(4096, true)
	var repl *dns.Msg

	info = Info{dns.RcodeServerFailure, false, false}
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
				}
			}
		}

		return rrs, info, nil
	}

	return nil, info, err
}
