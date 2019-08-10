package resolv

import (
	"testing"

	"github.com/miekg/dns"
)

func TestDo(t *testing.T) {
	r := New()

	rrs, _, dnssec, err := r.Do("example.org.", dns.TypeSOA)
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 1 {
		t.Errorf("expected 1 SOA RR, got %d", len(rrs))
	}
	soa := rrs[0]
	if _, ok := soa.(*dns.SOA); !ok {
		t.Errorf("expected SOA record, got %t", soa)
	}
	if !dnssec {
		t.Errorf("expected RRSIG, got none")
	}
}
