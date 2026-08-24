package core

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/kgretzky/pwndrop/log"
	"github.com/miekg/dns"
)

type Nameserver struct {
	srv    *dns.Server
	serial uint32
}

func NewNameserver(ch_exit *chan bool) (*Nameserver, error) {
	n := &Nameserver{
		serial: uint32(time.Now().Unix()),
	}

	listen_ip := Cfg.GetListenIP()
	dns_host := fmt.Sprintf("%s:%d", listen_ip, 53)

	dns.HandleFunc(".", n.handleRequest)

	log.Info("starting DNS server at UDP: %s", dns_host)
	go func() {
		n.srv = &dns.Server{Addr: dns_host, Net: "udp"}
		if err := n.srv.ListenAndServe(); err != nil {
			log.Fatal("failed to start nameserver at: %s", dns_host)
			*ch_exit <- false
		}
	}()

	return n, nil
}

func (n *Nameserver) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	listen_ip := Cfg.GetListenIP()
	if listen_ip == "" {
		return
	}

	// A malformed query (e.g. QDCOUNT=1 with no question section) reaches
	// this handler with an empty Question slice. Indexing it would panic, and
	// because miekg/dns runs handlers in bare goroutines with no recover, that
	// panic would crash the whole process. Bail out safely instead.
	if len(r.Question) == 0 {
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)

	qdomain := m.Question[0].Name
	log.Debug("dns: %s listen_ip: %s", qdomain, listen_ip)

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: qdomain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + qdomain,
		Mbox:    "hostmaster." + qdomain,
		Serial:  n.serial,
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minttl:  60,
	}
	m.Ns = []dns.RR{soa}

	log.Debug("qtype: %d", r.Question[0].Qtype)

	switch r.Question[0].Qtype {
	case dns.TypeA:
		log.Debug("DNS A: %s = %s", qdomain, listen_ip)
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: qdomain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(listen_ip),
		}
		m.Answer = append(m.Answer, rr)
	case dns.TypeNS:
		log.Debug("DNS NS: %s", qdomain)
		for _, i := range []int{1, 2} {
			rr := &dns.NS{
				Hdr: dns.RR_Header{Name: qdomain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns" + strconv.Itoa(i) + "." + qdomain,
			}
			m.Answer = append(m.Answer, rr)
		}
	}
	w.WriteMsg(m)
}

func pdom(domain string) string {
	return domain + "."
}
