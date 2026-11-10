package dnssd

import (
	"math/rand"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestSubtypes(t *testing.T) {
	cfg := Config{Name: "Printer", Type: "_ipp._tcp", Port: 631, Host: "gateway", Subtypes: []string{"_universal", "_print"}}
	srv, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"_universal._sub._ipp._tcp.local.", "_print._sub._ipp._tcp.local."}
	if got := srv.SubtypeNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SubtypeNames = %v, want %v", got, want)
	}
	ptrs := SubtypePTRs(srv)
	if len(ptrs) != 2 || ptrs[0].(*dns.PTR).Ptr != srv.EscapedServiceInstanceName() {
		t.Fatalf("SubtypePTRs = %v", ptrs)
	}
	if srv.Copy().Subtypes == nil {
		t.Fatal("Copy dropped the subtypes")
	}
	for _, bad := range []string{"universal", "_", "_a.b", "_a b"} {
		cfg.Subtypes = []string{bad}
		if _, err := NewService(cfg); err == nil {
			t.Errorf("NewService accepted subtype %q", bad)
		}
	}
}

func TestSubtypeQuestion(t *testing.T) {
	srv, err := NewService(Config{Name: "Printer", Type: "_ipp._tcp", Port: 631, Host: "gateway",
		IPs: []net.IP{net.ParseIP("192.0.2.1")}, Subtypes: []string{"_universal"}})
	if err != nil {
		t.Fatal(err)
	}
	r := &responder{random: rand.New(rand.NewSource(1))}
	query := new(dns.Msg)
	query.SetQuestion("_universal._sub._ipp._tcp.local.", dns.TypePTR)
	req := &Request{msg: query, iface: &net.Interface{Name: "test"}}
	resp := r.handleQuestion(query.Question[0], req, srv)
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("no answer to a subtype browse: %v", resp)
	}
	ptr, ok := resp.Answer[0].(*dns.PTR)
	if !ok || ptr.Hdr.Name != "_universal._sub._ipp._tcp.local." || ptr.Ptr != srv.EscapedServiceInstanceName() {
		t.Fatalf("answer = %v", resp.Answer[0])
	}
	// Another subtype is not answered.
	query.SetQuestion("_print._sub._ipp._tcp.local.", dns.TypePTR)
	if resp := r.handleQuestion(query.Question[0], req, srv); resp != nil {
		t.Fatalf("answered a subtype the service does not have: %v", resp)
	}
}

func TestTextOrder(t *testing.T) {
	srv, err := NewService(Config{Name: "Printer", Type: "_ipp._tcp", Port: 631, Host: "gateway",
		Text:      map[string]string{"txtvers": "1", "rp": "ipp/print", "pdl": "application/pdf", "URF": "W8", "ty": "Printer"},
		TextOrder: []string{"txtvers", "rp", "missing", "txtvers"}})
	if err != nil {
		t.Fatal(err)
	}
	// Listed keys first, in order, once; the rest sorted.
	want := []string{"txtvers=1", "rp=ipp/print", "URF=W8", "pdl=application/pdf", "ty=Printer"}
	if got := TXT(srv).Txt; !reflect.DeepEqual(got, want) {
		t.Fatalf("TXT = %v, want %v", got, want)
	}
}

// goodbyeConn records the responses a responder sends.
type goodbyeConn struct {
	MDNSConn
	mu   sync.Mutex
	sent []*Response
}

func (c *goodbyeConn) SendResponse(resp *Response) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, resp)
	return nil
}

func TestGoodbyeWithdrawsEveryRecord(t *testing.T) {
	srv, err := NewService(Config{Name: "Printer", Type: "_ipp._tcp", Port: 631, Host: "gateway",
		IPs: []net.IP{net.ParseIP("192.0.2.1")}, Ifaces: []string{"lo"}, Subtypes: []string{"_universal"}})
	if err != nil {
		t.Fatal(err)
	}
	conn := &goodbyeConn{}
	r := &responder{conn: conn}
	r.unannounce([]*Service{&srv})
	if len(conn.sent) == 0 {
		t.Skip("no loopback interface to say goodbye on")
	}
	types := map[uint16]int{}
	for _, rr := range conn.sent[0].msg.Answer {
		if rr.Header().Ttl != 0 {
			t.Fatalf("goodbye record with TTL %d: %v", rr.Header().Ttl, rr)
		}
		types[rr.Header().Rrtype]++
	}
	if types[dns.TypePTR] != 2 || types[dns.TypeSRV] != 1 || types[dns.TypeTXT] != 1 {
		t.Fatalf("goodbye records by type = %v, want 2 PTR (the type and the subtype), SRV and TXT", types)
	}
}

func TestUpdateTextWhileAnswering(t *testing.T) {
	srv, err := NewService(Config{Name: "Printer", Type: "_ipp._tcp", Port: 631, Host: "gateway",
		IPs: []net.IP{net.ParseIP("192.0.2.1")}, Subtypes: []string{"_universal"}, Text: map[string]string{"txtvers": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	conn := &goodbyeConn{}
	r := newResponder(conn)
	r.isRunning = true
	h := r.addManaged(srv)
	query := new(dns.Msg)
	query.SetQuestion("_universal._sub._ipp._tcp.local.", dns.TypePTR)
	req := &Request{msg: query, from: &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 5353}, iface: &net.Interface{Name: "test"}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			h.UpdateText(map[string]string{"txtvers": "1", "n": string(rune('a' + i%26))}, r)
			_ = h.Service()
		}
	}()
	for j := 0; j < 200; j++ {
		r.mutex.Lock()
		responses, _ := r.handleRequest(req)
		r.mutex.Unlock()
		if len(responses) != 1 {
			t.Fatalf("%d responses", len(responses))
		}
	}
	<-done
}

func TestOneDelayPerResponse(t *testing.T) {
	conn := &goodbyeConn{}
	r := newResponder(conn)
	r.isRunning = true
	for i := 0; i < 10; i++ {
		srv, err := NewService(Config{Name: "Printer " + string(rune('A'+i)), Type: "_ipp._tcp", Port: 631, Host: "gateway",
			IPs: []net.IP{net.ParseIP("192.0.2.1")}, Subtypes: []string{"_universal"}})
		if err != nil {
			t.Fatal(err)
		}
		r.addManaged(srv)
	}
	query := new(dns.Msg)
	query.SetQuestion("_universal._sub._ipp._tcp.local.", dns.TypePTR)
	req := &Request{msg: query, from: &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 5353}, iface: &net.Interface{Name: "test"}}
	start := time.Now()
	r.mutex.Lock()
	responses, delay := r.handleRequest(req)
	r.mutex.Unlock()
	// Building the answer for ten services takes no time; the one delay is
	// applied when it is sent, outside the lock.
	if took := time.Since(start); took > 20*time.Millisecond {
		t.Fatalf("handleRequest took %v under the lock", took)
	}
	if delay < 20*time.Millisecond || delay > 125*time.Millisecond {
		t.Fatalf("delay = %v, want 20-125 ms", delay)
	}
	if len(responses) != 1 || len(responses[0].msg.Answer) != 10 {
		t.Fatalf("responses = %v", responses)
	}
}
