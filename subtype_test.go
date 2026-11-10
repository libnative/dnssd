package dnssd

import (
	"math/rand"
	"net"
	"reflect"
	"testing"

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
