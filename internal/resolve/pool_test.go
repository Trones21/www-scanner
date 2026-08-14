package resolve

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/trones/www-scanner/internal/record"
)

// synthServer is an authoritative DNS server over loopback that answers
// anything instantly.
//
// It exists to measure the resolver with the network removed. Every throughput
// number so far has been a property of somebody's uplink or rate limiter; this
// is the control they should be compared against. If the client cannot saturate
// a server sitting on loopback, no amount of network is the problem.
type synthServer struct {
	pc      *net.UDPConn
	addr    string
	queries atomic.Int64
	// delay simulates a real resolver's latency, so a test can check the
	// pool multiplexes rather than serializing behind one slow answer.
	delay time.Duration
	// drop makes every Nth query vanish, the way a rate limiter does.
	drop int
	wg   sync.WaitGroup
}

func newSynthServer(t *testing.T, delay time.Duration, drop int) *synthServer {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Hundreds of queries can land within microseconds of each other. The
	// default receive buffer overflows, the kernel drops the excess, and the
	// client dutifully waits out its timeout — which looks exactly like the
	// pool failing to multiplex. Give the harness room so it measures the
	// client rather than itself.
	_ = pc.SetReadBuffer(4 << 20)
	s := &synthServer{pc: pc, addr: pc.LocalAddr().String(), delay: delay, drop: drop}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() { pc.Close(); s.wg.Wait() })
	return s
}

func (s *synthServer) serve() {
	defer s.wg.Done()
	for {
		// A fresh buffer per packet so the read loop can hand off without
		// waiting for anything. Parsing in this loop would serialize every
		// response behind one unpack.
		buf := make([]byte, 1500)
		n, from, err := s.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		seq := s.queries.Add(1)
		if s.drop > 0 && seq%int64(s.drop) == 0 {
			continue // silently dropped, exactly like a rate limiter
		}
		go s.answer(buf[:n], from)
	}
}

func (s *synthServer) answer(payload []byte, to *net.UDPAddr) {
	req := new(dns.Msg)
	if err := req.Unpack(payload); err != nil {
		return
	}
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name: req.Question[0].Name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: 300,
			},
			A: net.IPv4(192, 0, 2, 1),
		})
	}
	packed, err := resp.Pack()
	if err != nil {
		return
	}
	s.pc.WriteToUDP(packed, to)
}

func newTestResolver(t *testing.T, server string, sockets int) *Resolver {
	return newTestResolverTimeout(t, server, sockets, 2*time.Second)
}

func newTestResolverTimeout(t *testing.T, server string, sockets int, timeout time.Duration) *Resolver {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Servers = []string{server}
	cfg.SocketsPerServer = sockets
	cfg.Timeout = timeout
	cfg.Attempts = 2
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestPoolResolvesConcurrently(t *testing.T) {
	s := newSynthServer(t, 0, 0)
	r := newTestResolver(t, s.addr, 4)

	var wg sync.WaitGroup
	errs := make(chan string, 200)
	for i := range 200 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ans := r.Lookup(context.Background(), fmt.Sprintf("host%d.example.com", i))
			if ans.Status != record.ResolveOK {
				errs <- fmt.Sprintf("host%d: %v", i, ans.Status)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("lookup failed: %s", e)
	}
}

// The whole point of the pool: concurrency is bounded by the 16-bit message ID
// space, not by the socket count. Four sockets must carry hundreds of
// simultaneous queries without serializing behind each other.
func TestPoolMultiplexesRatherThanSerializing(t *testing.T) {
	const delay = 50 * time.Millisecond
	const queries = 300

	s := newSynthServer(t, delay, 0)
	r := newTestResolver(t, s.addr, 2)

	start := time.Now()
	var wg sync.WaitGroup
	for i := range queries {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.Lookup(context.Background(), fmt.Sprintf("h%d.example.com", i))
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Serialized, this would take queries*delay. Multiplexed it should
	// finish in a small multiple of one delay.
	serial := time.Duration(queries) * delay
	if elapsed > serial/10 {
		t.Errorf("300 queries over 2 sockets took %s; serialized would be %s — the pool is not multiplexing",
			elapsed.Round(time.Millisecond), serial)
	}
}

// A response arriving after its query gave up must not be handed to whichever
// query later inherited that message ID. Without the question check this is a
// silent wrong-address bug, which is far worse than a timeout.
func TestPoolRejectsMismatchedQuestion(t *testing.T) {
	s := newSynthServer(t, 0, 0)
	c, err := dialConn(s.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.close()

	ch := make(chan *dns.Msg, 1)
	id, ok := c.register(waiter{ch: ch, qname: "expected.example.com.", qtype: dns.TypeA})
	if !ok {
		t.Fatal("could not register a waiter")
	}
	defer c.unregister(id)

	// An answer with the right ID but the wrong question.
	wrong := new(dns.Msg)
	wrong.SetQuestion("somethingelse.example.com.", dns.TypeA)
	wrong.Id = id
	wrong.Response = true
	packed, err := wrong.Pack()
	if err != nil {
		t.Fatal(err)
	}
	c.pc.Write(packed)

	select {
	case got := <-ch:
		t.Fatalf("accepted an answer for %q while waiting on expected.example.com",
			got.Question[0].Name)
	case <-time.After(250 * time.Millisecond):
		// correct: dropped
	}
}

func TestPoolRetriesDroppedQueries(t *testing.T) {
	// Every second query vanishes. With 2 attempts, lookups should still
	// mostly succeed. The timeout is deliberately tiny: a dropped query is
	// only detectable by waiting one out, so a realistic value would make
	// this test take minutes to prove a millisecond of logic.
	s := newSynthServer(t, 0, 2)
	r := newTestResolverTimeout(t, s.addr, 2, 60*time.Millisecond)

	ok := 0
	for i := range 40 {
		if r.Lookup(context.Background(), fmt.Sprintf("r%d.example.com", i)).Status == record.ResolveOK {
			ok++
		}
	}
	if ok < 30 {
		t.Errorf("only %d/40 lookups survived a 50%% drop rate; retries are not working", ok)
	}
}

func TestPoolReportsSocketCount(t *testing.T) {
	s := newSynthServer(t, 0, 0)
	r := newTestResolver(t, s.addr, 8)
	if got := r.Sockets(); got != 8 {
		t.Errorf("Sockets() = %d, want 8", got)
	}

	legacy := newTestResolver(t, s.addr, 0)
	if got := legacy.Sockets(); got != 0 {
		t.Errorf("legacy path reported %d pooled sockets, want 0", got)
	}
}

// BenchmarkResolverCeiling measures lookups per second against a server on
// loopback — the resolver's ceiling with the network entirely removed.
//
// This is the control for every field measurement. A residential line gave ~110
// domains/sec and a rate-limited VPS gave 15; neither says anything about the
// client until compared against what it does when nothing is in the way.
//
//	go test ./internal/resolve/ -bench Ceiling -benchtime 5s
func BenchmarkResolverCeiling(b *testing.B) {
	for _, sockets := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("sockets=%d", sockets), func(b *testing.B) {
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				b.Fatal(err)
			}
			defer pc.Close()
			s := &synthServer{pc: pc, addr: pc.LocalAddr().String()}
			s.wg.Add(1)
			go s.serve()

			cfg := DefaultConfig()
			cfg.Servers = []string{s.addr}
			cfg.SocketsPerServer = sockets
			cfg.Timeout = 2 * time.Second
			r, err := New(cfg)
			if err != nil {
				b.Fatal(err)
			}
			defer r.Close()

			ctx := context.Background()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					i++
					r.Lookup(ctx, fmt.Sprintf("b%d.example.com", i))
				}
			})
			b.StopTimer()
			// One Lookup is two queries: A and AAAA.
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "lookups/s")
			b.ReportMetric(float64(b.N)*2/b.Elapsed().Seconds(), "queries/s")
		})
	}
}
