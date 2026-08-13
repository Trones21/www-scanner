package resolve

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// The pool exists because of a measured wall, not a theoretical one.
//
// miekg/dns opens a fresh UDP socket per query, so in-flight queries consume
// ephemeral ports one for one. At 10,000 workers a scan held 28,236 unique
// local UDP ports against a range of 28,232 — completely saturated — and 46%
// of DNS queries timed out as a result.
//
// The design notes had dismissed ephemeral port exhaustion, reasoning that the
// 4-tuple includes the destination and destinations vary constantly. That
// holds for HTTP, where TCP sockets peaked at a harmless 2,312 against
// thousands of distinct web servers. It does not hold for DNS, where every
// query goes to one of three upstreams, so the port space is shared exactly
// the way it is when hammering a single host.
//
// The fix is what the 16-bit DNS message ID is for: many concurrent queries
// over one socket, demultiplexed by ID on the way back. A handful of sockets
// replaces tens of thousands.

// maxIDAttempts bounds the search for an unused message ID. With a 16-bit
// space and realistic in-flight counts a free ID is found on the first or
// second try; this only guards against a socket that has genuinely filled up.
const maxIDAttempts = 64

// waiter is one outstanding query.
type waiter struct {
	ch    chan *dns.Msg
	qname string
	qtype uint16
}

// conn is a single connected UDP socket carrying many concurrent queries.
type conn struct {
	pc     *net.UDPConn
	server string

	mu       sync.Mutex
	inflight map[uint16]waiter
	closed   bool
}

func dialConn(server string) (*conn, error) {
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream %s: %w", server, err)
	}
	// Connected UDP: one ephemeral port for the socket's whole lifetime,
	// however many queries pass through it.
	pc, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", server, err)
	}
	c := &conn{pc: pc, server: server, inflight: make(map[uint16]waiter)}
	go c.readLoop()
	return c, nil
}

// register claims an unused message ID for a query.
func (c *conn) register(w waiter) (uint16, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, false
	}
	for range maxIDAttempts {
		id := uint16(rand.UintN(1 << 16))
		if _, taken := c.inflight[id]; !taken {
			c.inflight[id] = w
			return id, true
		}
	}
	return 0, false
}

func (c *conn) unregister(id uint16) {
	c.mu.Lock()
	delete(c.inflight, id)
	c.mu.Unlock()
}

// readLoop demultiplexes responses until the socket closes.
func (c *conn) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := c.pc.Read(buf)
		if err != nil {
			return // socket closed, or a fatal read error
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			continue // malformed; the query will time out on its own
		}

		c.mu.Lock()
		w, ok := c.inflight[msg.Id]
		if ok {
			// The ID alone is not enough. A query that timed out releases
			// its ID, a later query can be handed the same one, and the
			// original late answer would then be delivered to the wrong
			// caller — a silent wrong-address bug. The question section
			// has to agree too.
			if len(msg.Question) != 1 ||
				!equalName(msg.Question[0].Name, w.qname) ||
				msg.Question[0].Qtype != w.qtype {
				ok = false
			} else {
				delete(c.inflight, msg.Id)
			}
		}
		c.mu.Unlock()

		if ok {
			select {
			case w.ch <- msg:
			default: // caller already gave up
			}
		}
	}
}

func (c *conn) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.pc.Close()
}

// exchange sends one query and waits for its answer.
func (c *conn) exchange(ctx context.Context, m *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	if len(m.Question) != 1 {
		return nil, errors.New("query must have exactly one question")
	}
	ch := make(chan *dns.Msg, 1)
	id, ok := c.register(waiter{ch: ch, qname: m.Question[0].Name, qtype: m.Question[0].Qtype})
	if !ok {
		return nil, errSocketFull
	}
	defer c.unregister(id)

	m.Id = id
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	if _, err := c.pc.Write(packed); err != nil {
		return nil, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case resp := <-ch:
		return resp, nil
	case <-timer.C:
		return nil, errTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var (
	errSocketFull = errors.New("dns socket has no free message id")
	errTimeout    = &timeoutError{}
)

type timeoutError struct{}

func (*timeoutError) Error() string   { return "dns query timed out" }
func (*timeoutError) Timeout() bool   { return true }
func (*timeoutError) Temporary() bool { return true }

// pool holds the sockets shared by every worker in a scan.
type pool struct {
	conns []*conn
	next  atomic.Uint64
}

// newPool opens perServer sockets against each upstream. Total ephemeral port
// consumption is len(servers)*perServer for the whole process, regardless of
// how many queries are in flight.
func newPool(servers []string, perServer int) (*pool, error) {
	if perServer <= 0 {
		perServer = 1
	}
	p := &pool{}
	for _, s := range servers {
		for range perServer {
			c, err := dialConn(s)
			if err != nil {
				p.close()
				return nil, err
			}
			p.conns = append(p.conns, c)
		}
	}
	if len(p.conns) == 0 {
		return nil, errors.New("no dns sockets opened")
	}
	return p, nil
}

// pick returns the next socket, round-robin. Spreading queries evenly keeps
// any one socket's ID space sparse and spreads load across upstreams.
func (p *pool) pick() *conn {
	return p.conns[int(p.next.Add(1))%len(p.conns)]
}

// pickOther returns a socket on a different upstream than avoid, so a retry
// after a timeout is not sent straight back to the server that ignored it.
func (p *pool) pickOther(avoid string) *conn {
	for range len(p.conns) {
		c := p.pick()
		if c.server != avoid {
			return c
		}
	}
	return p.pick()
}

func (p *pool) close() {
	for _, c := range p.conns {
		c.close()
	}
}

// Sockets reports how many UDP sockets, and therefore ephemeral ports, the
// pool holds.
func (p *pool) Sockets() int { return len(p.conns) }

// equalName compares DNS names case-insensitively, as the protocol requires.
// Some resolvers echo the question with randomized case (0x20 encoding), so a
// byte-equal comparison would drop perfectly good answers.
func equalName(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
