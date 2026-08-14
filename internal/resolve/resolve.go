// Package resolve is a raw DNS client that does what it is told.
//
// The standard library resolver is not usable here for two reasons. It cannot
// distinguish NXDOMAIN from NOERROR-with-no-answers, which is the exact
// distinction the wildcard question turns on. And on the cgo path it blocks an
// OS thread per getaddrinfo, which puts a ceiling on in-flight concurrency
// that has nothing to do with the network.
//
// So: miekg/dns, explicit upstreams, explicit timeouts, rcodes reported rather
// than flattened into an error.
package resolve

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/trones/www-scanner/internal/record"
)

// Answer is the outcome of asking for one name.
type Answer struct {
	Status  record.Resolve
	RRTypes record.RRTypes
	Addrs   []net.IP
}

// Config controls resolver behaviour.
type Config struct {
	// Servers are upstream resolvers as host:port. Queries round-robin
	// across them, which spreads per-server rate limiting.
	//
	// Use only non-filtering resolvers. Anything that blocks domains —
	// malware lists, ad blocking, parental filtering — signals a block by
	// returning NXDOMAIN, which is exactly the answer this scanner treats
	// as "nobody configured this name". A filtering resolver reports its
	// own policy as a finding about the web.
	//
	// Open resolvers are worse and must not be used to widen the pool. Many
	// hijack NXDOMAIN to a search or ad page, which does not add noise to
	// the headline number so much as invert it: every missing name reads as
	// present, and the random-label wildcard probe reports every zone as a
	// wildcard.
	Servers []string
	// Timeout bounds a single query attempt, not the whole lookup.
	Timeout time.Duration
	// Attempts is the number of tries per query before giving up.
	Attempts int
	// UDPSize is the advertised EDNS0 buffer. 1232 is the DNS flag day
	// number: large enough to avoid most TCP fallback, small enough to
	// avoid IP fragmentation.
	UDPSize uint16
	// SocketsPerServer is how many multiplexed UDP sockets to open against
	// each upstream. Concurrency is bounded by the 16-bit message ID space
	// per socket, not by the socket count, so this stays small.
	//
	// Zero selects the legacy path: one fresh socket per query, which burns
	// one ephemeral port per in-flight query and saturates the range at
	// around 10,000 workers. Kept only so the two can be measured against
	// each other.
	SocketsPerServer int
}

// DefaultConfig returns settings tuned for a scan rather than for a shell.
func DefaultConfig() Config {
	return Config{
		Timeout:          3 * time.Second,
		Attempts:         2,
		UDPSize:          1232,
		SocketsPerServer: 8,
	}
}

// Resolver issues DNS queries against a fixed set of upstreams.
type Resolver struct {
	cfg  Config
	pool *pool // nil on the legacy one-socket-per-query path
	udp  *dns.Client
	tcp  *dns.Client
	next atomic.Uint64
}

// New builds a Resolver. If cfg.Servers is empty it falls back to
// /etc/resolv.conf, which on a systemd machine means the 127.0.0.53 stub —
// fine for a handful of domains, and the first thing to replace when the
// worker count goes up.
func New(cfg Config) (*Resolver, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 2
	}
	if cfg.UDPSize == 0 {
		cfg.UDPSize = 1232
	}
	if len(cfg.Servers) == 0 {
		servers, err := systemServers()
		if err != nil {
			return nil, err
		}
		cfg.Servers = servers
	}
	for i, s := range cfg.Servers {
		cfg.Servers[i] = withDefaultPort(s)
	}
	r := &Resolver{
		cfg: cfg,
		udp: &dns.Client{Net: "udp", Timeout: cfg.Timeout, UDPSize: cfg.UDPSize},
		tcp: &dns.Client{Net: "tcp", Timeout: cfg.Timeout},
	}
	if cfg.SocketsPerServer > 0 {
		p, err := newPool(cfg.Servers, cfg.SocketsPerServer)
		if err != nil {
			return nil, err
		}
		r.pool = p
	}
	return r, nil
}

// Servers reports the upstreams in use, for logging what a run actually asked.
func (r *Resolver) Servers() []string { return r.cfg.Servers }

// Sockets reports how many UDP sockets — and so how many ephemeral ports —
// the resolver holds for the life of the process. Zero means the legacy path,
// where the number is instead "one per query in flight".
func (r *Resolver) Sockets() int {
	if r.pool == nil {
		return 0
	}
	return r.pool.Sockets()
}

// Close releases the socket pool.
func (r *Resolver) Close() {
	if r.pool != nil {
		r.pool.close()
	}
}

// Lookup asks for A and AAAA concurrently and merges them into one Answer.
//
// The merge is deliberately optimistic on success and conservative on failure:
// one address of either family means the name resolves, but a definitive
// NXDOMAIN is only reported when nothing contradicts it.
func (r *Resolver) Lookup(ctx context.Context, name string) Answer {
	type result struct {
		ans Answer
		qt  uint16
	}
	ch := make(chan result, 2)
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		go func(qt uint16) {
			ch <- result{r.query(ctx, name, qt), qt}
		}(qt)
	}

	var merged Answer
	statuses := make([]record.Resolve, 0, 2)
	for range 2 {
		res := <-ch
		merged.RRTypes |= res.ans.RRTypes
		merged.Addrs = append(merged.Addrs, res.ans.Addrs...)
		statuses = append(statuses, res.ans.Status)
	}
	merged.Status = mergeStatus(statuses[0], statuses[1])
	return merged
}

// mergeStatus combines the A and AAAA outcomes for the same name.
//
// Order matters. An answer beats everything. NoData beats NXDOMAIN because a
// name that exists for one family exists, full stop — reporting NXDOMAIN there
// would be a false negative on the headline number. A transport failure only
// wins when nothing authoritative came back at all.
func mergeStatus(a, b record.Resolve) record.Resolve {
	rank := func(s record.Resolve) int {
		switch s {
		case record.ResolveOK:
			return 5
		case record.ResolveNoData:
			return 4
		case record.ResolveNXDOMAIN:
			return 3
		case record.ResolveRefused:
			return 2
		case record.ResolveServfail:
			return 1
		default: // timeout, error
			return 0
		}
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

// Delegation asks the parent what it knows about a name, independent of
// whether an address exists.
//
// An address lookup conflates three different facts into "did not resolve":
// nobody registered the name, somebody registered it and pointed it nowhere,
// and somebody registered it and the nameservers are dead. Querying NS
// separates them, which matters once the corpus is a registry zone file and
// every entry is registered by construction.
func (r *Resolver) Delegation(ctx context.Context, name string) record.Delegation {
	fqdn := dns.Fqdn(name)
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeNS)
	m.SetEdns0(r.cfg.UDPSize, false)
	m.RecursionDesired = true

	resp, err := r.exchange(ctx, m)
	if err != nil {
		return record.DelegationBroken
	}
	switch resp.Rcode {
	case dns.RcodeNameError:
		return record.DelegationNone
	case dns.RcodeServerFailure, dns.RcodeRefused:
		return record.DelegationBroken
	case dns.RcodeSuccess:
		for _, rr := range resp.Answer {
			if _, ok := rr.(*dns.NS); ok {
				return record.DelegationOK
			}
		}
		// NOERROR with no NS in the answer. Recursive resolvers often put
		// the delegation in AUTHORITY instead, so check there before
		// concluding the name has none.
		for _, rr := range resp.Ns {
			if _, ok := rr.(*dns.NS); ok {
				return record.DelegationOK
			}
		}
		return record.DelegationNoData
	}
	return record.DelegationBroken
}

// Exists reports whether a name resolves at all, without caring what to. Used
// for the wildcard probe, where the only question is whether a label nobody
// configured still comes back with an address.
func (r *Resolver) Exists(ctx context.Context, name string) (bool, bool) {
	ans := r.query(ctx, name, dns.TypeA)
	switch ans.Status {
	case record.ResolveOK:
		return true, true
	case record.ResolveNXDOMAIN, record.ResolveNoData:
		return false, true
	default:
		return false, false // inconclusive; don't record a wildcard verdict
	}
}

// WildcardLabel returns a name under domain that nobody could plausibly have
// configured. If this resolves, the zone has a wildcard and www resolving
// proves nothing.
func WildcardLabel(domain string) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var sb strings.Builder
	sb.Grow(16 + len(domain))
	for range 15 {
		sb.WriteByte(alphabet[rand.IntN(len(alphabet))])
	}
	sb.WriteByte('.')
	sb.WriteString(domain)
	return sb.String()
}

// exchange sends one prepared message with the configured retries and returns
// the raw response, so callers that care about rcodes rather than addresses do
// not have to reimplement the retry and pool logic.
func (r *Resolver) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	var lastServer string
	var lastErr error
	for range r.cfg.Attempts {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var resp *dns.Msg
		var err error
		var server string
		if r.pool != nil {
			c := r.pool.pick()
			if lastServer != "" {
				c = r.pool.pickOther(lastServer)
			}
			server = c.server
			resp, err = c.exchange(ctx, m.Copy(), r.cfg.Timeout)
		} else {
			server = r.cfg.Servers[int(r.next.Add(1))%len(r.cfg.Servers)]
			resp, _, err = r.udp.ExchangeContext(ctx, m, server)
		}
		lastServer = server
		if err == nil && resp != nil && resp.Truncated {
			resp, _, err = r.tcp.ExchangeContext(ctx, m, server)
		}
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errTimeout
	}
	return nil, lastErr
}

func (r *Resolver) query(ctx context.Context, name string, qtype uint16) Answer {
	fqdn := dns.Fqdn(name)
	m := new(dns.Msg)
	m.SetQuestion(fqdn, qtype)
	m.SetEdns0(r.cfg.UDPSize, false)
	m.RecursionDesired = true

	var last Answer
	var lastServer string
	for range r.cfg.Attempts {
		if ctx.Err() != nil {
			return Answer{Status: record.ResolveTimeout}
		}

		var resp *dns.Msg
		var err error
		var server string

		if r.pool != nil {
			c := r.pool.pick()
			if lastServer != "" {
				// Retry somewhere else: sending straight back to the
				// server that just ignored us mostly buys another timeout.
				c = r.pool.pickOther(lastServer)
			}
			server = c.server
			// Pack mutates the ID, so each attempt needs its own copy.
			resp, err = c.exchange(ctx, m.Copy(), r.cfg.Timeout)
		} else {
			server = r.cfg.Servers[int(r.next.Add(1))%len(r.cfg.Servers)]
			resp, _, err = r.udp.ExchangeContext(ctx, m, server)
		}
		lastServer = server

		if err == nil && resp != nil && resp.Truncated {
			// Fall back to TCP rather than reporting a partial answer.
			// Truncation is rare enough that a socket per occurrence is
			// not worth pooling.
			resp, _, err = r.tcp.ExchangeContext(ctx, m, server)
		}
		if err != nil {
			last = Answer{Status: classifyNetErr(err)}
			// A refusal or a servfail is an answer; retrying is pointless.
			// Only transport failures are worth another attempt.
			if last.Status != record.ResolveTimeout && last.Status != record.ResolveError {
				return last
			}
			continue
		}
		return fromMsg(resp, qtype)
	}
	return last
}

// LookupAddrs resolves a name to addresses for the HTTP dialer, so the scan
// makes one DNS query per name instead of two.
//
// Before this existed, every name was resolved once by the classifier and then
// a second time by http.Transport's own net.Resolver — doubling both the query
// volume and, on the legacy path, the ephemeral ports consumed.
func (r *Resolver) LookupAddrs(ctx context.Context, name string) ([]net.IP, error) {
	ans := r.Lookup(ctx, name)
	if ans.Status != record.ResolveOK || len(ans.Addrs) == 0 {
		return nil, &net.DNSError{
			Err:        ans.Status.String(),
			Name:       name,
			IsNotFound: ans.Status == record.ResolveNXDOMAIN || ans.Status == record.ResolveNoData,
			IsTimeout:  ans.Status == record.ResolveTimeout,
		}
	}
	return ans.Addrs, nil
}

func fromMsg(resp *dns.Msg, qtype uint16) Answer {
	switch resp.Rcode {
	case dns.RcodeNameError:
		return Answer{Status: record.ResolveNXDOMAIN}
	case dns.RcodeServerFailure:
		return Answer{Status: record.ResolveServfail}
	case dns.RcodeRefused:
		return Answer{Status: record.ResolveRefused}
	case dns.RcodeSuccess:
		// keep going
	default:
		return Answer{Status: record.ResolveError}
	}

	var ans Answer
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ans.RRTypes |= record.RRA
			ans.Addrs = append(ans.Addrs, v.A)
		case *dns.AAAA:
			ans.RRTypes |= record.RRAAAA
			ans.Addrs = append(ans.Addrs, v.AAAA)
		case *dns.CNAME:
			// A CNAME in the answer chain is worth recording on its own:
			// it is the fingerprint of a name pointed at a CDN, which is
			// how www got configured for most of the years it mattered.
			ans.RRTypes |= record.RRCNAME
		}
	}
	if len(ans.Addrs) > 0 {
		ans.Status = record.ResolveOK
	} else {
		// NOERROR with nothing of the requested type. The name exists.
		ans.Status = record.ResolveNoData
	}
	_ = qtype
	return ans
}

func classifyNetErr(err error) record.Resolve {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return record.ResolveTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return record.ResolveTimeout
	}
	return record.ResolveError
}

func withDefaultPort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

func systemServers() ([]string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read system resolvers: %w", err)
	}
	defer f.Close()

	var servers []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read system resolvers: %w", err)
	}
	if len(servers) == 0 {
		return nil, errors.New("no nameserver lines in /etc/resolv.conf")
	}
	return servers, nil
}
