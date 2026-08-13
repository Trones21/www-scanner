// Package probe classifies one domain: the DNS -> TCP -> TLS -> HTTP ladder
// for both the apex and www, and the canonical direction between them.
//
// No browser anywhere in the pipeline. Redirects are reported rather than
// silently followed by a transport, http:// is never upgraded on our behalf,
// and a timeout is described as a timeout.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/trones/www-scanner/internal/record"
	"github.com/trones/www-scanner/internal/resolve"
)

// Config controls one prober.
type Config struct {
	// Timeout bounds a whole per-name HTTP attempt including redirects.
	Timeout time.Duration
	// ConnectTimeout bounds the TCP handshake alone.
	ConnectTimeout time.Duration
	// MaxHops caps the redirect chain. Beyond this the chain is recorded
	// as terminating wherever it had got to.
	MaxHops int
	// HTTPFallback retries over plaintext when the TLS handshake fails, so
	// an http-only site still yields a status and a redirect chain. The TLS
	// failure is still what gets recorded in the TLS field.
	HTTPFallback bool
	// WildcardCheck probes a random label when www resolves, to tell
	// "someone configured www" apart from "the zone answers to everything".
	WildcardCheck bool
	// UserAgent identifies the scanner. Being identifiable is the polite
	// minimum when you are about to knock on a million doors.
	UserAgent string
}

// DefaultConfig returns settings suited to a wide scan of mostly-cold hosts.
func DefaultConfig() Config {
	return Config{
		Timeout:        10 * time.Second,
		ConnectTimeout: 5 * time.Second,
		MaxHops:        10,
		HTTPFallback:   true,
		WildcardCheck:  true,
		UserAgent:      "www-scanner/0.1 (+https://thomasrones.com/does-www-still-work)",
	}
}

// Prober holds the resolver and HTTP transport shared by all workers.
//
// One transport for the whole scan, not one per domain: the connection pool,
// the fd budget and the TLS session cache are process-wide resources, and the
// point of the exercise is to find out which of them gives out first.
type Prober struct {
	cfg      Config
	res      *resolve.Resolver
	client   *http.Client
	insecure *http.Client
}

// New builds a Prober over the given resolver.
func New(cfg Config, res *resolve.Resolver, maxConns int) *Prober {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if cfg.MaxHops <= 0 {
		cfg.MaxHops = 10
	}
	p := &Prober{cfg: cfg, res: res}
	p.client = newClient(cfg, res, maxConns, false)
	p.insecure = newClient(cfg, res, maxConns, true)
	return p
}

func newClient(cfg Config, res *resolve.Resolver, maxConns int, insecure bool) *http.Client {
	dialer := &net.Dialer{
		Timeout: cfg.ConnectTimeout,
		// Every host is contacted once, so keepalive buys nothing and
		// holding the socket open costs an fd we would rather spend on
		// the next domain.
		KeepAlive: -1,
	}
	tr := &http.Transport{
		DialContext:         dialThrough(res, dialer),
		TLSHandshakeTimeout: cfg.ConnectTimeout,
		// Defaults are MaxIdleConnsPerHost 2 / MaxIdleConns 100, which is
		// sized for a load test against one origin. Here every request is
		// a different origin, so the cap that matters is the total.
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: 2,
		MaxConnsPerHost:     4,
		IdleConnTimeout:     10 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure, //nolint:gosec // deliberate: see probeName
			MinVersion:         tls.VersionTLS10,
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
		// The whole question is where the chain points, so the chain must
		// not be walked behind our back.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Probe classifies one domain end to end.
func (p *Prober) Probe(ctx context.Context, domain string) record.Record {
	start := time.Now()
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	www := "www." + domain

	var rec record.Record

	// Both names are independent until the comparison at the end, so they
	// go out together. This halves the wall time of the common case, where
	// most of the elapsed time is spent waiting.
	type sideResult struct {
		side     record.Side
		host     string
		fellBack bool
	}
	apexCh := make(chan sideResult, 1)
	wwwCh := make(chan sideResult, 1)
	go func() { s, h, fb := p.probeName(ctx, domain, domain); apexCh <- sideResult{s, h, fb} }()
	go func() { s, h, fb := p.probeName(ctx, www, domain); wwwCh <- sideResult{s, h, fb} }()
	apexRes, wwwRes := <-apexCh, <-wwwCh

	rec.Apex, rec.WWW = apexRes.side, wwwRes.side
	if apexRes.fellBack || wwwRes.fellBack {
		rec.Flags |= record.FlagHTTPFallback
	}

	// Only worth asking when www came back with something. If www is
	// NXDOMAIN there is no false positive to rule out, and the query is a
	// third of the DNS budget spent to learn nothing.
	if p.cfg.WildcardCheck && rec.WWW.Resolve == record.ResolveOK {
		if exists, conclusive := p.res.Exists(ctx, resolve.WildcardLabel(domain)); conclusive {
			rec.Flags |= record.FlagWildcardChecked
			if exists {
				rec.Flags |= record.FlagWildcard
			}
		}
	}

	rec.Canonical = classifyCanonical(rec.Apex, rec.WWW, apexRes.host, wwwRes.host, domain)

	if ctx.Err() != nil {
		rec.Status = record.StatusAborted
	} else {
		rec.Status = record.StatusComplete
	}
	rec.DurationM = saturateMS(time.Since(start))
	return rec
}

// probeName walks the ladder for a single hostname and returns the side, the
// host the redirect chain came to rest on, and whether the recorded HTTP
// outcome came from the plaintext fallback rather than the secure attempt.
func (p *Prober) probeName(ctx context.Context, host, apex string) (record.Side, string, bool) {
	var side record.Side

	ans := p.res.Lookup(ctx, host)
	side.Resolve = ans.Status
	side.RRTypes = ans.RRTypes
	if ans.Status != record.ResolveOK {
		return side, "", false
	}

	terminal, fellBack := p.walk(ctx, &side, "https://"+host+"/", host, apex)

	// A TLS failure stops the secure chain but says nothing about whether
	// the host serves. Retrying in plaintext keeps the http-only long tail
	// from being recorded as dead, and the TLS field still carries why the
	// secure attempt failed.
	if p.cfg.HTTPFallback && side.HTTP == 0 && isTLSFailure(side.TLS) {
		fb := record.Side{Resolve: side.Resolve, RRTypes: side.RRTypes}
		t, _ := p.walk(ctx, &fb, "http://"+host+"/", host, apex)
		if fb.HTTP != 0 {
			fb.TLS = side.TLS // keep the real reason https failed
			return fb, t, true
		}
	}
	return side, terminal, fellBack
}

// walk follows the redirect chain by hand, one request at a time, and reports
// the host it came to rest on.
func (p *Prober) walk(ctx context.Context, side *record.Side, startURL, origin, apex string) (string, bool) {
	current := startURL
	lastHost := ""

	for hop := 0; hop <= p.cfg.MaxHops; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			side.TCP = record.TCPError
			break
		}
		req.Header.Set("User-Agent", p.cfg.UserAgent)
		req.Header.Set("Accept", "*/*")

		resp, err := p.client.Do(req)
		if err != nil {
			// Only the first hop tells us about this name's own transport.
			// A failure three redirects deep is somebody else's problem and
			// would be a lie in this name's TCP or TLS field.
			if hop == 0 {
				classifyTransportErr(side, err, strings.HasPrefix(current, "https://"))
			}
			break
		}
		// The body is never read: the answer is entirely in the status line
		// and the Location header, and at a million domains the bytes we
		// decline to read are the difference between a scan and a download.
		resp.Body.Close()

		if strings.HasPrefix(current, "https://") {
			side.TLS = record.TLSOK
		}
		side.TCP = record.TCPOK
		side.HTTP = uint16(resp.StatusCode)
		side.Hops = uint8(hop)
		lastHost = hostOf(current)

		loc := resp.Header.Get("Location")
		if !isRedirect(resp.StatusCode) || loc == "" {
			break
		}
		next, err := resolveRef(current, loc)
		if err != nil || next == current {
			break // unparseable Location, or a self-redirect loop
		}
		current = next
	}

	// Nothing answered, so there is no chain and no terminal host. Saying
	// "self" here would read as "it served its own name", which is the
	// opposite of what happened.
	if side.HTTP == 0 {
		side.Terminal = record.TerminalNone
		return "", false
	}
	side.Terminal = classifyTerminal(lastHost, origin, apex)
	return lastHost, false
}

func classifyTerminal(terminal, origin, apex string) record.Terminal {
	if terminal == "" {
		return record.TerminalNone
	}
	switch terminal {
	case origin:
		return record.TerminalSelf
	case apex:
		return record.TerminalApex
	case "www." + apex:
		return record.TerminalWWW
	}
	if strings.HasSuffix(terminal, "."+apex) {
		return record.TerminalSameSite
	}
	return record.TerminalExternal
}

// classifyCanonical answers the cultural half of the question: when both names
// work, which one is the real one?
func classifyCanonical(apex, www record.Side, apexTerm, wwwTerm, domain string) record.Canonical {
	apexOK := servesOK(apex)
	wwwOK := servesOK(www)

	switch {
	case !apexOK && !wwwOK:
		return record.CanonicalBothFail
	case apexOK && !wwwOK:
		return record.CanonicalApexOnly
	case !apexOK && wwwOK:
		return record.CanonicalWWWOnly
	}

	// Both answer. The terminal hosts decide, and only a real redirect
	// counts as a declaration — matching terminals reached without moving
	// is two sites that happen to agree, not a canonical form.
	wwwMoved := www.Hops > 0 || wwwTerm != "www."+domain
	apexMoved := apex.Hops > 0 || apexTerm != domain

	switch {
	case wwwMoved && wwwTerm == domain && !apexMoved:
		return record.CanonicalWWWToApex
	case apexMoved && apexTerm == "www."+domain && !wwwMoved:
		return record.CanonicalApexToWWW
	case wwwMoved && wwwTerm == domain && apexMoved && apexTerm == "www."+domain:
		// Each points at the other. Pathological, and rarer than it
		// sounds, but a redirect loop is not a canonical form.
		return record.CanonicalBothServe
	case wwwTerm == apexTerm && wwwMoved:
		// Both funnel somewhere else entirely, e.g. a marketing host.
		return record.CanonicalWWWToApex
	default:
		// The interesting branch: two independent 200s and nothing
		// declaring a winner. csv-helper.com is parked here on purpose.
		return record.CanonicalBothServe
	}
}

func servesOK(s record.Side) bool {
	return s.HTTP >= 200 && s.HTTP < 400
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

func isTLSFailure(t record.TLS) bool {
	return t != record.TLSUnattempted && t != record.TLSOK
}

// classifyTransportErr unpicks a Go transport error into the specific rung of
// the ladder that broke. Certificate name mismatch is the one that matters
// most: it is what you get when you add a www record and forget the cert.
func classifyTransportErr(side *record.Side, err error, wasTLS bool) {
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		side.TCP = record.TCPOK
		side.TLS = record.TLSNameMismatch
		return
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		side.TCP = record.TCPOK
		side.TLS = record.TLSUnknownAuthority
		return
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		side.TCP = record.TCPOK
		if invalidErr.Reason == x509.Expired {
			side.TLS = record.TLSExpired
		} else {
			side.TLS = record.TLSHandshakeFail
		}
		return
	}
	var recordErr *tls.RecordHeaderError
	var alertErr tls.AlertError
	if errors.As(err, &recordErr) || errors.As(err, &alertErr) {
		side.TCP = record.TCPOK
		side.TLS = record.TLSHandshakeFail
		return
	}

	// Not a certificate problem, so it is the transport underneath.
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		side.TCP = record.TCPRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		side.TCP = record.TCPUnreachable
	case isTimeout(err):
		// A timeout during the handshake is a different finding from a
		// timeout before the connection was up.
		if wasTLS && strings.Contains(err.Error(), "TLS handshake timeout") {
			side.TCP = record.TCPOK
			side.TLS = record.TLSTimeout
		} else {
			side.TCP = record.TCPTimeout
		}
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		side.TCP = record.TCPOK
		if wasTLS {
			side.TLS = record.TLSHandshakeFail
		}
	default:
		if wasTLS && strings.Contains(err.Error(), "tls:") {
			side.TCP = record.TCPOK
			side.TLS = record.TLSError
			return
		}
		side.TCP = record.TCPError
	}
}

func isTimeout(err error) bool {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func resolveRef(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", err
	}
	next := b.ResolveReference(r)
	if next.Scheme != "http" && next.Scheme != "https" {
		return "", fmt.Errorf("non-http redirect scheme %q", next.Scheme)
	}
	return next.String(), nil
}

func saturateMS(d time.Duration) uint16 {
	ms := d.Milliseconds()
	if ms < 0 {
		return 0
	}
	if ms > 65535 {
		return 65535
	}
	return uint16(ms)
}

// dialThrough routes the HTTP transport's name resolution through our own
// resolver instead of the standard library's.
//
// Handing http.Transport a hostname makes it resolve that name itself, so
// every probe was paying for two lookups of the same name — ours to classify
// it, and the transport's to connect. That doubled DNS query volume, and on
// the one-socket-per-query path it doubled ephemeral port consumption too,
// which is what actually ran the scan into the port ceiling.
//
// Resolving here also means the address family choice and the failure
// classification stay in one place.
func dialThrough(r *resolve.Resolver, d *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// Redirect targets can already be literals; nothing to resolve.
		if ip := net.ParseIP(host); ip != nil {
			return d.DialContext(ctx, network, addr)
		}

		ips, err := r.LookupAddrs(ctx, host)
		if err != nil {
			return nil, err
		}
		// Try each address in turn: a name with a dead first A record but a
		// live second one is serving, and recording it as dead would be a
		// false negative of exactly the kind this scan is looking for.
		var firstErr error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			if firstErr == nil {
				firstErr = err
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, firstErr
	}
}
