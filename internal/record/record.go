// Package record defines the fixed-width, positional result record.
//
// The Nth record belongs to the Nth corpus entry, so the domain string is
// never stored here. That has three consequences the scanner depends on:
//
//   - No write coordination. Workers write at i*Width into disjoint ranges
//     of one mmap'd file. No lock, no writer goroutine.
//   - Resumption is the zero value. StatusUnattempted is 0, so a freshly
//     allocated file is its own checkpoint and needs nothing kept consistent
//     alongside it.
//   - Run diffs are a merge join. Two (corpus, results) pairs streamed in
//     lockstep emit deltas without querying a billion rows.
//
// Every field is an enum or a small int. Nothing here is variable-width, and
// nothing here is text. Width is multiplied by the corpus size and shares a
// laptop disk with everything else, so it is meant to stay where it is.
package record

import "encoding/binary"

// Width is the size of one encoded Record in bytes.
const Width = 24

// Status describes whether a domain was probed at all.
type Status uint8

const (
	StatusUnattempted Status = 0 // zero value: this is what makes resume free
	StatusComplete    Status = 1
	StatusAborted     Status = 2 // context cancelled mid-probe; retry on resume
)

// Flags is a bitmask of per-domain observations.
type Flags uint8

const (
	// FlagWildcardChecked is set when the random-label probe actually ran.
	// Without it, a clear FlagWildcard is ambiguous between "no wildcard"
	// and "never asked".
	FlagWildcardChecked Flags = 1 << 0
	// FlagWildcard means a random label under the domain resolved, so the
	// fact that www resolves is not evidence anyone configured www.
	FlagWildcard Flags = 1 << 1
	// FlagHTTPFallback means the https attempt failed and the recorded HTTP
	// outcome came from a plaintext retry.
	FlagHTTPFallback Flags = 1 << 2
)

// Resolve is the DNS outcome for one name.
//
// NXDOMAIN and NoData are deliberately distinct. Collapsing them loses the
// wildcard story: a zone with *.example.com never returns NXDOMAIN, so the
// naive "does it resolve" boolean scores it as support.
type Resolve uint8

const (
	ResolveUnattempted Resolve = 0
	ResolveOK          Resolve = 1 // NOERROR with at least one address
	ResolveNXDOMAIN    Resolve = 2 // the name does not exist
	ResolveNoData      Resolve = 3 // NOERROR, zero answers: name exists, no A/AAAA
	ResolveTimeout     Resolve = 4
	ResolveServfail    Resolve = 5
	ResolveRefused     Resolve = 6
	ResolveError       Resolve = 7 // malformed, truncated past TCP retry, etc.
)

// RRTypes is a bitmask of what the answer chain actually contained.
type RRTypes uint8

const (
	RRA     RRTypes = 1 << 0
	RRAAAA  RRTypes = 1 << 1
	RRCNAME RRTypes = 1 << 2
)

// TCP is the transport-connect outcome.
type TCP uint8

const (
	TCPUnattempted TCP = 0
	TCPOK          TCP = 1
	TCPRefused     TCP = 2
	TCPTimeout     TCP = 3
	TCPUnreachable TCP = 4
	TCPError       TCP = 5
)

// TLS is the handshake outcome. Certificate name mismatch is its own class:
// it is a different mistake by a different person than a refused connection,
// and it is the specific failure a site hits when it adds a www record but
// never reissues the certificate.
type TLS uint8

const (
	TLSUnattempted      TLS = 0
	TLSOK               TLS = 1
	TLSNameMismatch     TLS = 2 // handshake completed, no SAN covers the name presented
	TLSExpired          TLS = 3
	TLSUnknownAuthority TLS = 4
	TLSHandshakeFail    TLS = 5
	TLSTimeout          TLS = 6
	TLSError            TLS = 7
)

// Terminal classifies where a redirect chain came to rest, relative to the
// domain being probed. Storing the class rather than the host keeps the
// record fixed-width.
type Terminal uint8

const (
	TerminalNone     Terminal = 0
	TerminalSelf     Terminal = 1 // ended on the same name it started from
	TerminalApex     Terminal = 2
	TerminalWWW      Terminal = 3
	TerminalSameSite Terminal = 4 // another label under the same registrable domain
	TerminalExternal Terminal = 5
)

// Canonical is the cultural question: for domains where something answers,
// which name wins?
type Canonical uint8

const (
	CanonicalUnknown   Canonical = 0
	CanonicalBothFail  Canonical = 1
	CanonicalApexOnly  Canonical = 2 // the shape all four of my domains were in
	CanonicalWWWOnly   Canonical = 3
	CanonicalWWWToApex Canonical = 4
	CanonicalApexToWWW Canonical = 5
	// CanonicalBothServe is the least obvious branch: both names return 200
	// independently and nothing declares a winner.
	CanonicalBothServe Canonical = 6
)

// Side holds the classification ladder for a single name.
type Side struct {
	Resolve  Resolve
	RRTypes  RRTypes
	TCP      TCP
	TLS      TLS
	HTTP     uint16 // status code, 0 if no response
	Terminal Terminal
	Hops     uint8
}

// Record is one corpus entry's full result. Encoded width is Width bytes.
type Record struct {
	Status    Status
	Flags     Flags
	Canonical Canonical
	DurationM uint16 // total probe wall time in ms, saturating
	Apex      Side
	WWW       Side
}

// Encode writes r into b, which must be at least Width bytes.
func (r Record) Encode(b []byte) {
	_ = b[Width-1] // bounds check hint
	b[0] = uint8(r.Status)
	b[1] = uint8(r.Flags)
	b[2] = uint8(r.Canonical)
	b[3] = 0 // reserved
	binary.LittleEndian.PutUint16(b[4:6], r.DurationM)
	binary.LittleEndian.PutUint16(b[6:8], 0) // reserved
	encodeSide(b[8:16], r.Apex)
	encodeSide(b[16:24], r.WWW)
}

// Decode reads a Record from b, which must be at least Width bytes.
func Decode(b []byte) Record {
	_ = b[Width-1]
	return Record{
		Status:    Status(b[0]),
		Flags:     Flags(b[1]),
		Canonical: Canonical(b[2]),
		DurationM: binary.LittleEndian.Uint16(b[4:6]),
		Apex:      decodeSide(b[8:16]),
		WWW:       decodeSide(b[16:24]),
	}
}

func encodeSide(b []byte, s Side) {
	b[0] = uint8(s.Resolve)
	b[1] = uint8(s.RRTypes)
	b[2] = uint8(s.TCP)
	b[3] = uint8(s.TLS)
	binary.LittleEndian.PutUint16(b[4:6], s.HTTP)
	b[6] = uint8(s.Terminal)
	b[7] = s.Hops
}

func decodeSide(b []byte) Side {
	return Side{
		Resolve:  Resolve(b[0]),
		RRTypes:  RRTypes(b[1]),
		TCP:      TCP(b[2]),
		TLS:      TLS(b[3]),
		HTTP:     binary.LittleEndian.Uint16(b[4:6]),
		Terminal: Terminal(b[6]),
		Hops:     b[7],
	}
}

// Has reports whether f contains every bit in want.
func (f Flags) Has(want Flags) bool { return f&want == want }

// Serves reports whether this name answered HTTP at all.
func (s Side) Serves() bool { return s.HTTP != 0 }

// WWWSupported is the headline classification: www resolves, terminates TLS
// under a certificate that covers it, and answers with a non-error status.
//
// A wildcard makes the resolve half meaningless on its own, which is why the
// caller passes the flag in rather than this reading only the Side.
func (r Record) WWWSupported() bool {
	if r.Status != StatusComplete {
		return false
	}
	if r.WWW.Resolve != ResolveOK {
		return false
	}
	if r.WWW.TLS != TLSOK {
		return false
	}
	return r.WWW.HTTP >= 200 && r.WWW.HTTP < 400
}

// Conclusive reports whether this record is evidence about the domain, rather
// than evidence about the scanner.
//
// Every rung of the ladder can fail two ways: the remote end is genuinely
// broken, or we overloaded ourselves and never got an answer. NXDOMAIN, a
// refused connection and a 404 are all findings. A timeout is not — it is the
// absence of one, and it is exactly what a scan running past its network's
// capacity manufactures in bulk.
//
// This is deliberately strict: a host that genuinely hangs is counted
// inconclusive too, so the rate is an upper bound on doubt rather than an
// estimate of it. That is what makes it useful across concurrency levels. The
// absolute number matters less than how it moves when workers go up, because
// the domains did not change — only the pressure did.
func (r Record) Conclusive() bool {
	if r.Status != StatusComplete {
		return false
	}
	return r.Apex.conclusive() && r.WWW.conclusive()
}

// Stall names the rung a probe died on, or "" if it produced a finding.
//
// This is the difference between "the scan is failing" and knowing why. DNS
// stalls point at resolver rate limiting; TCP stalls point at the egress path
// or a file-descriptor ceiling; TLS stalls point at CPU or the far end. They
// look identical in a throughput number and demand completely different fixes.
func (r Record) Stall() string {
	if r.Status != StatusComplete {
		return "incomplete"
	}
	for _, s := range []Side{r.Apex, r.WWW} {
		switch s.Resolve {
		case ResolveTimeout, ResolveError:
			return "dns-timeout"
		case ResolveServfail:
			return "servfail"
		case ResolveRefused:
			return "refused"
		}
	}
	// A dropped SYN and a dial error that actually returned something are
	// different diagnoses. Silent drops are what a provider's outbound rate
	// limiter produces, and lumping them together hides that.
	for _, s := range []Side{r.Apex, r.WWW} {
		if s.TCP == TCPTimeout {
			return "tcp-timeout"
		}
	}
	for _, s := range []Side{r.Apex, r.WWW} {
		if s.TCP == TCPError {
			return "tcp-error"
		}
	}
	for _, s := range []Side{r.Apex, r.WWW} {
		if s.TLS == TLSTimeout {
			return "tls-timeout"
		}
	}
	return ""
}

func (s Side) conclusive() bool {
	switch s.Resolve {
	case ResolveTimeout, ResolveError, ResolveServfail, ResolveRefused:
		// REFUSED is the resolver declining to answer us — an ACL or a
		// rate limit. Like a timeout it is a fact about the scan, not
		// about the domain, so it cannot count toward a census.
		return false
	}
	if s.TCP == TCPTimeout || s.TCP == TCPError {
		return false
	}
	return s.TLS != TLSTimeout
}

var resolveNames = [...]string{"unattempted", "ok", "nxdomain", "nodata", "timeout", "servfail", "refused", "error"}

func (r Resolve) String() string {
	if int(r) < len(resolveNames) {
		return resolveNames[r]
	}
	return "invalid"
}

var tcpNames = [...]string{"unattempted", "ok", "refused", "timeout", "unreachable", "error"}

func (t TCP) String() string {
	if int(t) < len(tcpNames) {
		return tcpNames[t]
	}
	return "invalid"
}

var tlsNames = [...]string{"unattempted", "ok", "name-mismatch", "expired", "unknown-authority", "handshake-fail", "timeout", "error"}

func (t TLS) String() string {
	if int(t) < len(tlsNames) {
		return tlsNames[t]
	}
	return "invalid"
}

var terminalNames = [...]string{"none", "self", "apex", "www", "same-site", "external"}

func (t Terminal) String() string {
	if int(t) < len(terminalNames) {
		return terminalNames[t]
	}
	return "invalid"
}

var canonicalNames = [...]string{"unknown", "both-fail", "apex-only", "www-only", "www->apex", "apex->www", "both-serve-no-canonical"}

func (c Canonical) String() string {
	if int(c) < len(canonicalNames) {
		return canonicalNames[c]
	}
	return "invalid"
}

func (r RRTypes) String() string {
	if r == 0 {
		return "-"
	}
	out := ""
	for _, p := range []struct {
		bit  RRTypes
		name string
	}{{RRA, "A"}, {RRAAAA, "AAAA"}, {RRCNAME, "CNAME"}} {
		if r&p.bit != 0 {
			if out != "" {
				out += "+"
			}
			out += p.name
		}
	}
	return out
}
