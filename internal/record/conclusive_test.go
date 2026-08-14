package record

import "testing"

// complete builds a record where both sides reached a finding, so each test
// can spoil exactly one thing.
func complete(mut func(*Record)) Record {
	r := Record{
		Status: StatusComplete,
		Apex:   Side{Resolve: ResolveOK, TCP: TCPOK, TLS: TLSOK, HTTP: 200},
		WWW:    Side{Resolve: ResolveOK, TCP: TCPOK, TLS: TLSOK, HTTP: 200},
	}
	mut(&r)
	return r
}

func TestConclusive(t *testing.T) {
	tests := []struct {
		name string
		rec  Record
		want bool
		why  string
	}{
		{"both sides served", complete(func(*Record) {}), true, ""},

		// Definite answers are findings, however negative. These are the
		// whole point of the scan and must never be counted as doubt.
		{"www does not exist", complete(func(r *Record) {
			r.WWW = Side{Resolve: ResolveNXDOMAIN}
		}), true, "NXDOMAIN is a finding"},
		{"www has no address record", complete(func(r *Record) {
			r.WWW = Side{Resolve: ResolveNoData}
		}), true, "NODATA is a finding"},
		{"nothing listening on www", complete(func(r *Record) {
			r.WWW = Side{Resolve: ResolveOK, TCP: TCPRefused}
		}), true, "a RST is an answer"},
		{"host unreachable", complete(func(r *Record) {
			r.WWW = Side{Resolve: ResolveOK, TCP: TCPUnreachable}
		}), true, "ICMP is an answer"},
		{"cert does not cover www", complete(func(r *Record) {
			r.WWW.TLS = TLSNameMismatch
		}), true, "a verification result is a finding"},
		{"vhost only knows the apex", complete(func(r *Record) {
			r.WWW.HTTP = 404
		}), true, "any status is a finding"},

		// Non-answers are about the scanner, not the domain.
		{"dns timed out", complete(func(r *Record) {
			r.WWW = Side{Resolve: ResolveTimeout}
		}), false, ""},
		{"resolver broke", complete(func(r *Record) {
			r.WWW = Side{Resolve: ResolveServfail}
		}), false, ""},
		{"resolver refused us", complete(func(r *Record) {
			r.WWW = Side{Resolve: ResolveRefused}
		}), false, "REFUSED is an ACL or rate limit, i.e. about us"},
		{"syn dropped", complete(func(r *Record) {
			r.WWW = Side{Resolve: ResolveOK, TCP: TCPTimeout}
		}), false, ""},
		{"handshake never finished", complete(func(r *Record) {
			r.WWW.TLS = TLSTimeout
		}), false, ""},

		// The apex half counts equally: the canonical-direction question
		// compares the two names, and a comparison against a blank is
		// meaningless.
		{"apex stalled, www fine", complete(func(r *Record) {
			r.Apex = Side{Resolve: ResolveTimeout}
		}), false, "either side stalling invalidates the record"},

		{"never probed", complete(func(r *Record) {
			r.Status = StatusUnattempted
		}), false, ""},
		{"cancelled mid-probe", complete(func(r *Record) {
			r.Status = StatusAborted
		}), false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rec.Conclusive(); got != tc.want {
				msg := tc.why
				if msg == "" {
					msg = "see Conclusive()"
				}
				t.Errorf("Conclusive() = %v, want %v (%s)", got, tc.want, msg)
			}
		})
	}
}

func TestStallNamesTheRung(t *testing.T) {
	tests := []struct {
		name string
		rec  Record
		want string
	}{
		{"conclusive records do not stall", complete(func(*Record) {}), ""},
		{"dns timeout", complete(func(r *Record) { r.WWW = Side{Resolve: ResolveTimeout} }), "dns-timeout"},
		{"servfail", complete(func(r *Record) { r.WWW = Side{Resolve: ResolveServfail} }), "servfail"},
		{"refused", complete(func(r *Record) { r.WWW = Side{Resolve: ResolveRefused} }), "refused"},
		{"tcp timeout", complete(func(r *Record) { r.WWW = Side{Resolve: ResolveOK, TCP: TCPTimeout} }), "tcp-timeout"},
		{"tcp error", complete(func(r *Record) { r.WWW = Side{Resolve: ResolveOK, TCP: TCPError} }), "tcp-error"},
		{"tls timeout", complete(func(r *Record) { r.WWW.TLS = TLSTimeout }), "tls-timeout"},
		{"aborted", complete(func(r *Record) { r.Status = StatusAborted }), "incomplete"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rec.Stall(); got != tc.want {
				t.Errorf("Stall() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A dropped SYN and a dial error that came back are opposite diagnoses — one is
// a rate limiter, the other is not — so they must not collapse into one label.
func TestStallSeparatesTCPTimeoutFromTCPError(t *testing.T) {
	timeout := complete(func(r *Record) { r.WWW = Side{Resolve: ResolveOK, TCP: TCPTimeout} }).Stall()
	dialErr := complete(func(r *Record) { r.WWW = Side{Resolve: ResolveOK, TCP: TCPError} }).Stall()
	if timeout == dialErr {
		t.Fatalf("both TCP failures report %q; the distinction is what identifies an egress limiter", timeout)
	}
}

// Stall reports the FIRST rung to fail in ladder order, so a domain is
// attributed to the earliest thing that went wrong rather than the last.
func TestStallReportsEarliestRung(t *testing.T) {
	r := complete(func(r *Record) {
		r.Apex = Side{Resolve: ResolveTimeout}
		r.WWW = Side{Resolve: ResolveOK, TCP: TCPTimeout}
	})
	if got := r.Stall(); got != "dns-timeout" {
		t.Errorf("Stall() = %q, want dns-timeout — DNS precedes TCP on the ladder", got)
	}
}

// Conclusive and Stall are two views of one decision and must never disagree.
func TestStallAgreesWithConclusive(t *testing.T) {
	sides := []Side{
		{Resolve: ResolveOK, TCP: TCPOK, TLS: TLSOK, HTTP: 200},
		{Resolve: ResolveNXDOMAIN},
		{Resolve: ResolveNoData},
		{Resolve: ResolveTimeout},
		{Resolve: ResolveServfail},
		{Resolve: ResolveRefused},
		{Resolve: ResolveError},
		{Resolve: ResolveOK, TCP: TCPRefused},
		{Resolve: ResolveOK, TCP: TCPTimeout},
		{Resolve: ResolveOK, TCP: TCPError},
		{Resolve: ResolveOK, TCP: TCPUnreachable},
		{Resolve: ResolveOK, TCP: TCPOK, TLS: TLSNameMismatch},
		{Resolve: ResolveOK, TCP: TCPOK, TLS: TLSTimeout},
		{Resolve: ResolveOK, TCP: TCPOK, TLS: TLSExpired, HTTP: 200},
	}
	for _, apex := range sides {
		for _, www := range sides {
			r := Record{Status: StatusComplete, Apex: apex, WWW: www}
			stalled := r.Stall() != ""
			if stalled == r.Conclusive() {
				t.Fatalf("Conclusive()=%v but Stall()=%q for apex=%+v www=%+v",
					r.Conclusive(), r.Stall(), apex, www)
			}
		}
	}
}
