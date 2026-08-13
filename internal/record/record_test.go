package record

import "testing"

func TestEncodeDecodeRoundTrip(t *testing.T) {
	want := Record{
		Status:    StatusComplete,
		Flags:     FlagWildcardChecked | FlagWildcard,
		Canonical: CanonicalWWWToApex,
		DurationM: 1234,
		Apex: Side{
			Resolve: ResolveOK, RRTypes: RRA | RRAAAA, TCP: TCPOK,
			TLS: TLSOK, HTTP: 200, Terminal: TerminalSelf, Hops: 0,
		},
		WWW: Side{
			Resolve: ResolveOK, RRTypes: RRA | RRCNAME, TCP: TCPOK,
			TLS: TLSNameMismatch, HTTP: 301, Terminal: TerminalApex, Hops: 2,
		},
	}

	buf := make([]byte, Width)
	want.Encode(buf)
	got := Decode(buf)

	if got != want {
		t.Errorf("round trip changed the record:\n got %+v\nwant %+v", got, want)
	}
}

// The zero value is load-bearing: it is what makes a freshly allocated result
// file its own resume checkpoint. If StatusUnattempted ever stops being 0, a
// resumed run silently skips every domain.
func TestZeroValueIsUnattempted(t *testing.T) {
	got := Decode(make([]byte, Width))
	if got.Status != StatusUnattempted {
		t.Errorf("zero bytes decoded to status %d, want StatusUnattempted (0)", got.Status)
	}
	if got != (Record{}) {
		t.Errorf("zero bytes decoded to %+v, want the zero Record", got)
	}
}

func TestEncodeFillsExactlyWidth(t *testing.T) {
	// A record must never write outside its own slot, or workers writing
	// at disjoint offsets would corrupt each other.
	buf := make([]byte, Width*3)
	full := Record{
		Status: 255, Flags: 255, Canonical: 255, DurationM: 65535,
		Apex: Side{255, 255, 255, 255, 65535, 255, 255},
		WWW:  Side{255, 255, 255, 255, 65535, 255, 255},
	}
	full.Encode(buf[Width : Width*2])

	for i, b := range buf[:Width] {
		if b != 0 {
			t.Fatalf("encode wrote %#x at byte %d, before its slot", b, i)
		}
	}
	for i, b := range buf[Width*2:] {
		if b != 0 {
			t.Fatalf("encode wrote %#x at byte %d, past its slot", b, Width*2+i)
		}
	}
}

func TestWWWSupported(t *testing.T) {
	base := func(mut func(*Record)) Record {
		r := Record{
			Status: StatusComplete,
			WWW:    Side{Resolve: ResolveOK, TCP: TCPOK, TLS: TLSOK, HTTP: 200},
		}
		mut(&r)
		return r
	}

	tests := []struct {
		name string
		rec  Record
		want bool
	}{
		{"serving www", base(func(*Record) {}), true},
		{"redirect counts as working", base(func(r *Record) { r.WWW.HTTP = 301 }), true},
		{"nxdomain", base(func(r *Record) { r.WWW.Resolve = ResolveNXDOMAIN }), false},
		{"resolves but no data", base(func(r *Record) { r.WWW.Resolve = ResolveNoData }), false},
		// The specific failure of adding a www record without reissuing
		// the certificate. It must not count as support.
		{"cert has no SAN for www", base(func(r *Record) { r.WWW.TLS = TLSNameMismatch }), false},
		{"expired cert", base(func(r *Record) { r.WWW.TLS = TLSExpired }), false},
		{"vhost only knows the apex", base(func(r *Record) { r.WWW.HTTP = 404 }), false},
		{"server error", base(func(r *Record) { r.WWW.HTTP = 500 }), false},
		{"never probed", base(func(r *Record) { r.Status = StatusUnattempted }), false},
		{"aborted mid-probe", base(func(r *Record) { r.Status = StatusAborted }), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rec.WWWSupported(); got != tc.want {
				t.Errorf("WWWSupported() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFlagsHas(t *testing.T) {
	f := FlagWildcardChecked | FlagWildcard
	if !f.Has(FlagWildcard) {
		t.Error("Has(FlagWildcard) = false on a flag set containing it")
	}
	if f.Has(FlagHTTPFallback) {
		t.Error("Has(FlagHTTPFallback) = true on a flag set without it")
	}
	// A clear FlagWildcard on its own is ambiguous, which is why the
	// checked bit exists.
	var never Flags
	if never.Has(FlagWildcardChecked) {
		t.Error("an unprobed record reports the wildcard check as having run")
	}
}

func TestRRTypesString(t *testing.T) {
	tests := []struct {
		in   RRTypes
		want string
	}{
		{0, "-"},
		{RRA, "A"},
		{RRA | RRAAAA, "A+AAAA"},
		{RRA | RRCNAME, "A+CNAME"},
		{RRA | RRAAAA | RRCNAME, "A+AAAA+CNAME"},
	}
	for _, tc := range tests {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("RRTypes(%d).String() = %q, want %q", tc.in, got, tc.want)
		}
	}
}
