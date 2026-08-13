package probe

import (
	"crypto/x509"
	"syscall"
	"testing"

	"github.com/trones/www-scanner/internal/record"
)

func serving(code uint16, hops uint8) record.Side {
	return record.Side{Resolve: record.ResolveOK, TCP: record.TCPOK, TLS: record.TLSOK, HTTP: code, Hops: hops}
}

func TestClassifyCanonical(t *testing.T) {
	const d = "example.com"
	dead := record.Side{Resolve: record.ResolveNXDOMAIN}

	tests := []struct {
		name              string
		apex, www         record.Side
		apexTerm, wwwTerm string
		want              record.Canonical
	}{
		{
			name: "www 301s to the apex",
			apex: serving(200, 0), www: serving(200, 1),
			apexTerm: d, wwwTerm: d,
			want: record.CanonicalWWWToApex,
		},
		{
			name: "apex 301s to www",
			apex: serving(200, 1), www: serving(200, 0),
			apexTerm: "www." + d, wwwTerm: "www." + d,
			want: record.CanonicalApexToWWW,
		},
		{
			// The least obvious branch, because nothing is failing.
			// csv-helper.com is parked here on purpose.
			name: "both serve 200 with no canonical form",
			apex: serving(200, 0), www: serving(200, 0),
			apexTerm: d, wwwTerm: "www." + d,
			want: record.CanonicalBothServe,
		},
		{
			name: "www missing entirely",
			apex: serving(200, 0), www: dead,
			apexTerm: d, wwwTerm: "",
			want: record.CanonicalApexOnly,
		},
		{
			name: "apex missing, www serves",
			apex: dead, www: serving(200, 0),
			apexTerm: "", wwwTerm: "www." + d,
			want: record.CanonicalWWWOnly,
		},
		{
			name: "neither answers",
			apex: dead, www: dead,
			want: record.CanonicalBothFail,
		},
		{
			name: "both funnel to a third host",
			apex: serving(200, 1), www: serving(200, 1),
			apexTerm: "shop.example.net", wwwTerm: "shop.example.net",
			want: record.CanonicalWWWToApex,
		},
		{
			// A 404 is not serving, so this is apex-only however
			// cleanly the www side completed its handshake.
			name: "www resolves and handshakes but 404s",
			apex: serving(200, 0), www: serving(404, 0),
			apexTerm: d, wwwTerm: "www." + d,
			want: record.CanonicalApexOnly,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyCanonical(tc.apex, tc.www, tc.apexTerm, tc.wwwTerm, d)
			if got != tc.want {
				t.Errorf("classifyCanonical() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClassifyTerminal(t *testing.T) {
	const apex = "example.com"
	tests := []struct {
		terminal, origin string
		want             record.Terminal
	}{
		{"", "www.example.com", record.TerminalNone},
		{"www.example.com", "www.example.com", record.TerminalSelf},
		{"example.com", "www.example.com", record.TerminalApex},
		{"www.example.com", "example.com", record.TerminalWWW},
		{"shop.example.com", "example.com", record.TerminalSameSite},
		{"example.org", "example.com", record.TerminalExternal},
		// Suffix matching must not be fooled by a domain that merely ends
		// in the same string.
		{"notexample.com", "example.com", record.TerminalExternal},
	}
	for _, tc := range tests {
		if got := classifyTerminal(tc.terminal, tc.origin, apex); got != tc.want {
			t.Errorf("classifyTerminal(%q, %q, %q) = %v, want %v",
				tc.terminal, tc.origin, apex, got, tc.want)
		}
	}
}

func TestClassifyTransportErr(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wasTLS  bool
		wantTCP record.TCP
		wantTLS record.TLS
	}{
		{
			// The headline TLS failure: someone added a www record and
			// never reissued the certificate.
			name: "certificate has no SAN for the name",
			err:  x509.HostnameError{Host: "www.example.com"}, wasTLS: true,
			wantTCP: record.TCPOK, wantTLS: record.TLSNameMismatch,
		},
		{
			name: "expired certificate",
			err:  x509.CertificateInvalidError{Reason: x509.Expired}, wasTLS: true,
			wantTCP: record.TCPOK, wantTLS: record.TLSExpired,
		},
		{
			name: "self-signed or unknown CA",
			err:  x509.UnknownAuthorityError{}, wasTLS: true,
			wantTCP: record.TCPOK, wantTLS: record.TLSUnknownAuthority,
		},
		{
			name: "connection refused",
			err:  syscall.ECONNREFUSED, wasTLS: true,
			wantTCP: record.TCPRefused, wantTLS: record.TLSUnattempted,
		},
		{
			name: "host unreachable",
			err:  syscall.EHOSTUNREACH, wasTLS: true,
			wantTCP: record.TCPUnreachable, wantTLS: record.TLSUnattempted,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var side record.Side
			classifyTransportErr(&side, tc.err, tc.wasTLS)
			if side.TCP != tc.wantTCP {
				t.Errorf("TCP = %v, want %v", side.TCP, tc.wantTCP)
			}
			if side.TLS != tc.wantTLS {
				t.Errorf("TLS = %v, want %v", side.TLS, tc.wantTLS)
			}
		})
	}
}

func TestResolveRef(t *testing.T) {
	tests := []struct {
		base, ref string
		want      string
		wantErr   bool
	}{
		{"https://www.example.com/", "https://example.com/", "https://example.com/", false},
		{"https://www.example.com/", "/landing", "https://www.example.com/landing", false},
		{"http://example.com/", "//cdn.example.com/x", "http://cdn.example.com/x", false},
		{"https://example.com/", "  https://example.com/spaced  ", "https://example.com/spaced", false},
		// A Location pointing at a non-HTTP scheme ends the chain rather
		// than being followed.
		{"https://example.com/", "mailto:hi@example.com", "", true},
		{"https://example.com/", "app://open", "", true},
	}
	for _, tc := range tests {
		got, err := resolveRef(tc.base, tc.ref)
		if tc.wantErr {
			if err == nil {
				t.Errorf("resolveRef(%q, %q) = %q, want an error", tc.base, tc.ref, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveRef(%q, %q) errored: %v", tc.base, tc.ref, err)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveRef(%q, %q) = %q, want %q", tc.base, tc.ref, got, tc.want)
		}
	}
}

func TestHostOf(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://www.example.com/path", "www.example.com"},
		{"https://EXAMPLE.com/", "example.com"},
		{"https://example.com:8443/", "example.com"},
	}
	for _, tc := range tests {
		if got := hostOf(tc.in); got != tc.want {
			t.Errorf("hostOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
