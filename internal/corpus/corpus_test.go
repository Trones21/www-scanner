package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com.", "example.com"},
		// A raw Tranco CSV can be fed straight in.
		{"1,google.com", "google.com"},
		{"# a comment", ""},
		{"", ""},
		// Anything that is not plausibly a hostname is dropped rather than
		// probed, because a malformed entry still occupies a positional
		// slot and would surface later as a mysterious DNS error.
		{"localhost", ""},
		{"https://example.com/", ""},
		{"two words.com", ""},
	}
	for _, tc := range tests {
		if got := normalize(tc.in); got != tc.want {
			t.Errorf("normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWriteLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.txt")
	domains := []string{"example.com", "example.org", "example.net"}

	stored, err := Write(path, domains, Manifest{Source: "test"})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if stored.Count != 3 {
		t.Errorf("stored manifest Count = %d, want 3", stored.Count)
	}
	if stored.SHA256 == "" {
		t.Error("stored manifest has no checksum; the denominator is not reproducible")
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Domains) != 3 {
		t.Fatalf("loaded %d domains, want 3", len(c.Domains))
	}
	// Order is the positional contract. If it drifts, every result record
	// written against this corpus points at the wrong domain.
	for i, want := range domains {
		if c.Domains[i] != want {
			t.Errorf("domain %d = %q, want %q", i, c.Domains[i], want)
		}
	}
	if c.Manifest.SHA256 != stored.SHA256 {
		t.Error("loaded manifest checksum does not match what was written")
	}

	if err := Verify(path); err != nil {
		t.Errorf("Verify on an untouched corpus: %v", err)
	}
}

// A corpus edited after results were written silently misaligns every record
// after the edit. The checksum is the only thing standing between that and a
// wrong published number.
func TestVerifyDetectsMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.txt")
	if _, err := Write(path, []string{"example.com", "example.org"}, Manifest{Source: "test"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := os.WriteFile(path, []byte("example.com\nexample.net\n"), 0o644); err != nil {
		t.Fatalf("mutate corpus: %v", err)
	}
	if err := Verify(path); err == nil {
		t.Fatal("Verify accepted a corpus that changed under its manifest")
	}
}

func TestLoadRejectsManifestCountMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corpus.txt")
	if err := os.WriteFile(path, []byte("example.com\nexample.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".json", []byte(`{"source":"test","count":99}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a corpus whose length contradicts its manifest")
	}
}

func TestParseRankedDedupesAndLimits(t *testing.T) {
	const csv = "1,a.com\n2,b.com\n3,a.com\n4,c.com\n5,d.com\n"
	got, err := parseRanked(strings.NewReader(csv), 3)
	if err != nil {
		t.Fatalf("parseRanked: %v", err)
	}
	want := []string{"a.com", "b.com", "c.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNaiveTimeParsesTrancoTimestamp(t *testing.T) {
	// Tranco emits ISO 8601 with no zone designator, which time.Time's
	// own unmarshaller rejects.
	var nt naiveTime
	if err := nt.UnmarshalJSON([]byte(`"2026-08-08T22:00:02.219439"`)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if got := nt.Format("2006-01-02"); got != "2026-08-08" {
		t.Errorf("parsed date = %q, want 2026-08-08", got)
	}
}
