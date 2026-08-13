// Package corpus handles the input list of domains.
//
// The corpus is materialized before a scan starts, never fetched during one.
// Acquisition is bulk, sequential and bandwidth-bound; scanning is per-domain,
// latency-bound and concurrent. Fused, neither can restart without redoing the
// other, and the two bottlenecks alias in every measurement.
//
// Once written, a corpus file is immutable and versioned. Result records are
// positional — the Nth record belongs to the Nth line here — so changing a
// corpus file in place silently invalidates every result ever written against
// it. The manifest's checksum exists to make that impossible to do by accident.
package corpus

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Manifest describes a frozen corpus artifact. It sits next to the domain
// file as <path>.json and is what makes a published percentage reproducible:
// the denominator is a named, checksummed, re-downloadable thing.
type Manifest struct {
	Source      string    `json:"source"`               // "tranco", "czds", "file"
	SourceURL   string    `json:"source_url,omitempty"` // permanent, citable if the source has one
	ListID      string    `json:"list_id,omitempty"`    // Tranco's permanent list identifier
	Fetched     time.Time `json:"fetched"`
	Count       int       `json:"count"`
	SHA256      string    `json:"sha256"` // over the domain file exactly as written
	Description string    `json:"description,omitempty"`
}

// Corpus is a frozen, ordered list of domains.
type Corpus struct {
	Path     string
	Domains  []string
	Manifest Manifest
}

// Load reads a corpus file and its manifest if one is present.
//
// The whole list is held in memory, which is correct up to a few hundred
// million names and wrong at a billion. Streaming is the change that unlocks
// the internet-scale run; nothing else in the pipeline needs to move.
func Load(path string) (*Corpus, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open corpus: %w", err)
	}
	defer f.Close()

	c := &Corpus{Path: path}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		d := normalize(sc.Text())
		if d == "" {
			continue
		}
		c.Domains = append(c.Domains, d)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read corpus at line %d: %w", line, err)
	}
	if len(c.Domains) == 0 {
		return nil, fmt.Errorf("corpus %s is empty", path)
	}

	if m, err := LoadManifest(path); err == nil {
		c.Manifest = *m
		if m.Count != 0 && m.Count != len(c.Domains) {
			return nil, fmt.Errorf(
				"corpus %s has %d domains but its manifest says %d; results written against it are positional and would be misaligned",
				path, len(c.Domains), m.Count)
		}
	}
	return c, nil
}

// LoadManifest reads the sidecar manifest for a corpus file.
func LoadManifest(corpusPath string) (*Manifest, error) {
	b, err := os.ReadFile(corpusPath + ".json")
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// Write freezes domains to path and writes the sidecar manifest, returning the
// manifest as stored — with the count and checksum filled in.
func Write(path string, domains []string, m Manifest) (Manifest, error) {
	f, err := os.Create(path)
	if err != nil {
		return m, fmt.Errorf("create corpus: %w", err)
	}
	h := sha256.New()
	w := bufio.NewWriterSize(io.MultiWriter(f, h), 1<<20)
	for _, d := range domains {
		if _, err := w.WriteString(d); err != nil {
			f.Close()
			return m, fmt.Errorf("write corpus: %w", err)
		}
		if err := w.WriteByte('\n'); err != nil {
			f.Close()
			return m, fmt.Errorf("write corpus: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return m, fmt.Errorf("flush corpus: %w", err)
	}
	if err := f.Close(); err != nil {
		return m, fmt.Errorf("close corpus: %w", err)
	}

	m.Count = len(domains)
	m.SHA256 = hex.EncodeToString(h.Sum(nil))
	if m.Fetched.IsZero() {
		m.Fetched = time.Now().UTC()
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, fmt.Errorf("encode manifest: %w", err)
	}
	if err := os.WriteFile(path+".json", append(b, '\n'), 0o644); err != nil {
		return m, fmt.Errorf("write manifest: %w", err)
	}
	return m, nil
}

// Verify rechecks the corpus file against its manifest checksum. Worth running
// before a census run, because a corpus that changed under an existing result
// file misaligns every record after the edit without erroring anywhere.
func Verify(path string) error {
	m, err := LoadManifest(path)
	if err != nil {
		return fmt.Errorf("no manifest to verify against: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != m.SHA256 {
		return fmt.Errorf("corpus %s checksum %s does not match manifest %s", path, got[:12], m.SHA256[:12])
	}
	return nil
}

// normalize lowercases, strips a trailing dot, and drops comments. Anything
// that is not plausibly a hostname is dropped rather than probed, because a
// malformed entry still occupies a positional slot and would otherwise show
// up in the results as a mysterious DNS error.
func normalize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	// Tolerate "rank,domain" so a raw Tranco CSV can be fed in directly.
	if i := strings.LastIndexByte(s, ','); i >= 0 {
		s = s[i+1:]
	}
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || !strings.Contains(s, ".") || strings.ContainsAny(s, " \t/:") {
		return ""
	}
	return s
}
