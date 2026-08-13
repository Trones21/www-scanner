// Package runmeta persists everything needed to interpret a result file.
//
// A positional result file is 24 bytes per domain and nothing else — no
// header, no column names, no record of what produced it. That is deliberate,
// but it means a bare .bin cannot answer the questions you actually ask when
// you come back to it a week later: was this the whole corpus or a sample?
// which sample? how many probes were real findings rather than timeouts? was
// the concurrency high enough to have poisoned it?
//
// Those questions were previously answerable only by remembering the command
// line, which is not a durable medium. This writes them down.
package runmeta

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Path returns the metadata path for a result file.
func Path(resultsPath string) string { return resultsPath + ".meta.json" }

// Meta describes one scan run.
type Meta struct {
	Tool    string    `json:"tool"`
	Mode    string    `json:"mode"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended,omitempty"`
	Elapsed string    `json:"elapsed,omitempty"`

	Corpus Corpus `json:"corpus"`
	Sample Sample `json:"sample"`
	Config Config `json:"config"`
	Result Result `json:"result"`
}

// Corpus identifies the denominator, so a published percentage can be checked.
type Corpus struct {
	Path        string `json:"path"`
	Count       int    `json:"count"`
	SHA256      string `json:"sha256,omitempty"`
	Source      string `json:"source,omitempty"`
	ListID      string `json:"list_id,omitempty"`
	SourceURL   string `json:"source_url,omitempty"`
	Description string `json:"description,omitempty"`
}

// Sample records how the probed subset was chosen. The distinction between a
// random sample and the head of a ranked list is the difference between an
// estimate and a ceiling.
type Sample struct {
	Method   string `json:"method"` // "full", "random", "head"
	Size     int    `json:"size"`
	Seed     uint64 `json:"seed,omitempty"`
	Fraction string `json:"fraction"`
	Note     string `json:"note"`
}

// Config records the knobs that can change the answer.
type Config struct {
	Workers        int      `json:"workers"`
	Resolvers      []string `json:"resolvers"`
	DNSSockets     int      `json:"dns_sockets_per_server"`
	DNSTimeout     string   `json:"dns_timeout"`
	DNSAttempts    int      `json:"dns_attempts"`
	HTTPTimeout    string   `json:"http_timeout"`
	ConnectTimeout string   `json:"connect_timeout"`
	WildcardCheck  bool     `json:"wildcard_check"`
	HTTPFallback   bool     `json:"http_fallback"`
}

// Result records how the run went, including whether to trust it.
type Result struct {
	Probed        int64            `json:"probed"`
	Skipped       int64            `json:"skipped"`
	Conclusive    int64            `json:"conclusive"`
	Validity      float64          `json:"validity"`
	ValidCensus   bool             `json:"valid_census"`
	RawPerSec     float64          `json:"raw_per_sec"`
	EffPerSec     float64          `json:"effective_per_sec"`
	MeanLatencyMS int64            `json:"mean_latency_ms"`
	Stalls        map[string]int64 `json:"stalls,omitempty"`
}

// Write saves the metadata beside the result file.
func Write(resultsPath string, m Meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode run metadata: %w", err)
	}
	if err := os.WriteFile(Path(resultsPath), append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("write run metadata: %w", err)
	}
	return nil
}

// Load reads metadata for a result file. A missing file is not an error —
// results written before this existed are still readable, just less legible.
func Load(resultsPath string) (*Meta, bool) {
	b, err := os.ReadFile(Path(resultsPath))
	if err != nil {
		return nil, false
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false
	}
	return &m, true
}

// Describe renders the provenance block that heads every report, so a number
// is never shown without the context needed to read it.
func (m Meta) Describe() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "RUN\n")
	fmt.Fprintf(&sb, "  when        %s", m.Started.Format("2006-01-02 15:04 MST"))
	if m.Elapsed != "" {
		fmt.Fprintf(&sb, "  (took %s)", m.Elapsed)
	}
	fmt.Fprintln(&sb)
	fmt.Fprintf(&sb, "  corpus      %s — %d domains\n", m.Corpus.Path, m.Corpus.Count)
	if m.Corpus.ListID != "" {
		fmt.Fprintf(&sb, "              %s list %s, sha256 %s\n",
			m.Corpus.Source, m.Corpus.ListID, short(m.Corpus.SHA256))
	}
	fmt.Fprintf(&sb, "  probed      %d domains — %s\n", m.Sample.Size, m.Sample.Note)
	if m.Sample.Method == "random" {
		fmt.Fprintf(&sb, "              random sample, %s of the corpus, seed %d (rerun to reproduce)\n",
			m.Sample.Fraction, m.Sample.Seed)
	}
	fmt.Fprintf(&sb, "  validity    %.1f%% of probes were findings", m.Result.Validity*100)
	if m.Result.ValidCensus {
		fmt.Fprintf(&sb, "  — above the 95%% census floor\n")
	} else {
		fmt.Fprintf(&sb, "  — BELOW the 95%% census floor, treat with suspicion\n")
	}
	fmt.Fprintf(&sb, "  throughput  %.1f effective domains/sec (%.1f raw)\n",
		m.Result.EffPerSec, m.Result.RawPerSec)
	if len(m.Result.Stalls) > 0 {
		fmt.Fprintf(&sb, "  stalled on  %s\n", formatStalls(m.Result.Stalls))
	}
	fmt.Fprintf(&sb, "  settings    %d workers, %d dns sockets/server, %s http timeout\n",
		m.Config.Workers, m.Config.DNSSockets, m.Config.HTTPTimeout)
	return sb.String()
}

func formatStalls(m map[string]int64) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	return strings.Join(parts, " ")
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
