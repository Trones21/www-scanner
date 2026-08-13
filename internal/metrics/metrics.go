// Package metrics is the instrumentation the scan needs from the first run,
// not the one added after it gets stuck.
//
// Logging only domains/sec makes every failure mode look identical. Little's
// Law says throughput = in-flight concurrency / mean completion time, so when
// throughput plateaus and the machine looks bored, one of those two terms is
// not what you think it is. Emitting both turns the search into a measurement:
// real in-flight far below the worker count means something is serializing,
// and a completion-time distribution far worse than the happy path means the
// tail is eating the run.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trones/www-scanner/internal/record"
)

// CensusValidityFloor is the conclusive fraction below which a run is not a
// census, whatever its raw throughput says.
//
// It is a judgement call, not a derived constant. A 200-worker reference run
// measured 99%+ against this corpus, and 10,000 workers measured 22%, so
// anything under 95% means the scanner is a material part of what it is
// reporting.
const CensusValidityFloor = 0.95

// Collector accumulates counters, an in-flight gauge and a latency histogram.
// Every method is safe for concurrent use.
type Collector struct {
	start time.Time

	inFlight   atomic.Int64
	completed  atomic.Int64
	skipped    atomic.Int64
	aborted    atomic.Int64
	conclusive atomic.Int64

	hist Histogram

	mu       sync.Mutex
	marked   *Snapshot
	stalls   map[string]int64
	resolves map[record.Resolve]int64
	tlsOut   map[record.TLS]int64
	canon    map[record.Canonical]int64
	wildcard int64
}

// NewCollector starts a collector with the clock running.
func NewCollector() *Collector {
	return &Collector{
		start:    time.Now(),
		stalls:   make(map[string]int64),
		resolves: make(map[record.Resolve]int64),
		tlsOut:   make(map[record.TLS]int64),
		canon:    make(map[record.Canonical]int64),
	}
}

// Begin marks a probe as in flight and returns the function to call when it
// finishes. The gauge it maintains is the numerator in Little's Law.
func (c *Collector) Begin() func() {
	c.inFlight.Add(1)
	return func() { c.inFlight.Add(-1) }
}

// Observe records one finished probe.
func (c *Collector) Observe(r record.Record, d time.Duration) {
	c.completed.Add(1)
	if r.Status == record.StatusAborted {
		c.aborted.Add(1)
	}
	if r.Conclusive() {
		c.conclusive.Add(1)
	}
	c.hist.Observe(d)

	c.mu.Lock()
	if why := r.Stall(); why != "" {
		c.stalls[why]++
	}
	c.resolves[r.WWW.Resolve]++
	c.tlsOut[r.WWW.TLS]++
	c.canon[r.Canonical]++
	if r.Flags.Has(record.FlagWildcard) {
		c.wildcard++
	}
	c.mu.Unlock()
}

// Skip counts a corpus entry that already had a result.
func (c *Collector) Skip() { c.skipped.Add(1) }

// Mark freezes a snapshot of the steady state.
//
// A time-boxed run stops dispatching and then drains, and during the drain
// completions trail off while the clock keeps running — so a snapshot taken at
// the end understates the rate by however long the slowest probe took. The
// benchmark wants the steady state, which is the moment feeding stopped.
func (c *Collector) Mark() {
	s := c.Snapshot()
	c.mu.Lock()
	c.marked = &s
	c.mu.Unlock()
}

// Steady returns the marked snapshot, or the current one if none was marked.
func (c *Collector) Steady() Snapshot {
	c.mu.Lock()
	m := c.marked
	c.mu.Unlock()
	if m != nil {
		return *m
	}
	return c.Snapshot()
}

// Histogram renders the completion-time distribution. A bimodal shape here —
// a cluster of fast successes plus a wall parked on the timeout value — means
// the lever is the timeout, not the worker count.
func (c *Collector) Histogram() string { return c.hist.Distribution() }

// Snapshot is a point-in-time view for the progress line.
type Snapshot struct {
	Elapsed   time.Duration
	Completed int64
	Skipped   int64
	Aborted   int64
	InFlight  int64
	Rate      float64
	P50       time.Duration
	P90       time.Duration
	P99       time.Duration
	Mean      time.Duration
	// LittleN is mean completion time times throughput: the concurrency
	// the system is actually sustaining. Compare it to the worker count.
	// A large gap is the whole diagnosis.
	LittleN float64

	// Conclusive counts probes that are evidence about a domain rather than
	// about the scanner.
	Conclusive int64
	// EffectiveRate is conclusive probes per second, and it is the only
	// throughput number worth optimizing.
	//
	// Raw domains/sec rewards breaking the scan: a timed-out probe is
	// cheaper than a completed one, so pushing concurrency past what the
	// network sustains makes the headline number go up while the data
	// evaporates. Measured here, 10,000 workers beat 1,000 on raw rate
	// nearly four to one and lost on this one.
	EffectiveRate float64
	// Validity is the conclusive fraction. Below ~0.95 a run is not a
	// census, whatever its raw rate says.
	Validity float64
	// Stalls counts inconclusive probes by the rung they died on, which is
	// what turns "it is slow" into a specific thing to fix.
	Stalls map[string]int64
}

// StallSummary renders the stall breakdown most-common first.
func (s Snapshot) StallSummary() string {
	if len(s.Stalls) == 0 {
		return "none"
	}
	type kv struct {
		k string
		v int64
	}
	pairs := make([]kv, 0, len(s.Stalls))
	for k, v := range s.Stalls {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
	var sb strings.Builder
	for i, p := range pairs {
		if i > 0 {
			sb.WriteString(" ")
		}
		fmt.Fprintf(&sb, "%s=%d", p.k, p.v)
	}
	return sb.String()
}

// Snapshot reads the current state.
func (c *Collector) Snapshot() Snapshot {
	elapsed := time.Since(c.start)
	done := c.completed.Load()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(done) / elapsed.Seconds()
	}
	mean := c.hist.Mean()
	conclusive := c.conclusive.Load()
	effective, validity := 0.0, 0.0
	if elapsed > 0 {
		effective = float64(conclusive) / elapsed.Seconds()
	}
	if done > 0 {
		validity = float64(conclusive) / float64(done)
	}
	c.mu.Lock()
	stalls := make(map[string]int64, len(c.stalls))
	for k, v := range c.stalls {
		stalls[k] = v
	}
	c.mu.Unlock()

	s := Snapshot{
		Stalls:     stalls,
		Elapsed:    elapsed,
		Completed:  done,
		Skipped:    c.skipped.Load(),
		Aborted:    c.aborted.Load(),
		InFlight:   c.inFlight.Load(),
		Rate:       rate,
		Conclusive: conclusive,

		EffectiveRate: effective,
		Validity:      validity,
		P50:           c.hist.Quantile(0.50),
		P90:           c.hist.Quantile(0.90),
		P99:           c.hist.Quantile(0.99),
		Mean:          mean,
		LittleN:       rate * mean.Seconds(),
	}
	return s
}

// ProgressLine formats a snapshot for a terminal.
func (s Snapshot) ProgressLine(total int, workers int) string {
	pct := 0.0
	if total > 0 {
		pct = float64(s.Completed+s.Skipped) / float64(total) * 100
	}
	eta := "?"
	if s.Rate > 0 {
		remaining := float64(total) - float64(s.Completed+s.Skipped)
		if remaining > 0 {
			eta = time.Duration(remaining / s.Rate * float64(time.Second)).Round(time.Second).String()
		} else {
			eta = "0s"
		}
	}
	return fmt.Sprintf(
		"%6.2f%% %d/%d  %.0f/s (%.0f eff, %.0f%% valid)  inflight %d/%d (N %.0f)  p50 %s p99 %s  eta %s",
		pct, s.Completed+s.Skipped, total, s.Rate, s.EffectiveRate, s.Validity*100,
		s.InFlight, workers, s.LittleN,
		round(s.P50), round(s.P99), eta,
	)
}

func round(d time.Duration) time.Duration { return d.Round(time.Millisecond) }

// WriteSummary prints the end-of-run breakdown.
func (c *Collector) WriteSummary(w io.Writer, workers int) {
	s := c.Snapshot()
	fmt.Fprintf(w, "\nscan complete in %s\n", s.Elapsed.Round(time.Millisecond))
	fmt.Fprintf(w, "  probed        %d  (%d skipped, %d aborted)\n", s.Completed, s.Skipped, s.Aborted)
	fmt.Fprintf(w, "  throughput    %.1f domains/sec raw\n", s.Rate)
	fmt.Fprintf(w, "  effective     %.1f domains/sec conclusively classified  <- the number that means anything\n", s.EffectiveRate)
	fmt.Fprintf(w, "  validity      %.1f%%  (%d of %d probes are evidence about a domain, not about the scanner)\n",
		s.Validity*100, s.Conclusive, s.Completed)
	fmt.Fprintf(w, "  latency       mean %s  p50 %s  p90 %s  p99 %s\n",
		round(s.Mean), round(s.P50), round(s.P90), round(s.P99))
	fmt.Fprintf(w, "  little's N    %.0f sustained against %d workers", s.LittleN, workers)
	if s.LittleN < float64(workers)*0.7 {
		fmt.Fprintf(w, "  <- workers are idle; something is serializing")
	}
	fmt.Fprintln(w)

	if s.Validity < CensusValidityFloor {
		fmt.Fprintf(w, "\n  !! VALIDITY %.1f%% — NOT A CENSUS.\n", s.Validity*100)
		fmt.Fprintf(w, "     %d probes timed out somewhere on the ladder. A timeout is not a finding,\n", s.Completed-s.Conclusive)
		fmt.Fprintf(w, "     it is the absence of one, and at this concurrency most of them are ours\n")
		fmt.Fprintf(w, "     rather than the remote end's. Lower -workers and rerun before believing\n")
		fmt.Fprintf(w, "     any percentage derived from this.\n")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(w, "\n  www dns:  %s\n", formatCounts(c.resolves, func(k record.Resolve) string { return k.String() }))
	fmt.Fprintf(w, "  www tls:  %s\n", formatCounts(c.tlsOut, func(k record.TLS) string { return k.String() }))
	fmt.Fprintf(w, "  canonical: %s\n", formatCounts(c.canon, func(k record.Canonical) string { return k.String() }))
	if c.wildcard > 0 {
		fmt.Fprintf(w, "  wildcard zones: %d (their www resolving is not evidence of support)\n", c.wildcard)
	}
}

func formatCounts[K comparable](m map[K]int64, name func(K) string) string {
	type kv struct {
		k K
		v int64
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
	var sb strings.Builder
	for i, p := range pairs {
		if i > 0 {
			sb.WriteString("  ")
		}
		fmt.Fprintf(&sb, "%s=%d", name(p.k), p.v)
	}
	return sb.String()
}

// Histogram is a fixed-bucket log-scale latency histogram.
//
// Bucketed rather than reservoir-sampled: the tail is the interesting part of
// this distribution and sampling is exactly what loses it. Buckets are
// atomics, so recording costs one add and no lock.
type Histogram struct {
	buckets [nBuckets]atomic.Int64
	sum     atomic.Int64 // total microseconds
	count   atomic.Int64
}

// Buckets double from 1ms, so bucket i covers [2^i ms, 2^(i+1) ms). 24 of them
// reaches ~4.7 hours, which is well past any timeout worth setting.
const nBuckets = 24

// Observe records one duration.
func (h *Histogram) Observe(d time.Duration) {
	us := d.Microseconds()
	if us < 0 {
		us = 0
	}
	h.sum.Add(us)
	h.count.Add(1)
	h.buckets[bucketOf(d)].Add(1)
}

func bucketOf(d time.Duration) int {
	ms := d.Milliseconds()
	if ms < 1 {
		return 0
	}
	b := int(math.Floor(math.Log2(float64(ms))))
	if b < 0 {
		return 0
	}
	if b >= nBuckets {
		return nBuckets - 1
	}
	return b
}

// Mean returns the arithmetic mean completion time — the denominator in
// Little's Law, and the number the tail quietly ruins.
func (h *Histogram) Mean() time.Duration {
	n := h.count.Load()
	if n == 0 {
		return 0
	}
	return time.Duration(h.sum.Load()/n) * time.Microsecond
}

// Quantile returns an approximate quantile, resolved to the bucket's upper
// bound. Precision is one octave, which is plenty for telling a 300ms happy
// path apart from a 10s timeout.
func (h *Histogram) Quantile(q float64) time.Duration {
	total := h.count.Load()
	if total == 0 {
		return 0
	}
	target := int64(math.Ceil(q * float64(total)))
	var cum int64
	for i := range nBuckets {
		cum += h.buckets[i].Load()
		if cum >= target {
			return time.Duration(1<<uint(i+1)) * time.Millisecond
		}
	}
	return time.Duration(1<<uint(nBuckets)) * time.Millisecond
}

// Distribution renders the histogram, so a bimodal run (fast successes plus a
// wall of timeouts) is visible rather than averaged away.
func (h *Histogram) Distribution() string {
	total := h.count.Load()
	if total == 0 {
		return "(no samples)"
	}
	var sb strings.Builder
	for i := range nBuckets {
		n := h.buckets[i].Load()
		if n == 0 {
			continue
		}
		lo := time.Duration(1<<uint(i)) * time.Millisecond
		hi := time.Duration(1<<uint(i+1)) * time.Millisecond
		frac := float64(n) / float64(total)
		bar := strings.Repeat("#", int(frac*50)+1)
		fmt.Fprintf(&sb, "  %7s-%-7s %8d %5.1f%% %s\n", lo, hi, n, frac*100, bar)
	}
	return sb.String()
}
