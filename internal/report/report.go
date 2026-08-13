// Package report turns a (corpus, results) pair into the numbers the article
// is about, and into a CSV of individual cases worth looking at by hand.
package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/trones/www-scanner/internal/corpus"
	"github.com/trones/www-scanner/internal/record"
	"github.com/trones/www-scanner/internal/sink"
)

// Summary is the aggregate view of a run.
type Summary struct {
	Total       int
	Attempted   int
	Unattempted int
	// Population is the size of the corpus the sample was drawn from, used
	// for the finite-population correction on confidence intervals.
	Population int

	// ApexServes is the denominator that matters. A popularity list ranked
	// partly by DNS query volume is full of infrastructure — CDN edge
	// zones, API backends, resolver anycast names — that was never a
	// website and has no opinion about www. Measuring www support against
	// the whole corpus silently counts those as failures and drags the
	// headline down by tens of points.
	ApexServes int

	WWWSupported int
	// WWWSupportedOfServing is WWWSupported restricted to domains whose
	// apex serves. This is the number the article is actually about.
	WWWSupportedOfServing int
	// WWWBroken counts the finding: the apex serves a site, and www does
	// not. The bucket all four of my own domains were in.
	WWWBroken int
	// BrokenReason breaks WWWBroken down by which rung of the ladder gave
	// way. Three different mistakes by three different people.
	BrokenReason map[string]int

	// WWWWildcardOnly counts domains where www resolves only because the
	// zone answers to everything. These are the false positives the naive
	// boolean counts as support.
	WWWWildcardOnly int

	ApexResolve map[record.Resolve]int
	WWWResolve  map[record.Resolve]int
	WWWTLS      map[record.TLS]int
	WWWHTTP     map[int]int
	Canonical   map[record.Canonical]int
	RRTypes     map[record.RRTypes]int
}

// Build walks the results and aggregates them.
func Build(c *corpus.Corpus, res sink.Sink) Summary {
	s := Summary{
		BrokenReason: map[string]int{},
		ApexResolve:  map[record.Resolve]int{},
		WWWResolve:   map[record.Resolve]int{},
		WWWTLS:       map[record.TLS]int{},
		WWWHTTP:      map[int]int{},
		Canonical:    map[record.Canonical]int{},
		RRTypes:      map[record.RRTypes]int{},
	}
	n := min(len(c.Domains), res.Len())
	s.Total = n
	s.Population = len(c.Domains)

	for i := range n {
		r := res.Get(i)
		if r.Status == record.StatusUnattempted {
			s.Unattempted++
			continue
		}
		s.Attempted++
		s.ApexResolve[r.Apex.Resolve]++
		s.WWWResolve[r.WWW.Resolve]++
		s.WWWTLS[r.WWW.TLS]++
		s.WWWHTTP[int(r.WWW.HTTP)]++
		s.Canonical[r.Canonical]++
		s.RRTypes[r.WWW.RRTypes]++

		supported := r.WWWSupported()
		if supported {
			s.WWWSupported++
		} else if r.WWW.Resolve == record.ResolveOK && r.Flags.Has(record.FlagWildcard) {
			s.WWWWildcardOnly++
		}

		if apexServes(r) {
			s.ApexServes++
			if supported {
				s.WWWSupportedOfServing++
			} else {
				s.WWWBroken++
				s.BrokenReason[brokenReason(r)]++
			}
		}
	}
	return s
}

// apexServes reports whether the bare domain is a website at all. Anything
// else is not a domain with an opinion about www.
func apexServes(r record.Record) bool {
	return r.Apex.HTTP >= 200 && r.Apex.HTTP < 400 && r.Apex.TLS == record.TLSOK
}

// brokenReason names the rung that gave way, in ladder order, so each domain
// is attributed to the first thing that went wrong rather than the last.
func brokenReason(r record.Record) string {
	switch {
	case r.WWW.Resolve == record.ResolveNXDOMAIN:
		return "no dns record at all (nxdomain)"
	case r.WWW.Resolve == record.ResolveNoData:
		return "name exists, no address record"
	case r.WWW.Resolve != record.ResolveOK:
		return "dns " + r.WWW.Resolve.String()
	case r.WWW.TCP == record.TCPRefused:
		return "resolves, nothing listening"
	case r.WWW.TCP == record.TCPTimeout:
		return "resolves, connection hangs"
	case r.WWW.TCP != record.TCPOK:
		return "tcp " + r.WWW.TCP.String()
	case r.WWW.TLS == record.TLSNameMismatch:
		return "cert has no SAN for www"
	case r.WWW.TLS == record.TLSExpired:
		return "cert expired"
	case r.WWW.TLS != record.TLSOK:
		return "tls " + r.WWW.TLS.String()
	case r.WWW.HTTP >= 400:
		return fmt.Sprintf("serves, returns %d", r.WWW.HTTP)
	default:
		return "unclassified"
	}
}

// ConfidenceInterval returns the 95% margin of error on a proportion measured
// from a sample, in percentage points.
//
// A sample without an interval invites the reader to treat it as exact. The
// finite-population correction matters here because the sample is a large
// fraction of the corpus — at 15% of a million it narrows the interval by
// about 8%, and ignoring it would overstate the uncertainty.
func ConfidenceInterval(p float64, n, population int) float64 {
	if n <= 1 || p < 0 || p > 1 {
		return 0
	}
	se := math.Sqrt(p * (1 - p) / float64(n))
	if population > n {
		se *= math.Sqrt(float64(population-n) / float64(population-1))
	}
	return 1.96 * se * 100
}

// Write prints the summary.
func (s Summary) Write(w io.Writer) {
	fmt.Fprintf(w, "corpus       %d domains  (%d probed, %d not yet attempted)\n", s.Total, s.Attempted, s.Unattempted)
	if s.Attempted == 0 {
		return
	}
	pct := func(n int) string { return fmt.Sprintf("%5.2f%%", float64(n)/float64(s.Attempted)*100) }
	ofServing := func(n int) string {
		if s.ApexServes == 0 {
			return "    -"
		}
		return fmt.Sprintf("%5.2f%%", float64(n)/float64(s.ApexServes)*100)
	}

	fmt.Fprintf(w, "\nHEADLINE\n")
	fmt.Fprintf(w, "  probed                   %8d  domains that produced a result\n", s.Attempted)
	fmt.Fprintf(w, "  apex serves a site       %8d  %s of those\n", s.ApexServes, pct(s.ApexServes))
	fmt.Fprintf(w, "                                     (the rest is CDN/API infrastructure with no opinion about www)\n")
	if s.ApexServes > 0 {
		p := float64(s.WWWSupportedOfServing) / float64(s.ApexServes)
		ci := ConfidenceInterval(p, s.ApexServes, s.Population)
		fmt.Fprintf(w, "\n  ...of those, www works   %8d  %s +/- %.2f pts (95%% CI)   <- THE ANSWER\n",
			s.WWWSupportedOfServing, ofServing(s.WWWSupportedOfServing), ci)
	}
	fmt.Fprintf(w, "  ...of those, www broken  %8d  %s\n", s.WWWBroken, ofServing(s.WWWBroken))
	fmt.Fprintf(w, "\n  (www works across the whole corpus: %d, %s — but a popularity list ranked partly by\n", s.WWWSupported, pct(s.WWWSupported))
	fmt.Fprintf(w, "   DNS query volume is full of CDN and API infrastructure that was never a website,\n")
	fmt.Fprintf(w, "   so that denominator understates it.)\n")

	if s.WWWWildcardOnly > 0 {
		fmt.Fprintf(w, "\n  wildcard-only            %8d  %s of corpus (resolves, but the zone answers to any label)\n",
			s.WWWWildcardOnly, pct(s.WWWWildcardOnly))
	}

	if len(s.BrokenReason) > 0 {
		fmt.Fprintf(w, "\nHOW www BREAKS (on domains whose apex serves)\n")
		writeEnum(w, s.BrokenReason, s.WWWBroken, func(k string) string { return k })
	}

	fmt.Fprintf(w, "\nDNS — www\n")
	writeEnum(w, s.WWWResolve, s.Attempted, func(k record.Resolve) string { return k.String() })
	fmt.Fprintf(w, "\nDNS — apex\n")
	writeEnum(w, s.ApexResolve, s.Attempted, func(k record.Resolve) string { return k.String() })
	fmt.Fprintf(w, "\nTLS — www\n")
	writeEnum(w, s.WWWTLS, s.Attempted, func(k record.TLS) string { return k.String() })
	fmt.Fprintf(w, "\nRECORD TYPE — www\n")
	writeEnum(w, s.RRTypes, s.Attempted, func(k record.RRTypes) string { return k.String() })
	fmt.Fprintf(w, "\nCANONICAL DIRECTION\n")
	writeEnum(w, s.Canonical, s.Attempted, func(k record.Canonical) string { return k.String() })

	fmt.Fprintf(w, "\nHTTP STATUS — www (top 10)\n")
	type kv struct{ k, v int }
	pairs := make([]kv, 0, len(s.WWWHTTP))
	for k, v := range s.WWWHTTP {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
	for i, p := range pairs {
		if i >= 10 {
			break
		}
		label := strconv.Itoa(p.k)
		if p.k == 0 {
			label = "(none)"
		}
		fmt.Fprintf(w, "  %-34s %8d  %s\n", label, p.v, pct(p.v))
	}
}

func writeEnum[K comparable](w io.Writer, m map[K]int, total int, name func(K) string) {
	type kv struct {
		k K
		v int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
	for _, p := range pairs {
		fmt.Fprintf(w, "  %-34s %8d  %5.2f%%\n", name(p.k), p.v, float64(p.v)/float64(total)*100)
	}
}

// Filter selects records for the CSV export.
type Filter struct {
	// Only exports domains whose www classification matches one of these
	// names ("nxdomain", "name-mismatch", "wildcard", "both-serve", ...).
	// Empty exports everything attempted.
	Only string
}

// WriteCSV exports per-domain rows. This is the "interesting individual cases
// worth looking at by hand" half of the storage plan — the blob answers how
// many, this answers which ones.
func WriteCSV(w io.Writer, c *corpus.Corpus, res sink.Sink, f Filter) (int, error) {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{
		"domain", "canonical", "wildcard",
		"apex_dns", "apex_rr", "apex_tcp", "apex_tls", "apex_http", "apex_terminal", "apex_hops",
		"www_dns", "www_rr", "www_tcp", "www_tls", "www_http", "www_terminal", "www_hops",
		"duration_ms",
	}
	if err := cw.Write(header); err != nil {
		return 0, err
	}

	n := min(len(c.Domains), res.Len())
	count := 0
	for i := range n {
		r := res.Get(i)
		if r.Status == record.StatusUnattempted || !matches(r, f.Only) {
			continue
		}
		row := []string{
			c.Domains[i], r.Canonical.String(), strconv.FormatBool(r.Flags.Has(record.FlagWildcard)),
			r.Apex.Resolve.String(), r.Apex.RRTypes.String(), r.Apex.TCP.String(), r.Apex.TLS.String(),
			strconv.Itoa(int(r.Apex.HTTP)), r.Apex.Terminal.String(), strconv.Itoa(int(r.Apex.Hops)),
			r.WWW.Resolve.String(), r.WWW.RRTypes.String(), r.WWW.TCP.String(), r.WWW.TLS.String(),
			strconv.Itoa(int(r.WWW.HTTP)), r.WWW.Terminal.String(), strconv.Itoa(int(r.WWW.Hops)),
			strconv.Itoa(int(r.DurationM)),
		}
		if err := cw.Write(row); err != nil {
			return count, err
		}
		count++
	}
	return count, cw.Error()
}

func matches(r record.Record, only string) bool {
	switch strings.ToLower(strings.TrimSpace(only)) {
	case "", "all":
		return true
	case "wildcard":
		return r.Flags.Has(record.FlagWildcard)
	case "supported":
		return r.WWWSupported()
	case "stalled":
		// The probes that produced no finding. Re-probing these at low
		// concurrency is the only way to tell our congestion from hosts
		// that genuinely hang.
		return !r.Conclusive()
	case "broken":
		// The finding: apex works, www does not. This is the bucket all
		// four of my own domains were in.
		return r.Apex.HTTP >= 200 && r.Apex.HTTP < 400 && !r.WWWSupported()
	default:
		return r.WWW.Resolve.String() == only ||
			r.WWW.TLS.String() == only ||
			r.Canonical.String() == only ||
			r.WWW.Terminal.String() == only
	}
}

// Diff streams two result sets over the same corpus and reports what moved.
// This is how the census becomes a trend series: a merge join over two
// positional files, not a query over a billion rows.
type Change struct {
	Domain string
	From   record.Record
	To     record.Record
}

// Diff returns domains whose www classification changed between two runs.
func Diff(c *corpus.Corpus, before, after sink.Sink) []Change {
	n := min(len(c.Domains), min(before.Len(), after.Len()))
	var out []Change
	for i := range n {
		a, b := before.Get(i), after.Get(i)
		if a.Status == record.StatusUnattempted || b.Status == record.StatusUnattempted {
			continue
		}
		if a.WWWSupported() != b.WWWSupported() || a.Canonical != b.Canonical {
			out = append(out, Change{Domain: c.Domains[i], From: a, To: b})
		}
	}
	return out
}
