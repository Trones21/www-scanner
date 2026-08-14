package scan

import (
	"fmt"
	"strings"

	"github.com/trones/www-scanner/internal/record"
	"github.com/trones/www-scanner/internal/sink"
)

// RecheckFilter selects which of a previous run's records are worth probing
// again.
type RecheckFilter string

const (
	// RecheckBroken is the naughty list: the apex serves a site and www does
	// not. This is the population that actually changes between runs, and on
	// the Tranco million it is about 6.5% of the corpus — a quarter of an
	// hour of work rather than a day of it.
	RecheckBroken RecheckFilter = "broken"
	// RecheckWorking is the compliant set, for catching regressions. Usually
	// worth rechecking a rotating slice rather than all of it.
	RecheckWorking RecheckFilter = "working"
	// RecheckStalled re-probes what produced no finding. Run at low
	// concurrency it separates hosts that genuinely hang from congestion we
	// caused ourselves.
	RecheckStalled RecheckFilter = "stalled"
	// RecheckServing is every domain that is a website at all.
	RecheckServing RecheckFilter = "serving"
	// RecheckAll re-probes everything the previous run attempted.
	RecheckAll RecheckFilter = "all"
)

// ParseRecheckFilter validates a filter name.
func ParseRecheckFilter(s string) (RecheckFilter, error) {
	f := RecheckFilter(strings.ToLower(strings.TrimSpace(s)))
	switch f {
	case RecheckBroken, RecheckWorking, RecheckStalled, RecheckServing, RecheckAll:
		return f, nil
	}
	return "", fmt.Errorf("unknown recheck filter %q: want broken, working, stalled, serving or all", s)
}

func (f RecheckFilter) matches(r record.Record) bool {
	if r.Status == record.StatusUnattempted {
		return false
	}
	apexServes := r.Apex.HTTP >= 200 && r.Apex.HTTP < 400 && r.Apex.TLS == record.TLSOK
	switch f {
	case RecheckBroken:
		// Conclusive is load-bearing here. A probe that timed out is not
		// evidence that www is broken — it is the absence of evidence. Let
		// those into the naughty list and a daily recheck spends its time
		// re-confirming our own timeouts, and the cohort drifts toward
		// whatever is slowest rather than whatever is broken. They belong
		// to RecheckStalled, which exists to disambiguate them.
		return r.Conclusive() && apexServes && !r.WWWSupported()
	case RecheckWorking:
		return r.Conclusive() && apexServes && r.WWWSupported()
	case RecheckStalled:
		return !r.Conclusive()
	case RecheckServing:
		return apexServes
	case RecheckAll:
		return true
	}
	return false
}

// RecheckIndices selects corpus positions from a previous run's results.
//
// The indices are returned rather than a new corpus deliberately. Exporting the
// matching domains and scanning them as their own corpus would renumber
// everything, and positional records only mean anything relative to one corpus
// — the diff between two runs would stop being a merge join and start being a
// string join. Selecting indices instead keeps the new result file aligned with
// the same master corpus, so `wwwscan diff` keeps working and the census stays
// a series rather than a pile of unrelated files.
//
// stride > 1 takes every Nth match, which is how a rotating re-verification of
// the large compliant population is spread across many days.
func RecheckIndices(prev sink.Sink, f RecheckFilter, stride int) []int {
	if stride < 1 {
		stride = 1
	}
	var idx []int
	seen := 0
	for i := range prev.Len() {
		if !f.matches(prev.Get(i)) {
			continue
		}
		if seen%stride == 0 {
			idx = append(idx, i)
		}
		seen++
	}
	return idx
}
