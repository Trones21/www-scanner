package scan

import (
	"testing"

	"github.com/trones/www-scanner/internal/record"
	"github.com/trones/www-scanner/internal/sink"
)

var _ sink.Sink = (*memSink)(nil)

// buildPrev fills a sink with one record of each interesting shape, at known
// positions, so a filter's output can be checked by index.
func buildPrev(t *testing.T) sink.Sink {
	t.Helper()
	mm := newMemSink(8)

	serving := record.Side{Resolve: record.ResolveOK, TCP: record.TCPOK, TLS: record.TLSOK, HTTP: 200}

	// 0: apex serves, www serves — working
	mm.set(0, record.Record{Status: record.StatusComplete, Apex: serving, WWW: serving})
	// 1: apex serves, www NXDOMAIN — broken
	mm.set(1, record.Record{Status: record.StatusComplete, Apex: serving,
		WWW: record.Side{Resolve: record.ResolveNXDOMAIN}})
	// 2: apex serves, www cert mismatch — broken
	mm.set(2, record.Record{Status: record.StatusComplete, Apex: serving,
		WWW: record.Side{Resolve: record.ResolveOK, TCP: record.TCPOK, TLS: record.TLSNameMismatch}})
	// 3: apex does not serve — not in any apex-based cohort
	mm.set(3, record.Record{Status: record.StatusComplete,
		Apex: record.Side{Resolve: record.ResolveNXDOMAIN},
		WWW:  record.Side{Resolve: record.ResolveNXDOMAIN}})
	// 4: www timed out — stalled
	mm.set(4, record.Record{Status: record.StatusComplete, Apex: serving,
		WWW: record.Side{Resolve: record.ResolveOK, TCP: record.TCPTimeout}})
	// 5: never probed — in nothing
	// 6: apex serves, www serves — working
	mm.set(6, record.Record{Status: record.StatusComplete, Apex: serving, WWW: serving})
	// 7: apex serves, www 404 — broken
	mm.set(7, record.Record{Status: record.StatusComplete, Apex: serving,
		WWW: record.Side{Resolve: record.ResolveOK, TCP: record.TCPOK, TLS: record.TLSOK, HTTP: 404}})
	return mm
}

func TestRecheckIndicesSelectsCohorts(t *testing.T) {
	prev := buildPrev(t)

	tests := []struct {
		filter RecheckFilter
		want   []int
	}{
		{RecheckBroken, []int{1, 2, 7}},
		{RecheckWorking, []int{0, 6}},
		{RecheckServing, []int{0, 1, 2, 4, 6, 7}},
		// index 4 stalled; 3 and 5 are conclusive/unattempted respectively
		{RecheckStalled, []int{4}},
		{RecheckAll, []int{0, 1, 2, 3, 4, 6, 7}},
	}
	for _, tc := range tests {
		t.Run(string(tc.filter), func(t *testing.T) {
			got := RecheckIndices(prev, tc.filter, 1)
			if len(got) != len(tc.want) {
				t.Fatalf("%s selected %v, want %v", tc.filter, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("%s selected %v, want %v", tc.filter, got, tc.want)
				}
			}
		})
	}
}

// Indices must stay relative to the master corpus, or the diff between two runs
// stops being a merge join.
func TestRecheckIndicesArePositions(t *testing.T) {
	got := RecheckIndices(buildPrev(t), RecheckBroken, 1)
	for _, idx := range got {
		if idx < 0 || idx >= 8 {
			t.Fatalf("index %d is not a position in the master corpus", idx)
		}
	}
}

func TestRecheckStrideRotates(t *testing.T) {
	prev := buildPrev(t)
	all := RecheckIndices(prev, RecheckServing, 1)
	every2 := RecheckIndices(prev, RecheckServing, 2)

	if len(every2) != (len(all)+1)/2 {
		t.Errorf("stride 2 selected %d of %d, want %d", len(every2), len(all), (len(all)+1)/2)
	}
	for _, idx := range every2 {
		found := false
		for _, a := range all {
			if a == idx {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("stride selected %d, which is not in the unstrided set", idx)
		}
	}
}

func TestParseRecheckFilter(t *testing.T) {
	for _, ok := range []string{"broken", "WORKING", " stalled ", "serving", "all"} {
		if _, err := ParseRecheckFilter(ok); err != nil {
			t.Errorf("ParseRecheckFilter(%q) errored: %v", ok, err)
		}
	}
	if _, err := ParseRecheckFilter("naughty"); err == nil {
		t.Error("ParseRecheckFilter accepted an unknown filter")
	}
}

// memSink is an in-memory Sink for tests, so cohort selection can be checked
// without touching the filesystem.
type memSink struct{ recs []record.Record }

func newMemSink(n int) *memSink               { return &memSink{recs: make([]record.Record, n)} }
func (m *memSink) set(i int, r record.Record) { m.recs[i] = r }

func (m *memSink) Write(i int, r record.Record) error {
	m.recs[i] = r
	return nil
}
func (m *memSink) Get(i int) record.Record { return m.recs[i] }
func (m *memSink) Len() int                { return len(m.recs) }
func (m *memSink) Sync() error             { return nil }
func (m *memSink) Close() error            { return nil }
