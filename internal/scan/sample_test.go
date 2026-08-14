package scan

import "testing"

func TestSampleIndicesDistinctSortedInRange(t *testing.T) {
	const n, k = 100000, 5000
	idx := SampleIndices(n, k, 42)

	if len(idx) != k {
		t.Fatalf("got %d indices, want %d", len(idx), k)
	}
	seen := make(map[int]struct{}, k)
	for i, v := range idx {
		if v < 0 || v >= n {
			t.Fatalf("index %d out of range [0,%d)", v, n)
		}
		if _, dup := seen[v]; dup {
			t.Fatalf("index %d appears twice", v)
		}
		seen[v] = struct{}{}
		// Ascending order keeps mmap writes roughly sequential; an
		// unsorted sample would scatter them across the page cache.
		if i > 0 && idx[i-1] >= v {
			t.Fatalf("indices not ascending at %d: %d then %d", i, idx[i-1], v)
		}
	}
}

// The seed is recorded in run metadata precisely so a published number can be
// re-checked against the identical domains. If it does not reproduce, that
// promise is empty.
func TestSampleIndicesReproducible(t *testing.T) {
	a := SampleIndices(50000, 1000, 20260813)
	b := SampleIndices(50000, 1000, 20260813)
	if len(a) != len(b) {
		t.Fatalf("same seed produced %d and %d indices", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("same seed diverged at %d: %d vs %d", i, a[i], b[i])
		}
	}

	c := SampleIndices(50000, 1000, 20260814)
	same := 0
	for i := range a {
		if a[i] == c[i] {
			same++
		}
	}
	if same == len(a) {
		t.Fatal("different seeds produced an identical sample")
	}
}

func TestSampleIndicesFullCorpus(t *testing.T) {
	idx := SampleIndices(500, 500, 1)
	if len(idx) != 500 {
		t.Fatalf("got %d, want the whole corpus", len(idx))
	}
	idx = SampleIndices(500, 900, 1)
	if len(idx) != 500 {
		t.Fatalf("asking for more than exists returned %d, want 500", len(idx))
	}
}

// A biased sampler would quietly invalidate every percentage the scanner
// publishes, so check the draw is actually spread across the corpus rather
// than clustered at one end.
func TestSampleIndicesCoversCorpusEvenly(t *testing.T) {
	const n, k, buckets = 100000, 10000, 10
	idx := SampleIndices(n, k, 7)

	counts := make([]int, buckets)
	for _, v := range idx {
		counts[v*buckets/n]++
	}
	expected := k / buckets
	for b, got := range counts {
		// +/-20% of expected is loose enough not to flake and tight
		// enough to catch a sampler that favours a region.
		if got < expected*8/10 || got > expected*12/10 {
			t.Errorf("decile %d holds %d samples, want about %d — the draw is not uniform",
				b, got, expected)
		}
	}
}
