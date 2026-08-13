package scan

import (
	"math/rand/v2"
	"sort"
)

// SampleIndices picks k distinct corpus positions out of n, uniformly at
// random, and returns them in ascending order.
//
// Sampling matters more than it looks. A corpus in popularity order means
// "scan the first N" is not a small sample of the web — it is a census of the
// best-resourced part of it. The first 5,000 Tranco entries are Google,
// Cloudflare and Facebook, whose ops teams do not forget to configure www. A
// number drawn from there is close to a ceiling, not an estimate.
//
// Ascending order is not cosmetic: the feeder walks it in order, so mmap
// writes stay roughly sequential and the page cache is not thrashed.
//
// The seed is returned to the caller and recorded in the run metadata, so the
// same sample can be drawn again and a published number can be re-checked
// against the identical domains.
func SampleIndices(n, k int, seed uint64) []int {
	if k >= n {
		idx := make([]int, n)
		for i := range idx {
			idx[i] = i
		}
		return idx
	}

	r := rand.New(rand.NewPCG(seed, 0x9E3779B97F4A7C15))

	// Floyd's algorithm: k distinct values from [0,n) using O(k) memory and
	// no shuffle of the full corpus, which matters when n is a billion and
	// k is a few hundred thousand.
	chosen := make(map[int]struct{}, k)
	for j := n - k; j < n; j++ {
		t := r.IntN(j + 1)
		if _, taken := chosen[t]; taken {
			t = j
		}
		chosen[t] = struct{}{}
	}

	idx := make([]int, 0, k)
	for i := range chosen {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	return idx
}
