// Package scan drives the worker pool.
//
// The shape is deliberately plain: a feeder walks the corpus in order, N
// workers pull indices off a channel, and each worker writes its result at its
// own offset. There is no result channel and no collector goroutine, because
// positional records make both unnecessary — and a single collector goroutine
// is exactly the kind of accidental serialization that makes Little's N come
// out far below the worker count.
package scan

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/trones/www-scanner/internal/corpus"
	"github.com/trones/www-scanner/internal/metrics"
	"github.com/trones/www-scanner/internal/probe"
	"github.com/trones/www-scanner/internal/record"
	"github.com/trones/www-scanner/internal/sink"
)

// Options configures a run.
type Options struct {
	Workers int
	// Limit stops after this many corpus entries; 0 means the whole corpus.
	Limit int
	// Indices restricts the scan to these corpus positions, in the order
	// given. Nil scans 0..Limit. Used for sampling.
	Indices []int
	// Duration stops feeding new domains after this long, then waits for
	// in-flight probes to drain. Zero means run to the limit.
	//
	// Time-boxing is the right shape for a benchmark. Bounding by domain
	// count makes run time a function of the throughput being measured, so
	// the slowest configuration — the one you least want to sit through —
	// takes the longest, and no sweep has a predictable schedule.
	Duration time.Duration
	// Resume skips entries whose stored record is not StatusUnattempted.
	// Free, because the zero value means "never tried".
	Resume bool
	// ProgressEvery controls how often the progress line is emitted.
	ProgressEvery time.Duration
	// SyncEvery flushes dirty mmap pages periodically so a crash loses
	// seconds of work rather than the run.
	SyncEvery time.Duration
	// Progress receives the progress lines. Nil disables them.
	Progress io.Writer
}

// DefaultOptions returns a conservative starting point. 200 workers is chosen
// to be obviously below any limit worth discovering — the exercise is to raise
// it until something gives.
func DefaultOptions() Options {
	return Options{
		Workers:       200,
		ProgressEvery: 2 * time.Second,
		SyncEvery:     30 * time.Second,
	}
}

// Run scans the corpus into the sink and returns the collected metrics.
func Run(ctx context.Context, c *corpus.Corpus, p *probe.Prober, out sink.Sink, opts Options) (*metrics.Collector, error) {
	if opts.Workers <= 0 {
		opts.Workers = 1
	}
	total := len(c.Domains)
	if opts.Limit > 0 && opts.Limit < total {
		total = opts.Limit
	}
	if out.Len() < total {
		return nil, fmt.Errorf("sink holds %d records but the scan covers %d domains", out.Len(), total)
	}

	col := metrics.NewCollector()
	indices := make(chan int, opts.Workers*2)

	var wg sync.WaitGroup
	for range opts.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range indices {
				done := col.Begin()
				start := time.Now()
				rec := p.Probe(ctx, c.Domains[idx])
				elapsed := time.Since(start)
				// Write before observing, so a record counted as
				// complete is always a record already on disk.
				if err := out.Write(idx, rec); err != nil && opts.Progress != nil {
					fmt.Fprintf(opts.Progress, "\nwrite %d: %v\n", idx, err)
				}
				done()
				col.Observe(rec, elapsed)
			}
		}()
	}

	if opts.Indices != nil {
		total = len(opts.Indices)
	}
	stop := startReporters(ctx, col, out, opts, total)

	// A time box stops the feed but never cancels work already started:
	// cancelling in-flight probes would discard exactly the slow ones and
	// flatter the configurations that are struggling most.
	timeUp := make(chan struct{})
	if opts.Duration > 0 {
		t := time.AfterFunc(opts.Duration, func() { close(timeUp) })
		defer t.Stop()
	}

	// Feed in corpus order. Completions then land in roughly ascending
	// offsets, which keeps the mmap writes from scattering across the page
	// cache — the one thing that would make positional storage expensive.
	work := opts.Indices
	if work == nil {
		work = make([]int, total)
		for i := range work {
			work[i] = i
		}
	}

	fed := 0
feed:
	for _, idx := range work {
		if opts.Resume && out.Get(idx).Status != record.StatusUnattempted {
			col.Skip()
			continue
		}
		select {
		case <-timeUp:
			break feed
		default:
		}
		select {
		case indices <- idx:
			fed++
		case <-timeUp:
			break feed
		case <-ctx.Done():
			break feed
		}
	}
	close(indices)
	if opts.Duration > 0 {
		// Freeze the rate here, before the drain dilutes it.
		col.Mark()
	}
	if opts.Duration > 0 && opts.Progress != nil {
		fmt.Fprintf(opts.Progress, "\r%-140s\r  time box reached after %d dispatched; draining in-flight...\n", "", fed)
	}
	wg.Wait()
	stop()

	if err := out.Sync(); err != nil {
		return col, fmt.Errorf("final sync: %w", err)
	}
	return col, ctx.Err()
}

// startReporters runs the progress line and the periodic flush, and returns a
// function that stops both.
func startReporters(ctx context.Context, col *metrics.Collector, out sink.Sink, opts Options, total int) func() {
	done := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup

	if opts.Progress != nil && opts.ProgressEvery > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(opts.ProgressEvery)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					fmt.Fprintf(opts.Progress, "\r%-140s", col.Snapshot().ProgressLine(total, opts.Workers))
				case <-done:
					fmt.Fprintf(opts.Progress, "\r%-140s\r", "")
					return
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	if opts.SyncEvery > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(opts.SyncEvery)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					_ = out.Sync()
				case <-done:
					return
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	return func() {
		once.Do(func() { close(done) })
		wg.Wait()
	}
}
