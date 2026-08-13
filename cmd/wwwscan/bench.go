package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/trones/www-scanner/internal/corpus"
	"github.com/trones/www-scanner/internal/probe"
	"github.com/trones/www-scanner/internal/resolve"
	"github.com/trones/www-scanner/internal/scan"
	"github.com/trones/www-scanner/internal/sink"
)

// cmdBench sweeps configurations and prints a row per configuration as it
// finishes.
//
// Every run is time-boxed and every row appears the moment it is measured, so
// the sweep has a schedule you can read off before starting it and a partial
// answer at every point during it. Ctrl-C stops after the current row rather
// than throwing away the sweep.
func cmdBench(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	corpusPath := fs.String("corpus", "corpora/tranco.txt", "corpus file")
	workersList := fs.String("workers", "200,1000,4000", "comma-separated worker counts to sweep")
	socketsList := fs.String("dns-sockets", "8", "comma-separated pooled sockets per upstream; 0 means one socket per query")
	dur := fs.Duration("duration", 15*time.Second, "time box per configuration")
	// Non-filtering addresses only. A resolver that blocks anything returns
	// NXDOMAIN for it, and NXDOMAIN is the single most important signal this
	// scanner reads — 9.9.9.9 is Quad9's malware-blocking address and would
	// silently report its blocklist as missing www records. 9.9.9.10 is the
	// unfiltered one. Same reason 1.1.1.2 (Cloudflare malware) and the
	// AdGuard/OpenDNS filtering addresses are absent.
	servers := fs.String("resolver", "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.10,149.112.112.10",
		"comma-separated DNS servers; use only non-filtering resolvers, since a blocked domain arrives as NXDOMAIN and is indistinguishable from a missing record")
	offset := fs.Int("offset", 0, "start this far into the corpus")
	timeout := fs.Duration("timeout", 10*time.Second, "per-name HTTP timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	workers, err := intList(*workersList)
	if err != nil {
		return fmt.Errorf("-workers: %w", err)
	}
	sockets, err := intList(*socketsList)
	if err != nil {
		return fmt.Errorf("-dns-sockets: %w", err)
	}

	// net/http logs HTTP/2 frame violations from other people's servers
	// through the standard logger, which would shred the progress line.
	log.SetOutput(io.Discard)

	c, err := corpus.Load(*corpusPath)
	if err != nil {
		return err
	}
	if *offset >= len(c.Domains) {
		return fmt.Errorf("-offset %d is past the end of a %d-domain corpus", *offset, len(c.Domains))
	}
	// Each configuration gets a fresh slice of the corpus. Reusing the same
	// domains would let DNS caches warm between runs and make whichever
	// configuration ran last look fastest.
	pool := c.Domains[*offset:]

	runs := len(workers) * len(sockets)
	drain := *timeout + 5*time.Second
	fmt.Fprintf(os.Stderr, "sweeping %d configurations x (%s + up to %s drain) = about %s total\n",
		runs, *dur, drain, (time.Duration(runs) * (*dur + drain)).Round(time.Second))
	fmt.Fprintf(os.Stderr, "corpus %s, starting at offset %d, resolver %s\n", *corpusPath, *offset, *servers)
	reportFDLimit(workers)

	fmt.Printf("%-8s %-8s %8s %8s %7s %8s %8s  %s\n",
		"workers", "sockets", "raw/s", "eff/s", "valid", "little'sN", "probed", "stalled on")
	fmt.Printf("%s\n", strings.Repeat("-", 88))

	used := 0
	for _, s := range sockets {
		for _, w := range workers {
			if ctx.Err() != nil {
				fmt.Fprintf(os.Stderr, "\nsweep interrupted; rows above are complete measurements\n")
				return nil
			}

			// Give each run its own domains, sized generously so the time
			// box is what ends it rather than running out of corpus.
			want := w * 40
			if want > len(pool)-used {
				want = len(pool) - used
			}
			if want < w {
				return fmt.Errorf("corpus exhausted after %d configurations; use a larger corpus or fewer runs", used)
			}
			slice := &corpus.Corpus{Domains: pool[used : used+want]}
			used += want

			row, err := benchOne(ctx, slice, benchCfg{
				workers: w, sockets: s, duration: *dur,
				servers: *servers, timeout: *timeout,
			})
			if err != nil {
				return err
			}

			label := strconv.Itoa(s)
			if s == 0 {
				label = "legacy"
			}
			fmt.Printf("%-8d %-8s %8.1f %8.1f %6.1f%% %8.0f %8d  %s\n",
				w, label, row.raw, row.eff, row.validity*100, row.littleN, row.probed, row.stalls)
		}
	}
	fmt.Fprintf(os.Stderr, "\neff/s is the number to compare: raw/s counts timeouts, which get cheaper as\n")
	fmt.Fprintf(os.Stderr, "concurrency breaks the scan, so raw rewards exactly the failure to avoid.\n")
	fmt.Fprintf(os.Stderr, "\nstalled on: dns = resolver rate limiting or an unreachable resolver;\n")
	fmt.Fprintf(os.Stderr, "tcp = egress filtering, provider SYN limits, or a file-descriptor ceiling;\n")
	fmt.Fprintf(os.Stderr, "tls = cpu starvation or the far end. These need opposite fixes.\n")
	return nil
}

type benchCfg struct {
	workers  int
	sockets  int
	duration time.Duration
	servers  string
	timeout  time.Duration
}

type benchRow struct {
	raw, eff, validity, littleN float64
	probed                      int64
	stalls                      string
}

func benchOne(ctx context.Context, c *corpus.Corpus, cfg benchCfg) (benchRow, error) {
	rcfg := resolve.DefaultConfig()
	rcfg.SocketsPerServer = cfg.sockets
	for _, s := range strings.Split(cfg.servers, ",") {
		if s = strings.TrimSpace(s); s != "" {
			rcfg.Servers = append(rcfg.Servers, s)
		}
	}
	res, err := resolve.New(rcfg)
	if err != nil {
		return benchRow{}, err
	}
	defer res.Close()

	pcfg := probe.DefaultConfig()
	pcfg.Timeout = cfg.timeout
	p := probe.New(pcfg, res, cfg.workers*2)

	opts := scan.DefaultOptions()
	opts.Workers = cfg.workers
	opts.Duration = cfg.duration
	opts.Resume = false
	opts.SyncEvery = 0
	opts.Progress = os.Stderr
	opts.ProgressEvery = time.Second

	fmt.Fprintf(os.Stderr, "  running workers=%d sockets=%d for %s...\n", cfg.workers, cfg.sockets, cfg.duration)

	col, err := scan.Run(ctx, c, p, sink.NewNull(len(c.Domains)), opts)
	if err != nil && ctx.Err() == nil {
		return benchRow{}, err
	}
	s := col.Steady()
	fmt.Fprintf(os.Stderr, "\r%-140s\r", "")
	return benchRow{
		raw: s.Rate, eff: s.EffectiveRate, validity: s.Validity,
		littleN: s.LittleN, probed: s.Completed, stalls: s.StallSummary(),
	}, nil
}

func intList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a number", part)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no values given")
	}
	return out, nil
}

// reportFDLimit warns when the process cannot open enough sockets for the
// concurrency being asked of it.
//
// Each in-flight probe holds roughly two connections, so a soft limit of 1024
// caps useful concurrency near 400 workers no matter what -workers says. The
// failures it produces look exactly like network trouble.
func reportFDLimit(workers []int) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return
	}
	maxWorkers := 0
	for _, w := range workers {
		if w > maxWorkers {
			maxWorkers = w
		}
	}
	need := uint64(maxWorkers)*2 + 128
	fmt.Fprintf(os.Stderr, "open files %d soft / %d hard; peak config needs about %d\n",
		lim.Cur, lim.Max, need)
	if lim.Cur < need {
		fmt.Fprintf(os.Stderr,
			"WARNING: the soft limit is below what %d workers need. Results above that\n"+
				"         point measure the fd ceiling, not the network. Raise it with\n"+
				"         'ulimit -n %d' before rerunning.\n", maxWorkers, lim.Max)
	}
	fmt.Fprintln(os.Stderr)
}
