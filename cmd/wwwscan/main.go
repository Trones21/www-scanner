// Command wwwscan classifies www support across a domain corpus.
//
//	wwwscan corpus  -out corpora/tranco.txt        materialize a frozen corpus
//	wwwscan probe   example.com                    one domain, human-readable
//	wwwscan scan    -corpus ... -out ...           the run
//	wwwscan report  -corpus ... -results ...       the numbers
//	wwwscan diff    -corpus ... -a ... -b ...      what moved between runs
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/trones/www-scanner/internal/corpus"
	"github.com/trones/www-scanner/internal/metrics"
	"github.com/trones/www-scanner/internal/probe"
	"github.com/trones/www-scanner/internal/record"
	"github.com/trones/www-scanner/internal/report"
	"github.com/trones/www-scanner/internal/resolve"
	"github.com/trones/www-scanner/internal/runmeta"
	"github.com/trones/www-scanner/internal/scan"
	"github.com/trones/www-scanner/internal/sink"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "corpus":
		err = cmdCorpus(ctx, os.Args[2:])
	case "probe":
		err = cmdProbe(ctx, os.Args[2:])
	case "scan":
		err = cmdScan(ctx, os.Args[2:])
	case "bench":
		err = cmdBench(ctx, os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "wwwscan: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `wwwscan — does www still work?

  corpus   materialize a frozen, checksummed domain list
  probe    classify a single domain, human-readable
  scan     run the corpus through the classifier
  bench    sweep worker/socket configurations, time-boxed, a row at a time
  report   aggregate a result file
  diff     compare two result files over the same corpus

Run "wwwscan <command> -h" for flags.
`)
}

// resolverFlags are shared by probe and scan.
type resolverFlags struct {
	servers  string
	timeout  time.Duration
	attempts int
	sockets  int
}

func (rf *resolverFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&rf.servers, "resolver", "", "comma-separated DNS servers (default: /etc/resolv.conf, which on systemd is the 127.0.0.53 stub — replace this before raising -workers)")
	fs.DurationVar(&rf.timeout, "dns-timeout", 3*time.Second, "per-query DNS timeout")
	fs.IntVar(&rf.attempts, "dns-attempts", 2, "DNS attempts per query")
	fs.IntVar(&rf.sockets, "dns-sockets", 8, "multiplexed UDP sockets per upstream; 0 uses one fresh socket per query, which saturates the ephemeral port range around 10k workers")
}

func (rf *resolverFlags) build() (*resolve.Resolver, error) {
	cfg := resolve.DefaultConfig()
	cfg.Timeout = rf.timeout
	cfg.Attempts = rf.attempts
	cfg.SocketsPerServer = rf.sockets
	if rf.servers != "" {
		for _, s := range strings.Split(rf.servers, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.Servers = append(cfg.Servers, s)
			}
		}
	}
	return resolve.New(cfg)
}

func cmdCorpus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("corpus", flag.ExitOnError)
	out := fs.String("out", "corpora/tranco.txt", "path to write the frozen corpus")
	src := fs.String("from", "", "import from a local file instead of downloading Tranco")
	date := fs.String("date", "latest", "Tranco list date (YYYY-MM-DD or 'latest')")
	limit := fs.Int("limit", 0, "keep only the top N domains (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if dir := dirOf(*out); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	var m *corpus.Manifest
	var err error
	if *src != "" {
		m, err = corpus.FromFile(*src, *out, *limit)
	} else {
		fmt.Fprintf(os.Stderr, "resolving tranco list for %s...\n", *date)
		m, err = corpus.FetchTranco(ctx, *out, *date, *limit)
	}
	if err != nil {
		return err
	}

	fmt.Printf("wrote %s\n", *out)
	fmt.Printf("  domains  %d\n", m.Count)
	fmt.Printf("  source   %s\n", m.Source)
	if m.ListID != "" {
		fmt.Printf("  list id  %s  (permanent: %s)\n", m.ListID, m.SourceURL)
	}
	fmt.Printf("  sha256   %s\n", m.SHA256)
	return nil
}

func cmdProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	var rf resolverFlags
	rf.register(fs)
	timeout := fs.Duration("timeout", 10*time.Second, "per-name HTTP timeout")
	noWildcard := fs.Bool("no-wildcard-check", false, "skip the random-label wildcard probe")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("probe needs at least one domain")
	}

	res, err := rf.build()
	if err != nil {
		return err
	}
	pcfg := probe.DefaultConfig()
	pcfg.Timeout = *timeout
	pcfg.WildcardCheck = !*noWildcard
	p := probe.New(pcfg, res, 64)

	fmt.Printf("resolver: %s\n", strings.Join(res.Servers(), ", "))
	for _, d := range fs.Args() {
		start := time.Now()
		r := p.Probe(ctx, d)
		printProbe(d, r, time.Since(start))
	}
	return nil
}

func printProbe(domain string, r record.Record, elapsed time.Duration) {
	w := max(len("www."+domain), 12)
	fmt.Printf("\n%s  (%s)\n", domain, elapsed.Round(time.Millisecond))
	fmt.Printf("  %-*s  %-8s %-12s %-11s %-17s %-5s %-9s %s\n",
		w, "name", "dns", "rr", "tcp", "tls", "http", "terminal", "hops")
	printSide(w, domain, r.Apex)
	printSide(w, "www."+domain, r.WWW)

	fmt.Printf("  canonical: %s\n", r.Canonical)
	if r.Flags.Has(record.FlagWildcard) {
		fmt.Printf("  wildcard:  yes — a random label resolves too, so www resolving proves nothing\n")
	} else if r.Flags.Has(record.FlagWildcardChecked) {
		fmt.Printf("  wildcard:  no\n")
	}
	if r.Flags.Has(record.FlagHTTPFallback) {
		fmt.Printf("  note:      https failed, so the http status above came from a plaintext retry\n")
	}
	if r.WWWSupported() {
		fmt.Printf("  verdict:   www works\n")
	} else {
		fmt.Printf("  verdict:   www does NOT work — %s\n", explain(r))
	}
}

func printSide(w int, name string, s record.Side) {
	http := "-"
	if s.HTTP != 0 {
		http = fmt.Sprintf("%d", s.HTTP)
	}
	fmt.Printf("  %-*s  %-8s %-12s %-11s %-17s %-5s %-9s %d\n",
		w, name, s.Resolve, s.RRTypes, s.TCP, s.TLS, http, s.Terminal, s.Hops)
}

// explain names the rung of the ladder that broke. Each of these is a
// different mistake by a different person; flattening them to "no" is what
// throws away the finding.
func explain(r record.Record) string {
	switch {
	case r.WWW.Resolve == record.ResolveNXDOMAIN:
		return "the name does not exist (no record at all)"
	case r.WWW.Resolve == record.ResolveNoData:
		return "the name exists but has no address record"
	case r.WWW.Resolve != record.ResolveOK:
		return "dns " + r.WWW.Resolve.String()
	case r.WWW.TCP == record.TCPRefused:
		return "resolves, but nothing is listening"
	case r.WWW.TCP == record.TCPTimeout:
		return "resolves, but the connection hangs"
	case r.WWW.TLS == record.TLSNameMismatch:
		return "the certificate has no SAN entry for this name"
	case r.WWW.TLS == record.TLSExpired:
		return "the certificate has expired"
	case r.WWW.TLS != record.TLSOK && r.WWW.TLS != record.TLSUnattempted:
		return "tls " + r.WWW.TLS.String()
	case r.WWW.HTTP >= 400:
		return fmt.Sprintf("serves, but returns %d (the vhost likely only knows the apex)", r.WWW.HTTP)
	default:
		return "unclassified"
	}
}

func cmdScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var rf resolverFlags
	rf.register(fs)
	corpusPath := fs.String("corpus", "", "corpus file (required)")
	outPath := fs.String("out", "", "result file; empty writes nowhere")
	mode := fs.String("mode", "census", "census (correctness first, validity enforced) or throughput (null sink, any concurrency, findings not trusted)")
	nullSink := fs.Bool("null-sink", false, "discard results — implied by -mode throughput")
	workers := fs.Int("workers", 200, "concurrent probes in flight")
	limit := fs.Int("limit", 0, "scan only the first N domains in corpus order (0 = all) — this is the HEAD of a popularity-ranked list, not a sample")
	sample := fs.Int("sample", 0, "randomly sample N domains from across the whole corpus (preferred over -limit for any published number)")
	seed := fs.Uint64("seed", 0, "sample seed; 0 picks one and records it so the sample is reproducible")
	recheck := fs.String("recheck", "", "re-probe only the domains a previous result file matched (path to that .bin)")
	recheckFilter := fs.String("recheck-filter", "broken", "which of them: broken, working, stalled, serving, all")
	recheckStride := fs.Int("recheck-stride", 1, "take every Nth match, for rotating re-verification across days")
	duration := fs.Duration("duration", 0, "stop feeding new domains after this long, then drain (0 = no time box)")
	resume := fs.Bool("resume", true, "skip domains that already have a result")
	timeout := fs.Duration("timeout", 10*time.Second, "per-name HTTP timeout")
	connTimeout := fs.Duration("connect-timeout", 5*time.Second, "TCP/TLS connect timeout")
	noWildcard := fs.Bool("no-wildcard-check", false, "skip the random-label wildcard probe")
	checkDeleg := fs.Bool("check-delegation", false, "also query NS at the apex, separating 'not registered' from 'registered but pointed nowhere'")
	noFallback := fs.Bool("no-http-fallback", false, "do not retry plaintext when TLS fails")
	histogram := fs.Bool("histogram", false, "print the completion-time distribution at the end")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" {
		return fmt.Errorf("scan needs -corpus")
	}
	switch *mode {
	case "census":
		if *outPath == "" && !*nullSink {
			return fmt.Errorf("a census run needs -out (or -mode throughput to measure speed instead)")
		}
	case "throughput":
		// A throughput run must not write a result file. Its output is a
		// rate, and the records it would produce are contaminated by the
		// very concurrency being measured — exactly the data that must
		// never end up in a census.
		if *outPath != "" {
			return fmt.Errorf("-mode throughput cannot write results: at benchmark concurrency the records measure the scanner, not the web")
		}
		*nullSink = true
	default:
		return fmt.Errorf("unknown -mode %q: want census or throughput", *mode)
	}

	c, err := corpus.Load(*corpusPath)
	if err != nil {
		return err
	}

	total := len(c.Domains)
	if *limit > 0 && *limit < total {
		total = *limit
	}

	var out sink.Sink
	if *nullSink {
		out = sink.NewNull(len(c.Domains))
	} else {
		if dir := dirOf(*outPath); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		mm, err := sink.Create(*outPath, len(c.Domains))
		if err != nil {
			return err
		}
		defer mm.Close()
		out = mm
	}

	res, err := rf.build()
	if err != nil {
		return err
	}
	pcfg := probe.DefaultConfig()
	pcfg.Timeout = *timeout
	pcfg.ConnectTimeout = *connTimeout
	pcfg.WildcardCheck = !*noWildcard
	pcfg.CheckDelegation = *checkDeleg
	pcfg.HTTPFallback = !*noFallback
	p := probe.New(pcfg, res, *workers*2)

	opts := scan.DefaultOptions()
	opts.Workers = *workers
	opts.Limit = *limit
	opts.Duration = *duration

	// Sampling and -limit are different claims about the world, so refuse
	// to guess which one was meant.
	if *sample > 0 && *limit > 0 {
		return fmt.Errorf("use -sample or -limit, not both: one draws from the whole corpus, the other takes the head of it")
	}
	if *recheck != "" && (*sample > 0 || *limit > 0) {
		return fmt.Errorf("-recheck selects its own domains; drop -sample and -limit")
	}
	sampleMeta := runmeta.Sample{
		Method: "full", Size: len(c.Domains),
		Fraction: "100%", Note: "every domain in the corpus",
	}
	if *sample > 0 {
		if *sample > len(c.Domains) {
			return fmt.Errorf("-sample %d exceeds the %d-domain corpus", *sample, len(c.Domains))
		}
		s := *seed
		if s == 0 {
			s = uint64(time.Now().UnixNano())
		}
		opts.Indices = scan.SampleIndices(len(c.Domains), *sample, s)
		total = len(opts.Indices)
		sampleMeta = runmeta.Sample{
			Method: "random", Size: *sample, Seed: s,
			Fraction: fmt.Sprintf("%.2f%%", float64(*sample)/float64(len(c.Domains))*100),
			Note:     "uniform random sample drawn across the whole corpus",
		}
	} else if *recheck != "" {
		prev, err := sink.Open(*recheck)
		if err != nil {
			return fmt.Errorf("open previous results: %w", err)
		}
		defer prev.Close()
		if prev.Len() != len(c.Domains) {
			return fmt.Errorf("previous results hold %d records but this corpus has %d domains; a recheck must run against the corpus it was written for",
				prev.Len(), len(c.Domains))
		}
		f, err := scan.ParseRecheckFilter(*recheckFilter)
		if err != nil {
			return err
		}
		opts.Indices = scan.RecheckIndices(prev, f, *recheckStride)
		if len(opts.Indices) == 0 {
			return fmt.Errorf("no domains in %s match filter %q", *recheck, *recheckFilter)
		}
		total = len(opts.Indices)
		note := fmt.Sprintf("re-probe of domains matching %q in %s", *recheckFilter, *recheck)
		if *recheckStride > 1 {
			note += fmt.Sprintf(", every %d%s match", *recheckStride, ordinalSuffix(*recheckStride))
		}
		sampleMeta = runmeta.Sample{
			Method: "recheck", Size: len(opts.Indices),
			Fraction: fmt.Sprintf("%.2f%%", float64(len(opts.Indices))/float64(len(c.Domains))*100),
			Note:     note,
		}
	} else if *limit > 0 {
		sampleMeta = runmeta.Sample{
			Method: "head", Size: *limit,
			Fraction: fmt.Sprintf("%.2f%%", float64(*limit)/float64(len(c.Domains))*100),
			Note:     "the FIRST N in corpus order — for a ranked corpus this is the most popular domains, not a representative sample",
		}
	}
	opts.Resume = *resume && !*nullSink
	opts.Progress = os.Stderr

	fmt.Fprintf(os.Stderr, "corpus    %s (%d domains", *corpusPath, len(c.Domains))
	if c.Manifest.ListID != "" {
		fmt.Fprintf(os.Stderr, ", tranco %s", c.Manifest.ListID)
	}
	fmt.Fprintf(os.Stderr, ")\n")
	if *nullSink {
		fmt.Fprintf(os.Stderr, "sink      null (throughput run)\n")
	} else {
		fmt.Fprintf(os.Stderr, "sink      %s (%d bytes/domain, %s total)\n",
			*outPath, record.Width, humanBytes(int64(len(c.Domains))*record.Width))
	}
	if n := res.Sockets(); n > 0 {
		fmt.Fprintf(os.Stderr, "resolver  %s  (%d pooled sockets => %d ephemeral ports)\n",
			strings.Join(res.Servers(), ", "), n, n)
	} else {
		fmt.Fprintf(os.Stderr, "resolver  %s  (legacy: one socket per query — expect port exhaustion above ~5k workers)\n",
			strings.Join(res.Servers(), ", "))
	}
	fmt.Fprintf(os.Stderr, "mode      %s\n", *mode)
	fmt.Fprintf(os.Stderr, "workers   %d  (GOMAXPROCS %d)\n", *workers, runtime.GOMAXPROCS(0))
	fmt.Fprintf(os.Stderr, "scanning  %d domains\n\n", total)

	// net/http's HTTP/2 transport logs frame-level protocol violations
	// through the standard logger, unconditionally. Across a million
	// strangers' servers those are constant, they are not our bug, and they
	// shred the progress line. We log nothing through the standard logger
	// ourselves, so discarding it costs nothing.
	log.SetOutput(io.Discard)

	started := time.Now()
	col, err := scan.Run(ctx, c, p, out, opts)
	if col != nil {
		col.WriteSummary(os.Stderr, *workers)
	}

	if !*nullSink && col != nil {
		snap := col.Snapshot()
		meta := runmeta.Meta{
			Tool: "wwwscan", Mode: *mode,
			Started: started, Ended: time.Now(),
			Elapsed: snap.Elapsed.Round(time.Second).String(),
			Corpus: runmeta.Corpus{
				Path: *corpusPath, Count: len(c.Domains),
				SHA256: c.Manifest.SHA256, Source: c.Manifest.Source,
				ListID: c.Manifest.ListID, SourceURL: c.Manifest.SourceURL,
				Description: c.Manifest.Description,
			},
			Sample: sampleMeta,
			Config: runmeta.Config{
				Workers: *workers, Resolvers: res.Servers(), DNSSockets: rf.sockets,
				DNSTimeout: rf.timeout.String(), DNSAttempts: rf.attempts,
				HTTPTimeout: timeout.String(), ConnectTimeout: connTimeout.String(),
				WildcardCheck: !*noWildcard, HTTPFallback: !*noFallback,
			},
			Result: runmeta.Result{
				Probed: snap.Completed, Skipped: snap.Skipped, Conclusive: snap.Conclusive,
				Validity: snap.Validity, ValidCensus: snap.Validity >= metrics.CensusValidityFloor,
				RawPerSec: snap.Rate, EffPerSec: snap.EffectiveRate,
				MeanLatencyMS: snap.Mean.Milliseconds(), Stalls: snap.Stalls,
			},
		}
		if err := runmeta.Write(*outPath, meta); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "\nprovenance written to %s\n", runmeta.Path(*outPath))
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\ninterrupted — rerun the same command to resume from where it stopped\n")
		return nil
	}
	if *histogram {
		fmt.Fprintf(os.Stderr, "\ncompletion time distribution:\n%s", col.Histogram())
	}
	if !*nullSink {
		fmt.Fprintf(os.Stderr, "\nresults in %s — wwwscan report -corpus %s -results %s\n", *outPath, *corpusPath, *outPath)
	}
	return nil
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	corpusPath := fs.String("corpus", "", "corpus file (required)")
	resultsPath := fs.String("results", "", "result file (required)")
	csvOut := fs.String("csv", "", "also write per-domain rows here")
	only := fs.String("only", "", "csv filter: supported, broken, wildcard, or any classification name (nxdomain, name-mismatch, both-serve-no-canonical, ...)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" || *resultsPath == "" {
		return fmt.Errorf("report needs -corpus and -results")
	}

	c, err := corpus.Load(*corpusPath)
	if err != nil {
		return err
	}
	res, err := sink.Open(*resultsPath)
	if err != nil {
		return err
	}
	defer res.Close()

	if res.Len() != len(c.Domains) {
		return fmt.Errorf("results hold %d records but the corpus has %d domains; these do not belong together",
			res.Len(), len(c.Domains))
	}

	// Matching record counts are not proof of a matching corpus: two Tranco
	// lists from different days are both exactly a million entries, and
	// pairing one day's results with another day's names silently attaches
	// every record to the wrong domain. The checksum is what actually binds
	// them.
	meta, hasMeta := runmeta.Load(*resultsPath)
	if hasMeta {
		if meta.Corpus.SHA256 != "" && c.Manifest.SHA256 != "" && meta.Corpus.SHA256 != c.Manifest.SHA256 {
			return fmt.Errorf(
				"these results were produced against a different corpus\n"+
					"  results were written against : %s (%s)\n"+
					"  you are reporting against    : %s (%s)\n"+
					"positional records are meaningless across corpora — every row would name the wrong domain",
				meta.Corpus.ListID, short(meta.Corpus.SHA256), c.Manifest.ListID, short(c.Manifest.SHA256))
		}
		fmt.Print(meta.Describe())
		fmt.Println()
	} else {
		fmt.Printf("RUN\n  (no provenance file at %s — this result predates run metadata,\n"+
			"   so what was probed and how cannot be verified)\n\n", runmeta.Path(*resultsPath))
	}

	report.Build(c, res).Write(os.Stdout)

	if *csvOut != "" {
		f, err := os.Create(*csvOut)
		if err != nil {
			return err
		}
		defer f.Close()
		n, err := report.WriteCSV(f, c, res, report.Filter{Only: *only})
		if err != nil {
			return err
		}
		fmt.Printf("\nwrote %d rows to %s\n", n, *csvOut)
	}
	return nil
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	corpusPath := fs.String("corpus", "", "corpus file both runs used (required)")
	aPath := fs.String("a", "", "earlier result file (required)")
	bPath := fs.String("b", "", "later result file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" || *aPath == "" || *bPath == "" {
		return fmt.Errorf("diff needs -corpus, -a and -b")
	}

	c, err := corpus.Load(*corpusPath)
	if err != nil {
		return err
	}
	a, err := sink.Open(*aPath)
	if err != nil {
		return err
	}
	defer a.Close()
	b, err := sink.Open(*bPath)
	if err != nil {
		return err
	}
	defer b.Close()

	changes := report.Diff(c, a, b)
	fmt.Printf("%d domains changed classification\n\n", len(changes))
	for _, ch := range changes {
		fmt.Printf("  %-40s %s -> %s", ch.Domain, ch.From.Canonical, ch.To.Canonical)
		if ch.From.WWWSupported() != ch.To.WWWSupported() {
			if ch.To.WWWSupported() {
				fmt.Printf("   [www fixed]")
			} else {
				fmt.Printf("   [www broke]")
			}
		}
		fmt.Println()
	}
	return nil
}

// ordinalSuffix is only for the human-readable note in run metadata.
func ordinalSuffix(n int) string {
	if n%100 >= 11 && n%100 <= 13 {
		return "th"
	}
	switch n % 10 {
	case 1:
		return "st"
	case 2:
		return "nd"
	case 3:
		return "rd"
	}
	return "th"
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func dirOf(path string) string {
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
