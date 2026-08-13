# www-scanner

Does `www` still work?

`www` was never part of the protocol. It's an ordinary hostname that got famous
— the box running the HTTP daemon, back when you named machines after their
jobs. It outlived that convention because [you can't put a CNAME at a zone
apex](https://datatracker.ietf.org/doc/html/rfc1034#section-3.6.2), so for years
pointing `www` at a CDN was one line and pointing the bare domain at one was a
research project. Once ALIAS records and CNAME flattening fixed the apex, the
ordering flipped and `www` became the afterthought.

This measures how far that has gone, across a corpus of real domains.

It exists because I found `www` broken on all four of my own domains —
`ERR_NAME_NOT_RESOLVED`, no record at all — and four data points can't tell
"the convention is dead" apart from "I shipped four broken sites."

Background: [Does www Still Work?](https://thomasrones.com/does-www-still-work)

## Quickstart

```sh
go build -o wwwscan ./cmd/wwwscan

# One domain, human-readable. No corpus needed.
./wwwscan probe github.com

# Freeze a corpus, scan a slice of it, read the numbers.
./wwwscan corpus -out corpora/tranco.txt
./wwwscan scan   -corpus corpora/tranco.txt -out results/run1.bin -limit 5000 -workers 200
./wwwscan report -corpus corpora/tranco.txt -results results/run1.bin
```

`probe` is the fastest way to see what the classifier does:

```
$ ./wwwscan probe github.com
github.com  (1.2s)
  name            dns      rr           tcp         tls               http  terminal  hops
  github.com      ok       A            ok          ok                200   self      0
  www.github.com  ok       A+CNAME      ok          ok                200   apex      1
  canonical: www->apex
  wildcard:  no
  verdict:   www works
```

## What it measures

The naive version is one boolean: does `www.<domain>` resolve. That boolean is
wrong in both directions, and most of the design follows from fixing it.

**Wrong on the false-positive side.** A wildcard record makes `www` resolve, and
`asdfjkl` resolve, and every other label resolve, without any of them serving
anything. So the scanner separates NXDOMAIN from NOERROR-with-no-answers, and
when `www` resolves it fires one query at a random 15-character label. If that
resolves too, `www` resolving is not evidence anyone configured `www`. In the
Tranco top 5k, **~15% of domains whose `www` resolves are wildcard zones.**

**Wrong on the false-negative side.** There's a ladder of ways to resolve and
still be broken, and they're different mistakes by different people:

| rung | what broke |
|---|---|
| DNS | NXDOMAIN, or NOERROR with no address record |
| TCP | resolves, nothing listening / connection hangs |
| TLS | handshake fails — **cert has no SAN for `www`** is its own class |
| HTTP | 404 because the vhost only knows the apex |

Flattening those to "no" throws away the finding, so each is recorded
separately.

**And the direction question**, which is the culturally interesting one. For
domains where both names work: does `www` 301 to the apex, does the apex 301 to
`www`, or do both serve 200 with no canonical form at all?

**No browser anywhere in the pipeline.** The omnibox does its own fixups and
will add or strip `www` on your behalf. The HSTS preload list rewrites the
request before DNS is consulted. One Enter keypress emits a pile of speculative
rows. All of that obscures the thing being measured. This uses a raw resolver
([miekg/dns](https://github.com/miekg/dns), so rcodes survive instead of being
flattened into an error) and a raw HTTP client that reports redirects instead of
following them and describes a timeout as a timeout.

## The two goals are separate runs

They share a core and nothing else, and conflating them is the main trap.

**Census** — a complete, correct record of `www` state. Correctness matters;
speed is secondary. Full per-domain records land on disk.

**Throughput** — how many domains/sec, and what gives out first. Runs with
`-null-sink` so the storage path can't contaminate the measurement.

Because they never run at the same time, storage design serves the census and
owes the benchmark nothing. There is no completeness-vs-speed tradeoff to make.
The runs below turned out to be an argument for keeping them separate that's
stronger than the theoretical one.

## Storage

Results are **fixed-width records written positionally**: the Nth record belongs
to the Nth corpus entry, so the domain string is never stored. 24 bytes per
domain, enums and small ints only — ~24 GB at a billion domains, no text, no
index.

Three consequences worth having:

- **No write coordination.** Each worker writes at `i * 24` into one mmap'd
  file. Disjoint offsets, no lock, no writer goroutine, no result channel — a
  single collector goroutine is exactly the kind of accidental serialization
  that shows up later as workers sitting idle.
- **Resumption is the zero value.** `StatusUnattempted` is 0, so a freshly
  allocated file is its own checkpoint. Interrupt a run, rerun the same command,
  it picks up where it stopped. There's nothing separate to keep consistent.
- **Run diffs are a merge join.** Two (corpus, results) pairs streamed in
  lockstep emit deltas — `wwwscan diff`. That's how the census becomes a trend
  series without querying a billion rows.

The corpus itself is frozen and checksummed. Positional records are meaningless
against a different corpus, so the sink refuses to open a result file whose
length disagrees with the corpus, and the manifest records the exact Tranco list
ID so the denominator is re-downloadable:

```json
{
  "source": "tranco",
  "source_url": "https://tranco-list.eu/download/GQP4K/1000000",
  "list_id": "GQP4K",
  "count": 1000000,
  "sha256": "8ab1f621118f3f704465a11b51769cfc584f261f300d8ca427aad5733ec56eb8"
}
```

## First results

Tranco list `GQP4K`, top 5,000, 2026-08-08. A slice, not the headline number.

```
HEADLINE
  apex serves a site           3032  60.64% of corpus
  ...of those, www works       2728  89.97%   <- the number the question is asking
  ...of those, www broken       304  10.03%

HOW www BREAKS (on domains whose apex serves)
  no dns record at all (nxdomain)         102  33.55%
  resolves, connection hangs               65  21.38%
  tcp error                                26   8.55%
  serves, returns 404                      24   7.89%
  serves, returns 403                      23   7.57%
  cert has no SAN for www                  22   7.24%
  name exists, no address record           21   6.91%

CANONICAL DIRECTION
  both-fail                  1651  33.02%
  apex->www                  1285  25.70%
  www->apex                  1225  24.50%
  both-serve-no-canonical     321   6.42%
  apex-only                   308   6.16%
  www-only                    210   4.20%
```

**The denominator is the finding here.** Only 61% of the Tranco top 5k serve a
homepage at the apex at all. The rest is infrastructure — `gtld-servers.net`,
`akamaiedge.net`, `apple-dns.net`, `googleapis.com` — which ranks highly because
Tranco is built partly from DNS query volume, and which has no opinion about
`www`. Measuring against the whole corpus gives 58.72%; measuring against
domains that are actually websites gives 89.97%. Same data, thirty-one points
apart, and the second one is the answer to the question that was asked.

Two caveats to carry into any write-up:

- **The top million is a biased sample.** These are the domains most likely to
  have someone competent running DNS. 90% is closer to an upper bound than an
  average — if even this population is at 10% broken, the tail is worse.
- **Negative caching biases the number down, never up.** An NXDOMAIN answer may
  be a cached negative from before someone fixed it, and SOA minimums are
  routinely 24h. A domain that added `www` this morning still reads NXDOMAIN
  through a caching resolver until tomorrow.

So: I shipped four broken sites, and roughly one site in ten is in the same
state. Both stories were true.

## Throughput: what actually gave out

Same 5,000 domains, `-null-sink`, from a laptop on a domestic connection.

| workers | resolver | timeout | domains/sec | mean | in-flight (Little's N) |
|--:|---|--:|--:|--:|--:|
| 200 | systemd stub | 10s | 85.5 | 1.92s | 165 / 200 |
| 200 | 1.1.1.1 + 8.8.8.8 + 9.9.9.9 | 10s | 99.8 | 1.77s | 177 / 200 |
| 200 | public | **3s** | 100.3 | 1.78s | 179 / 200 |
| 1000 | public | 10s | 139.2 | 5.63s | 784 / 1000 |

Little's Law holds to the digit throughout — `784 / 5.632s = 139`. Which makes
the table readable as a diagnosis rather than a list of numbers:

**Moving off the systemd-resolved stub bought 17%**, not the order of magnitude
the notes half-expected. The stub was a real constraint and a small one.

**Cutting the timeout from 10s to 3s bought nothing at all** — throughput and
mean latency both unchanged to within noise. That kills the tail-latency
hypothesis for this workload at this concurrency: if the mean were dominated by
probes parked on the timeout ceiling, moving the ceiling would have moved the
mean. It didn't. The mean is the bulk of the distribution, not its tail. All the
shorter timeout did was turn slow successes into failures.

**5× the workers bought 1.4× the throughput and tripled the mean.** Sublinear
throughput with superlinear latency is a shared resource saturating, and it
isn't any of the local suspects: fds are capped at 524288, conntrack peaked at
54825 of 262144 (21%), and CPU sat near one core of sixteen. The remaining
candidates are all off-box — the household NAT, the uplink, or per-source rate
limiting at the resolvers — and telling them apart needs a run from a different
vantage point rather than more instrumentation on this one.

**The part that matters most is that the 1000-worker run produced different
answers.** Successful TLS handshakes fell from 3408 to 2660 against the same
corpus; `www-only` went from 229 to 575. The scan wasn't just slower per unit of
work, it was wrong — congestion turned real sites into timeouts, and every one
of those would have been recorded as a broken `www`.

That's the census/throughput split earning its keep. A run tuned for speed
silently manufactures failures, and the failure it manufactures is exactly the
thing being measured. Census runs stay at concurrency the network can actually
sustain; the benchmark can push until it breaks, because nobody reads its output.

## Ground truth

A classifier for the open web has no test set, but I own four domains and
control their DNS, so each can be parked in a known state:

| domain | fixture state | classifier |
|---|---|---|
| `csv-helper.com` | both serve 200, no canonical tag | `both-serve-no-canonical` ✓ |
| `thomasrones.com` | both serve 200 | `both-serve-no-canonical` ✓ |
| `apresapply.com` | both serve 200 | `both-serve-no-canonical` ✓ |
| `fxf.social` | both serve 200 | `both-serve-no-canonical` ✓ |

`both-serve-no-canonical` is the least obvious branch to get right, because
nothing is failing. Public domains cover the others for now — `github.com` is
`www->apex`, `nytimes.com` and `wikipedia.org` are `apex->www`, `go.dev` has no
`www` at all, `t.co` resolves `www` and fails TLS on it.

Still wanted as owned fixtures: `www`→apex 301, apex→`www` 301, `www` NXDOMAIN,
a cert with no SAN for the name presented, and a wildcard zone. One caveat that
follows from negative caching: flipping a fixture and immediately re-running
tests the resolver's cache, not the fixture. Verify against authoritative
nameservers, or give the test zone a short SOA minimum.

## Commands

```
wwwscan corpus  -out corpora/tranco.txt [-date YYYY-MM-DD] [-limit N] [-from file]
wwwscan probe   <domain>... [-resolver 1.1.1.1,8.8.8.8]
wwwscan scan    -corpus <f> {-out <f> | -null-sink} [-workers N] [-limit N]
                [-resume] [-timeout 10s] [-connect-timeout 5s] [-histogram]
                [-resolver ...] [-no-wildcard-check] [-no-http-fallback]
wwwscan report  -corpus <f> -results <f> [-csv out.csv] [-only broken|supported|wildcard|<class>]
wwwscan diff    -corpus <f> -a <before.bin> -b <after.bin>
```

`report -only broken` is the useful one for reading individual cases: domains
whose apex serves and whose `www` doesn't.

## Layout

```
cmd/wwwscan/      CLI
internal/record/  24-byte positional record, enums, encode/decode
internal/corpus/  frozen checksummed domain lists; Tranco fetch
internal/resolve/ raw DNS over miekg/dns — rcodes, not errors
internal/probe/   the ladder, per domain, both names concurrently
internal/sink/    mmap and null sinks behind one interface
internal/scan/    worker pool
internal/metrics/ in-flight gauge + latency histogram (Little's Law)
internal/report/  aggregates, CSV export, run diffs
```

## Open

- **Corpus at real scale.** CZDS zone files are the answer for whole-internet
  coverage (`.com` is ~160M delegated names) but need per-TLD application and
  approval. Certificate Transparency logs answer part of the question with zero
  DNS queries — a SAN list covering `www.example.com` is direct evidence someone
  provisioned it — with a bias that's at least legible.
- **Streaming the corpus.** It's held in memory today, which is fine to a few
  hundred million and wrong at a billion. Nothing else in the pipeline needs to
  change.
- **Authoritative queries for the final classification pass**, to remove the
  negative-caching bias, at the cost of walking the delegation chain per domain.
- **Where the off-box wall actually is.** Needs a run from somewhere that isn't
  a domestic uplink.
- **Keeping the trend honest.** Dead entries need `last_seen_alive` and a
  consecutive-failure count, pruned only after N strikes, with prunes recorded
  so the denominator stays reconstructible. Prune eagerly and run 2 measures a
  different population — the trend line becomes survivorship. Cheap now,
  expensive to retrofit once run 1 exists.
- **SQLite sidecar** for aggregates, run metadata, and a reservoir sample of
  interesting failures. The blob answers how many; that answers which ones.
