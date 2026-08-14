# www-scanner

Does `www` still work?

`www` was never part of the protocol. It's an ordinary hostname that got famous
— the box running the HTTP daemon, back when you named machines after their
jobs. It outlived that convention because [you can't put a CNAME at a zone
apex](https://datatracker.ietf.org/doc/html/rfc1034#section-3.6.2), so for years
pointing `www` at a CDN was one line and pointing the bare domain at one was a
research project. Once ALIAS records and CNAME flattening fixed the apex, the
ordering flipped and `www` became the afterthought.

This measures how far that has gone.

**The target is every currently registered domain** — roughly 360 million across
all TLDs. ICANN CZDS zone files are the intended corpus, because a TLD zone
contains exactly the *delegated* names: a domain that lapsed drops out at the
next daily refresh, so an expired registration never gets counted as "someone
who broke `www`". Those two failures are indistinguishable by DNS alone and
conflating them would corrupt the measurement.

Tranco's top million is the **test harness**, not the target. It is small,
citable and permanently archived, which makes it the right thing to develop the
classifier against and to eyeball specific names in.

It exists because I found `www` broken on all four of my own domains —
`ERR_NAME_NOT_RESOLVED`, no record at all — and four data points can't tell
"the convention is dead" apart from "I shipped four broken sites."

Background: [Does www Still Work?](https://thomasrones.com/does-www-still-work)

## Quickstart

```sh
go build -o wwwscan ./cmd/wwwscan

# One domain, human-readable. No corpus needed.
./wwwscan probe github.com

# Freeze a corpus, sample it, read the numbers.
./wwwscan corpus -out corpora/tranco.txt
./wwwscan scan   -corpus corpora/tranco.txt -out results/run1.bin -sample 20000 -workers 200
./wwwscan report -corpus corpora/tranco.txt -results results/run1.bin

# Time-boxed throughput sweep — a row per configuration as it lands.
./wwwscan bench  -workers 200,1000 -duration 15s
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
150k random sample, **26,085 zones — 20% of those whose `www` resolves — are
wildcards.**

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
ID so the denominator is re-downloadable. Every scan also writes a
`.meta.json` beside its results recording the sample seed, every timeout, and
the validity achieved — and `report` refuses to pair results with a corpus they
were not written against, because two Tranco lists from different days are both
exactly a million entries:

```json
{
  "source": "tranco",
  "source_url": "https://tranco-list.eu/download/26J79/1000000",
  "list_id": "26J79",
  "count": 1000000,
  "sha256": "33243560e98e15e05462f2b1fdf2dd57779977273838095454fecd104f0baf5b"
}
```

## First results

Run 1: **150,000-domain uniform random sample** of Tranco list `26J79`,
2026-08-13, seed `20260813`. Full write-up and provenance in
[RUNS.md](RUNS.md).

```
HEADLINE
  probed                     150000  domains that produced a result
  apex serves a site         102569  68.38% of those

  ...www never measured         682  probe stalled — excluded from the ratio below

  of the 101887 measured:
    www works                 92798  91.08% +/- 0.17 pts (95% CI)   <- THE ANSWER
    www broken                 9089   8.92%

HOW www BREAKS (on domains whose apex serves)
  no dns record at all (nxdomain)        3660  37.46%
  cert has no SAN for www                1840  18.83%
  name exists, no address record          732   7.49%
  tls error                               728   7.45%
  serves, returns 403                     644   6.59%
  resolves, connection hangs              489   5.00%
  serves, returns 404                     444   4.54%
  cert expired                            229   2.34%

CANONICAL DIRECTION
  www->apex                             40818  27.21%
  both-fail                             36411  24.27%
  apex->www                             30796  20.53%
  both-serve-no-canonical               28635  19.09%
  apex-only                              8476   5.65%
  www-only                               4864   3.24%
```

**Over half of all breakage is a record nobody created** — 37.5% NXDOMAIN plus
7.5% NODATA. Not a misconfiguration, an absence. The second cause is subtler:
18.8% added the DNS record and never reissued the certificate to cover the name,
so the connection opens and the handshake is refused.

**The denominator is the other finding.** Only 68% of the corpus serves a
homepage at all; the rest is CDN, API and DNS infrastructure that was never a
website and has no opinion about `www`. Measured against everything, the number
is 65.4%. Measured against actual websites that were successfully measured, 91.1%.
Same data, twenty-six points
apart, and only one of them answers the question that was asked.

Sample, not head-of-list: `-sample` draws uniformly across the corpus, which is
the difference between an estimate and a ceiling. The first 5,000 Tranco entries
are Google and Cloudflare, whose ops teams do not forget to configure `www` —
they scored 89.97% under the old accounting, so the popularity bias turned out to be
about half a point.

Three caveats for any write-up:

- **Even the full million is a biased sample of the web**, and it is not the
  target population. These are domains someone visits. The registered tail is
  almost certainly worse.
- **Negative caching biases the number down, never up.** An NXDOMAIN may be a
  cached negative from before someone fixed it, and SOA minimums are routinely
  24h. Querying authoritative nameservers on the final pass would remove it.
- **Validity was 93.0%**, below the 95% census floor, so the scanner declined to
  certify its own run. Re-probing 3,000 stalled domains at 25 workers found ~85%
  still stall, i.e. genuinely unreachable hosts rather than scanner congestion;
  corrected validity is ~99%. See [The Stall Ladder](https://claude.ai/code/artifact/874537f7-fda1-4d5e-98a7-0f12451cdcac).

So: I shipped four broken sites, and roughly one site in ten is in the same
state. Both stories were true.

## Throughput: what actually gave out

Two ceilings matter, and they are nowhere near each other.

**With the network removed**, the resolver does **138,000 DNS queries/sec**
against a synthetic authoritative server on loopback
(`go test ./internal/resolve/ -bench Ceiling`):

| pooled sockets | lookups/s | queries/s |
|--:|--:|--:|
| 1 | 47,664 | 95,327 |
| 4 | 66,380 | 132,760 |
| 16 | **69,186** | **138,372** |

**In the field**, the full census ladder does about **110 domains/sec**, which
is roughly 550 queries/sec — a 250x gap, none of it in the code. Measured on a
150k sample and a null-sink sweep:

| workers | resolver | eff/s | validity | bound by |
|--:|---|--:|--:|---|
| 200 | systemd stub | 85.5 | — | the stub |
| 200 | 6 public | 109.6 | 95.4% | new connections/sec |
| 1,000 | 6 public | 109.3 | 79.3% | same ceiling, more failure |
| 10,000 | 6 public | ~130 | 9.8% | same ceiling, mostly failure |

Everything local was idle throughout: one core of sixteen, ~90 MB of RAM, 7 Mbps
of a home connection, conntrack at 39% of its ceiling, file descriptors at 6%.

What did give out, in order of discovery:

- **Ephemeral ports, at 10,000 workers.** One UDP socket per query held 28,236
  local ports against a range of 28,232. The design notes had ruled this out
  because destinations vary — true for HTTP, whose TCP sockets peaked at a
  harmless 2,312, and false for DNS, where three upstreams share the whole port
  space. Pooling took it to 42 ports and did not make anything faster, because
  it was never the binding constraint at usable concurrency.
- **The tail-latency hypothesis was wrong.** Cutting the HTTP timeout from 10s
  to 3s changed throughput and mean latency by less than 1%. It only converted
  slow successes into failures.
- **Provider egress limits**, which nobody predicted. A Hostinger VPS managed
  15 effective domains/sec: healthy at 20 workers (93.2% validity), collapsing
  to 39.7% at 200, with `tcp=377 servfail=1` — connections dropped, DNS fine.
  That is roughly 30 new outbound connections per second, enforced silently by
  discarding SYNs, and it exists because a `www` census looks exactly like a
  port scan.

**Raw domains/sec is a trap.** A timed-out probe is cheaper than a completed
one, so pushing concurrency makes the headline number rise while the data
evaporates: 10,000 workers reached ~860 raw/s at 15% validity. Every rate quoted
here is `eff/s` — conclusively classified domains per second — and a run below
95% validity is refused as a census.

The conclusion the numbers force: **the scarce resource is not bandwidth, CPU or
sockets. It is permission** — how many new connections per second the network
path will allow. That is a procurement question for the HTTPS half. The DNS
half, where the client is already at 138k qps, is not constrained by anything we
have measured yet.

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
