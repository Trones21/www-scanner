# DNS Tool Benchmark: Establishing a Baseline on Your Hardware

Goal: stop guessing. Run several DNS tools on the *same* machine, against the
*same* input and resolvers, and get real queries/sec numbers. Then the ~110/sec
vs ~360k/sec gap becomes a measured thing we can attribute to specific causes,
not a mystery.

Run it with [`benchmarks/dns-bench.sh`](../benchmarks/dns-bench.sh).

## The tools, grouped by what class they represent

The benchmark deliberately includes slow baselines, because the *shape* of the
gap between classes is the whole point.

| Tool | Class | What it proves |
| --- | --- | --- |
| `getent hosts` (serial) | stub resolver, serialized | reproduces the naive `getaddrinfo` path — expect ~100/sec territory |
| `dig` + `xargs -P100` | stub resolver, N-way parallel | isolates how much of the gap is *just concurrency* vs the resolver path |
| `massdns` | async UDP, bulk | the reference fast path — thousands in flight, raw UDP |
| `dnsx` (projectdiscovery) | async UDP, bulk | Go-based bulk resolver, easy flags |
| `zdns` (zmap) | async UDP, bulk | another bulk resolver for cross-check |

If `getent-serial` lands near your scanner's 110/sec, that's strong evidence
your scanner is on the stub-resolver path. If `dig-xargs-100` jumps to a few
thousand/sec but massdns is far higher, the remaining gap is the resolver path
itself (stub vs raw UDP), not concurrency.

## The fairness rules (why the script is fussy)

A benchmark that isn't controlled tells you nothing. The script holds these
constant across every tool:

1. **Same input list.** One file of names, reused everywhere.
2. **Same resolver set.** Otherwise you're comparing upstreams, not tools. All
   tools point at the same resolver(s).
3. **Same record type** (A, then rerun with `--type AAAA`).
4. **Success rate is measured, not just speed.** This is the one people skip.
   A tool reporting 300k/sec while silently dropping 90% of answers is doing
   30k useful/sec. The script reports `qps` **and** `success_pct`; read them
   together.

## The gotchas that will wreck your numbers

- **Caching.** If your input has repeats or you rerun against a warm recursive
  resolver, you're benchmarking the cache, not resolution. Use a large, diverse
  name list (e.g. Tranco/Majestic top-1M prefixed with `www.`). Cold cache =
  honest numbers.
- **Public resolvers rate-limit.** 1.1.1.1/8.8.8.8 will throttle you hard past
  a few thousand q/s — you'll see high qps collapse into low success_pct. For a
  true max-throughput baseline, run a **local recursive resolver** (unbound) and
  point every tool at `127.0.0.1`. massdns's headline numbers assume a big pool
  of resolvers you're allowed to hammer.
- **OS limits.** File-descriptor ceiling (`ulimit -n`), ephemeral port
  exhaustion, and conntrack table size all cap concurrency. The script raises
  `ulimit -n`; if you're behind a stateful firewall/NAT, conntrack may be the
  real ceiling (`net.netfilter.nf_conntrack_max`).
- **Loopback vs network.** A local unbound removes network RTT from the tool
  comparison; a remote resolver adds it uniformly. Pick one and be consistent.

## How to run

```bash
# 1. Get a big, diverse name list (defeats caching). Example: Tranco.
#    Prefix hosts with www. if that's what you're scanning.
#    -> names.txt   (one name per line)

# 2. (Recommended) run a local resolver for max-throughput numbers:
#    sudo apt install unbound && sudo systemctl start unbound
#    echo 127.0.0.1 > resolvers.txt
#    Otherwise the script falls back to a public set (will rate-limit).

# 3. Run it.
./benchmarks/dns-bench.sh --input names.txt --resolvers resolvers.txt \
    --type A --conc 10000 --count 100000

# 4. Rerun for AAAA to compare record types.
./benchmarks/dns-bench.sh --input names.txt --resolvers resolvers.txt --type AAAA
```

Results print as a table and land in `bench-out/results.tsv`.

## Why the numbers differ — hypotheses to confirm with the data

Rank these against what the table actually shows:

1. **Stub resolver vs raw UDP.** `getaddrinfo`/`getent`/`dig` default go through
   the system stub resolver: blocking, one query at a time per call, plus
   nsswitch/`/etc/hosts` lookups. Bulk tools speak UDP straight to resolvers.
   This is usually the biggest single factor.
2. **Concurrency model.** Serial vs thread-per-query vs event-loop
   (epoll, thousands in flight). Bulk tools decouple throughput from per-query
   latency; serial tools are latency-bound at ~1/RTT.
3. **Extra work per item.** If the scanner does TCP/TLS/HTTP per name, it can't
   be compared to a pure-DNS tool at all — different question, different cost.
   (This is the split covered in `dns-query-performance.md`.)
4. **Resolver choice & caching.** Warm local cache vs cold public resolver can
   swing results by orders of magnitude.
5. **Retry/timeout policy.** Aggressive retries inflate load; short timeouts
   drop slow-but-valid answers (lowers success_pct).
6. **Apparent vs real throughput.** Rate limiting and UDP packet loss show up as
   high qps + low success_pct. Always read both columns.
7. **Host limits.** fd ceiling, ephemeral ports, conntrack, CPU — cap the async
   tools well below their theoretical max.

## What we do with the baseline

Once we have the table, the scanner's 110/sec sits in context:

- If a bulk tool hits tens of thousands/sec at high success on your exact
  hardware and network, the ceiling is real and the scanner is leaving ~1000x on
  the table — worth the Stage-1 rewrite (see `dns-query-performance.md`).
- If even massdns is capped low on your network (rate limits, conntrack), then
  the fix is infrastructure (local unbound, resolver pool), not scanner code —
  and we'd have proven that *before* rewriting anything.
