# Scanner Restructure: Isolate DNS Existence from HTTP Liveness

> Status: design note / blueprint. Written away from the code, so this is
> architecture-level, not file-level. When the real scanner is pushed, map
> these stages onto the existing modules and fill in the file references.

## The problem, stated plainly

The current scanner does **~110 checks/second**. That is roughly **9 ms per
item**, which is the signature of paying one network round-trip *per item, more
or less serialized*. For comparison, [massDNS](https://github.com/blechschmidt/massdns)
sustains ~360k queries/second.

The ~3000x gap is not a tuning problem. It is a **structural** one: the scanner
answers several different questions in a single pass, so:

1. The cheap question (does a DNS record exist?) is bottlenecked by the
   expensive one (does an HTTP server answer 200/301?).
2. There is no way to see which stage is actually slow, because throughput is
   reported for the combined pass, not per question.

The fix is not "make it faster." The fix is **isolate the variables**: split
the questions into separate stages, each answering exactly one thing, each
measured on its own.

## The questions are not the same question

| Question | Transport | Cost | Depends on |
| --- | --- | --- | --- |
| Does `www.x.com` have an **A** record? | UDP (DNS) | ~1 packet each way | resolver reachability |
| Does `www.x.com` have an **AAAA** record? | UDP (DNS) | ~1 packet each way | resolver reachability |
| Does the host **answer HTTP** (200/301/…)? | TCP + (TLS) + HTTP | full connection setup + handshake + request | A/AAAA existing first |
| Is the **TLS cert** valid? | TCP + TLS | handshake | host answering first |

DNS existence is a **UDP** question. You do **not** need TCP, TLS, or a 200
response to answer it. Answering it should never wait on a TCP connect or a TLS
handshake. Today it apparently does — that is the whole slowdown.

## Why massDNS is fast (and why the current path isn't)

massDNS gets its throughput from four things, none of which are exotic:

1. **Raw/async UDP sockets** — not the OS stub resolver (`getaddrinfo` /
   system resolver). The stub resolver blocks, consults `/etc/hosts` and
   nsswitch, and serializes; it is the single most common cause of slow DNS
   scans.
2. **Thousands of queries in flight at once** — an event loop (epoll/kqueue),
   *not* thread-per-query. It fires a query and moves on; replies are matched
   up later by transaction ID. Throughput is bounded by packets-per-second,
   **not** by per-query latency.
3. **A pool of resolvers**, so no single upstream rate-limits you.
4. **Zero TCP/TLS/HTTP.** It only asks the DNS question.

If any of these is missing — especially #1 and #2, or if an HTTP check is
riding along on every item — you collapse back toward one-round-trip-per-item,
which is exactly ~110/sec territory.

## Target architecture: a narrowing pipeline

Model the scan as stages, each consuming the survivors of the previous one:

```
input names (www.a.com, www.b.com, ...)
        │
        ▼
┌─────────────────────────────┐
│ Stage 1: DNS existence      │  UDP, async, thousands in flight
│  - A?    (separate query)   │  target: tens of thousands/sec+
│  - AAAA? (separate query)   │  output: names that resolve
└─────────────────────────────┘
        │  (only resolvers survive)
        ▼
┌─────────────────────────────┐
│ Stage 2: HTTP liveness      │  TCP + TLS + HTTP
│  - 200 / 301 / status       │  inherently slow (RTT-bound)
│  - cert validity (optional) │  but tiny candidate set now
└─────────────────────────────┘
        │
        ▼
     results
```

Key properties:

- **Each stage answers ONE question.** A and AAAA are two separate cheap UDP
  queries in Stage 1 — fine, still cheap. HTTP status and cert are Stage 2.
- **Stages are independently measured.** Each stage reports its own throughput
  and its own funnel count. The output should read like:
  `Stage 1 (DNS): 52,000/s, 8,300/220,000 resolve → Stage 2 (HTTP): 140/s, 4,100/8,300 answer 200`.
  The moment you can see that, you know *exactly* where the time goes — which
  is the thing you can't see today.
- **Stage 2's slowness is acceptable** because it only runs on Stage-1
  survivors, which is a small fraction of the input. Slow-per-item is fine when
  the item count is small.

## What "isolate variables" buys you concretely

Right now you literally cannot answer "is my DNS fast or is my HTTP slow?"
because they're fused. After the split, the failure modes separate:

- If **Stage 1** is slow → it's the resolver path (stub resolver? no
  concurrency? single upstream?). Fixable to massDNS-class numbers.
- If **Stage 2** is slow → that's expected and bounded by connection RTT and
  concurrency; you tune worker count, timeouts, and connection reuse, and you
  accept it's never going to be 360k/sec because TLS handshakes aren't free.

You suspected the DNS part might already be fast and just buried in unclear
output. The per-stage instrumentation is what proves it either way.

## Stage 1 implementation checklist (when back at the code)

- [ ] Confirm the current path. Is it `getaddrinfo`/system resolver, an async
      DNS library, or raw UDP? (This alone likely explains 110/sec.)
- [ ] Stop using the blocking stub resolver for the existence check. Use an
      async DNS resolver or send UDP queries directly to resolver IPs.
- [ ] Fire queries concurrently with a large in-flight budget (thousands), not
      thread-per-query. Match replies by transaction ID.
- [ ] Use a **pool of resolvers**; rotate to avoid per-resolver rate limits.
- [ ] Keep A and AAAA as separate queries; record which (or both) exist.
- [ ] Handle the DNS realities: timeouts + retries (UDP drops packets),
      truncated (TC=1) responses, NXDOMAIN vs NOERROR-no-answer, SERVFAIL.
- [ ] Emit Stage-1-only throughput and a funnel count. No HTTP anywhere in this
      path.

## Stage 2 implementation checklist

- [ ] Consume only Stage-1 survivors (names with A and/or AAAA).
- [ ] Separate transport concerns: TCP connect, TLS handshake, HTTP request are
      distinct and separately timeable.
- [ ] Bounded worker pool; per-attempt timeout; reuse connections where sane.
- [ ] Record status (200/301/…), and optionally cert validity, as separate
      fields — not folded into one boolean.
- [ ] Emit Stage-2-only throughput and its own funnel count.

## Measurement is the deliverable

Before optimizing anything, make the output show **per-stage rate and per-stage
funnel**. That is the single change that turns "it feels slow" into "Stage N is
slow for reason R." Optimize only what the numbers point at.

## Open questions to resolve against the real code

- What does a single "check" currently do end to end? (Confirms whether HTTP is
  riding on every item.)
- Which resolver path is in use today?
- What is the concurrency model — worker count, thread-per-item, async?
- Where does the input list of names come from, and how large is it?
