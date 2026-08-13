# The No-Limiter Ceiling: Finding Your First Real Bottleneck

The idea: run your own DNS responder so **nothing throttles you**. No upstream
rate limit, no recursion, no cache — just a box that answers every query
instantly. Point your tools/scanner at it and the number you get is *your*
ceiling. The question this answers is exactly: **once nobody is rate-limiting
me, what breaks first?**

The sink lives in [`benchmarks/dns-sink/`](../benchmarks/dns-sink/):
- `main.go` — a tiny Go responder, one listener per core (SO_REUSEPORT), zero
  deps. Answers every A with `192.0.2.1`, every AAAA with `2001:db8::1`. It
  prints its own answered-q/s so you can see if *it* is the limit.
- `Corefile` — a zero-code CoreDNS alternative (needs CoreDNS installed).

Both were built and smoke-tested (valid answers for A, AAAA, and arbitrary
names).

## First, the framing fix: PPS, not bandwidth

DNS query+response is ~50–80 bytes. At 360k q/s that's ~29 MB/s ≈ 230 Mbps —
trivial. You will **not** run out of bandwidth. What you run out of is
**packets per second**: the rate the kernel, NIC, and CPU can push small UDP
datagrams. "We have tons of bandwidth" is true and beside the point; the sink
exists to find the PPS wall.

## Run it in three topologies to attribute the loss

Same tool, same input, three places for the sink. The deltas localize the
bottleneck:

| # | Sink runs on | Tool talks to | Removes | Adds |
| --- | --- | --- | --- | --- |
| A | the laptop itself | `127.0.0.1` | the entire network | nothing — pure code + kernel |
| B | the home box | its LAN IP | internet, rate limits | one gigabit LAN hop |
| C | a VPS (Hostinger) | its public IP | rate limits only | real internet RTT |

**Topology A is the important one.** If your scanner still does ~110/sec
answering off loopback — where a round trip is microseconds and there is no
network to blame — then the bottleneck is unambiguously *in your code*. No
amount of network or resolver tuning will help; the Stage-1 rewrite
(`dns-query-performance.md`) is the only lever. Run the bulk tools (massdns,
dnsx) in topology A too, as the reference: they'll show what the same hardware
does when the code isn't the limit.

## How to run

```bash
# On the sink box:
cd benchmarks/dns-sink && go build -o dns-sink .
sudo ./dns-sink -addr :53          # or -addr :5353 to avoid needing root

# On the tool box, point every tool's resolver at the sink's IP.
# Reuse the benchmark harness — it already takes --resolvers:
echo <SINK_IP> > sink-resolver.txt
../dns-bench.sh --input names.txt --resolvers sink-resolver.txt --conc 20000

# Watch the sink's own printed "answered N q/s". If that's far above the tool's
# rate, the sink isn't the bottleneck — the tool or the path is.
```

Note: the loopback/LAN/VPS resolver only applies to tools that take an explicit
resolver target (massdns, dnsx, zdns, and your scanner). The `getent`/`dig`
stub baselines follow the system resolver, so for those you'd set the sink as
the system nameserver — usually not worth it; use them only for the
stub-path comparison in the earlier benchmark.

## The bottleneck ladder — what breaks first, in order

Once the rate limiter is gone, you'll hit these roughly in this sequence.
Each one has a tell and a fix:

1. **Your code's send model.** Serial or thread-per-query resolution caps at
   ~1/RTT per worker. *Tell:* topology A (loopback) is slow despite microsecond
   RTT. *Fix:* async, thousands of queries in flight (the Stage-1 rewrite).
2. **Single UDP socket / single core.** One socket's send/recv is CPU-bound on
   one core's softirq processing. *Tell:* one core pegged, others idle; adding
   concurrency stops helping. *Fix:* multiple sockets with SO_REUSEPORT, or
   `sendmmsg`/`recvmmsg` batching (this is why the sink uses per-core
   listeners).
3. **File descriptors / ephemeral ports.** Thousands in flight exhaust the fd
   limit or the ephemeral port range. *Tell:* errors at a concurrency
   threshold. *Fix:* `ulimit -n`, widen `net.ipv4.ip_local_port_range`.
4. **conntrack (if any stateful firewall/NAT is in the path).** UDP flows get
   tracked; the table fills and new packets drop. *Tell:* high send rate, replies
   vanish, `dmesg` shows "nf_conntrack: table full". *Fix:* raise
   `nf_conntrack_max`, or a `NOTRACK` rule for the test traffic, or a path with
   no NAT (loopback/LAN avoid it).
5. **NIC / driver PPS + softirq.** The raw small-packet rate of the hardware and
   its interrupt handling. *Tell:* topology B/C plateau with CPU spent in
   softirq. *Fix:* RSS/multiqueue, more cores, or accept it as the hardware
   ceiling.

You climb this ladder rung by rung: fix rung 1, you hit rung 2, and so on. The
sink lets you see each rung clearly because it never adds a rung of its own.

## Important caveat: this is the ceiling, not the field

A sink that answers instantly is the *best case*. Real scanning hits thousands
of real authoritative servers with varied RTT, some slow, some that genuinely
rate-limit you. So production throughput will sit **below** the sink number.
That's fine — the sink's job is to separate "my stack can't go faster" from
"the internet won't let me go faster." If the sink says 200k/s and real scans
do 5k/s, the limit is the field, not your code. If the sink says 110/s, the
limit was never the field at all.
