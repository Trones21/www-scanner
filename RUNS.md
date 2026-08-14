# Runs

An index of every scan worth citing, with the artifact that presents it and the
provenance file that proves it.

Result files are gitignored — they are large and regenerable. What is committed
here is the record of what was run, what it found, and where the write-up lives.
Every run's `-seed` and corpus checksum are in its `.meta.json`, so any row below
can be reproduced exactly.

---

## Run 1 — first census

**[The www Census](https://claude.ai/code/artifact/7ac244d3-4005-4624-92a8-b41d730ed8a8)**

| | |
|---|---|
| date | 2026-08-13 |
| corpus | Tranco `26J79`, 1,000,000 domains, sha256 `33243560e98e` |
| sample | 150,000 uniform random, seed `20260813` (15.00%) |
| elapsed | 22m45s at 102.2 effective domains/sec |
| vantage | residential connection, Colorado |
| provenance | `results/census-sample.bin.meta.json` |

**Headline: of domains that serve a homepage and were successfully measured,
91.08% ± 0.17 also serve `www`.**

- 68.4% of the sampled corpus serves a homepage at all; the rest is CDN, API and
  DNS infrastructure that was never a website.
- 682 apex-serving domains had a `www` probe that stalled. They are excluded from
  the ratio rather than counted as broken — they were not measured, and assuming
  either answer would be inventing data. An earlier version of this page said
  90.47% because it folded them in as failures.
- Over half of all `www` breakage is a DNS record nobody created (37.5% NXDOMAIN,
  7.5% NODATA). The next largest cause, 18.8%, is a certificate never reissued to
  cover the name — someone added the record and stopped there.
- 26,085 sampled zones are wildcards, where `www` resolving proves nothing.
- Nearly one site in five serves both names independently with no canonical form.

Reported validity was 93.0%, below the 95% census floor. Re-probing 3,000 of the
stalled domains at 25 workers found ~85% still stall, so they are unreachable
hosts rather than scanner congestion; corrected validity is ~99%.

Reproduce:

```sh
wwwscan scan -corpus corpora/tranco.txt -out results/census-sample.bin \
             -sample 150000 -seed 20260813 -workers 200
```

---

## Reference — what "invalid" means

**[The Stall Ladder](https://claude.ai/code/artifact/874537f7-fda1-4d5e-98a7-0f12451cdcac)**

Not a run: the mechanism behind the validity number. Walks the four rungs a
probe passes through and shows how each one fails two different ways — a finding
(about the domain) or a stall (about the scanner). Explains why both names must
be conclusive for a record to count, and why a TCP timeout is deliberately
counted against ourselves.

---

## Throughput measurements

Not census runs. All `-mode throughput`, null sink, so no results were kept.

| date | vantage | workers | eff/s | valid | bound by |
|---|---|--:|--:|--:|---|
| 2026-08-13 | laptop, WiFi | 200 | 109.6 | 95.4% | new connections/sec on a domestic line |
| 2026-08-13 | laptop, WiFi | 1,000 | 109.3 | 79.3% | same ceiling, more failure |
| 2026-08-13 | laptop, WiFi | 10,000 | ~130 | 9.8% | same ceiling, mostly failure |
| 2026-08-13 | Hostinger VPS | 20 | 14.7 | 93.2% | healthy below the limiter |
| 2026-08-13 | Hostinger VPS | 200 | 16.6 | 39.7% | provider egress cap, ~30 conn/sec |

Raw domains/sec peaked near 860 at 10,000 workers, at 15% validity — the scanner
discovering it fails faster than it succeeds. This is why `eff/s` is the only
rate quoted.

**These measure the census workload, which is the expensive one.** A DNS-only
scanner is a different program with different limits, and has not been built yet.

---

## Adding a run

1. Scan with `-sample`/`-seed`, never `-limit`, for anything quotable.
2. Keep the `.meta.json` — `report` refuses to pair results with the wrong corpus,
   but only if the provenance file is there.
3. Publish the artifact, add a section above with its link, and note anything the
   run contradicted.
