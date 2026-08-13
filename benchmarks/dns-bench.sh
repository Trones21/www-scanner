#!/usr/bin/env bash
#
# dns-bench.sh — compare DNS-resolution tools on YOUR hardware.
#
# Runs each installed tool against the SAME input list and the SAME resolver
# set, times it, and reports queries/sec AND success rate. The point is a fair,
# apples-to-apples baseline so we can reason about why numbers differ.
#
# NOTE: this was written on a remote machine and could not be executed there.
# It is meant to run on your laptop. It passes `bash -n`; treat the per-tool
# flags as sane defaults and tune them (see comments) for your versions.
#
# Usage:
#   ./dns-bench.sh --input names.txt [--resolvers resolvers.txt] [--type A]
#                  [--conc 10000] [--count 100000]
#
# Fairness rules this script tries to honor (see docs/dns-benchmark.md):
#   - same input list for every tool
#   - same resolver set for every tool (so we compare tools, not upstreams)
#   - measure SUCCESS RATE, not just wall-clock — a tool that "does 300k/s" but
#     drops 90% of answers is not doing 300k useful/s.

set -euo pipefail

# ---- defaults -------------------------------------------------------------
INPUT=""
RESOLVERS=""
RTYPE="A"
CONC=10000          # in-flight concurrency for async tools
COUNT=0             # 0 = use whole input; else subsample first N lines
OUTDIR="./bench-out"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input)     INPUT="$2"; shift 2 ;;
    --resolvers) RESOLVERS="$2"; shift 2 ;;
    --type)      RTYPE="$2"; shift 2 ;;
    --conc)      CONC="$2"; shift 2 ;;
    --count)     COUNT="$2"; shift 2 ;;
    --outdir)    OUTDIR="$2"; shift 2 ;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$INPUT" && -f "$INPUT" ]] || { echo "need --input <file of names>" >&2; exit 2; }
mkdir -p "$OUTDIR"

# ---- prep input -----------------------------------------------------------
WORK="$OUTDIR/input.txt"
if [[ "$COUNT" -gt 0 ]]; then
  head -n "$COUNT" "$INPUT" > "$WORK"
else
  cp "$INPUT" "$WORK"
fi
N=$(wc -l < "$WORK" | tr -d ' ')
echo ">> input: $N names, record type $RTYPE, concurrency $CONC"

# ---- prep resolvers -------------------------------------------------------
# If you don't pass --resolvers, we fall back to a tiny public set. Public
# resolvers RATE-LIMIT hard at scale — for real max numbers, run a local
# recursive resolver (unbound) and point every tool at 127.0.0.1.
if [[ -z "$RESOLVERS" ]]; then
  RESOLVERS="$OUTDIR/resolvers.txt"
  printf '%s\n' 1.1.1.1 8.8.8.8 9.9.9.9 8.8.4.4 1.0.0.1 > "$RESOLVERS"
  echo ">> WARNING: no --resolvers given; using public set (will rate-limit)."
fi
FIRST_NS=$(head -n1 "$RESOLVERS")

# ---- raise limits (best effort) ------------------------------------------
ulimit -n 1048576 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null || true

# ---- timing + reporting ---------------------------------------------------
RESULTS="$OUTDIR/results.tsv"
printf 'tool\tseconds\tanswers\tqps\tsuccess_pct\n' > "$RESULTS"

have() { command -v "$1" >/dev/null 2>&1; }

# run <label> <answers-counter-cmd> -- <command...>
# answers-counter-cmd is run after; it must print the number of successful
# answers found in the tool's output file "$OUTDIR/<label>.out".
run() {
  local label="$1"; shift
  local counter="$1"; shift
  [[ "$1" == "--" ]] && shift
  local out="$OUTDIR/$label.out"
  echo ">> [$label] $*"
  local start end secs answers qps pct
  start=$(date +%s.%N)
  if ! "$@" > "$out" 2>"$OUTDIR/$label.err"; then
    echo "   !! $label exited non-zero (see $OUTDIR/$label.err); recording partial"
  fi
  end=$(date +%s.%N)
  secs=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')
  answers=$(eval "$counter")
  qps=$(awk -v n="$N" -v s="$secs" 'BEGIN{ if(s>0) printf "%.0f", n/s; else print "NA"}')
  pct=$(awk -v a="$answers" -v n="$N" 'BEGIN{ if(n>0) printf "%.1f", 100*a/n; else print "0"}')
  printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$secs" "$answers" "$qps" "$pct" >> "$RESULTS"
  echo "   $label: ${secs}s, $answers answers, ${qps} q/s, ${pct}% success"
}

# ===========================================================================
# Baselines — reproduce the "stub resolver" slow path on purpose.
# ===========================================================================

# 1) Serial stub resolver via getent (what a naive loop / getaddrinfo does).
if have getent; then
  run "getent-serial" "grep -c . '$OUTDIR/getent-serial.out'" -- \
    bash -c 'while read -r h; do getent hosts "$h" >/dev/null 2>&1 && echo "$h"; done < "'"$WORK"'"'
fi

# 2) Parallel stub resolver via xargs+dig — same stub path, N-way concurrency.
#    Shows how much of the gap is JUST concurrency vs the resolver path itself.
if have dig; then
  run "dig-xargs-100" "grep -c . '$OUTDIR/dig-xargs-100.out'" -- \
    bash -c 'xargs -P 100 -I{} sh -c "dig +short +tries=1 +time=1 '"$RTYPE"' {} @'"$FIRST_NS"' | grep -q . && echo {}" < "'"$WORK"'"'
fi

# ===========================================================================
# Bulk async resolvers — the massDNS class.
# ===========================================================================

# massdns: -s = concurrent lookups, -o S = simple output, -t = record type.
if have massdns; then
  run "massdns" "grep -c . '$OUTDIR/massdns.out'" -- \
    massdns -r "$RESOLVERS" -t "$RTYPE" -o S -s "$CONC" "$WORK"
fi

# dnsx (projectdiscovery): -t threads, -r resolver file. -a resolves A.
if have dnsx; then
  flag="-a"; [[ "$RTYPE" == "AAAA" ]] && flag="-aaaa"
  run "dnsx" "grep -c . '$OUTDIR/dnsx.out'" -- \
    dnsx -l "$WORK" $flag -t "$CONC" -r "$RESOLVERS" -silent
fi

# zdns (zmap): reads names on stdin. --name-servers pins the resolver set.
if have zdns; then
  run "zdns" "grep -c '\"status\":\"NOERROR\"' '$OUTDIR/zdns.out'" -- \
    bash -c 'zdns '"$RTYPE"' --name-servers "'"$FIRST_NS"'" --threads "'"$CONC"'" < "'"$WORK"'"'
fi

# ===========================================================================
# Summary
# ===========================================================================
echo
echo "==================== RESULTS ===================="
column -t -s $'\t' "$RESULTS"
echo "================================================="
echo "raw outputs + stderr in $OUTDIR/"
echo "reminder: compare qps AND success_pct together. High qps + low success"
echo "means packet loss / rate limiting, not real throughput."
