#!/usr/bin/env bash
#
# Build wwwscan, ship it to a VPS, and run it there.
#
# The point is to measure throughput from somewhere that isn't a domestic
# uplink. Every number measured on the laptop plateaued at ~110 effective
# domains/sec regardless of workers, resolvers, sockets or timeouts, which
# points at the house rather than the code. One run from a real link settles
# it, and the per-machine ceiling it reports is what sets the fleet size for
# anything at billion scale.
#
# No Go toolchain is needed on the remote: the binary is built static here.
#
#   ./scripts/deploy.sh vps.example.com                  # deploy + doctor + bench
#   ./scripts/deploy.sh -u tom vps.example.com doctor    # just the machine facts
#   ./scripts/deploy.sh vps.example.com bench -workers 200,1000,4000 -duration 20s
#   ./scripts/deploy.sh vps.example.com shell            # interactive session
#
set -euo pipefail

# Empty by default so ~/.ssh/config wins. Passing root@ or -p 22 explicitly
# would override a Host block's User and Port, which is exactly the wrong
# behaviour when the argument is an alias the user already configured.
USER=""
PORT=""
IDENTITY=""
REMOTE_DIR=/opt/wwwscan
CORPUS_LIMIT=200000

usage() {
	cat >&2 <<'EOF'
usage: deploy.sh [options] <host> [command ...]

<host> may be a hostname, an IP, or a Host alias from ~/.ssh/config. Options
left unset defer to your ssh config, so an alias that already works with
"ssh <alias>" works here unchanged.

options:
  -u USER      ssh user (default: whatever ~/.ssh/config says, else ssh's default)
  -p PORT      ssh port (default: whatever ~/.ssh/config says, else 22)
  -i KEY       ssh identity file (default: whatever ~/.ssh/config says)
  -d DIR       remote directory (default: /opt/wwwscan)
  -n N         corpus size to materialize remotely (default: 200000, 0 = full 1M)
  -h           this help

commands:
  bench [args] time-boxed sweep (default; extra args pass through to wwwscan bench)
  doctor       print the remote machine's limits, which is how bench output gets read
  scan [args]  a real census run
  probe [args] classify individual domains
  shell        interactive ssh into the deploy directory
  push         deploy the binary and corpus, then stop

Nothing here runs with sudo. If the remote needs raised limits, deploy.sh
reports what it found rather than changing the machine under you.
EOF
	exit 2
}

while getopts ":u:p:i:d:n:h" opt; do
	case "$opt" in
	u) USER=$OPTARG ;;
	p) PORT=$OPTARG ;;
	i) IDENTITY=$OPTARG ;;
	d) REMOTE_DIR=$OPTARG ;;
	n) CORPUS_LIMIT=$OPTARG ;;
	h) usage ;;
	:) echo "deploy.sh: -$OPTARG needs a value" >&2; exit 2 ;;
	\?) echo "deploy.sh: unknown option -$OPTARG" >&2; usage ;;
	esac
done
shift $((OPTIND - 1))

[ $# -ge 1 ] || usage
HOST=$1
shift
COMMAND=${1:-bench}
[ $# -gt 0 ] && shift || true

SSH_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
SCP_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
if [ -n "$PORT" ]; then
	SSH_OPTS+=(-p "$PORT")
	SCP_OPTS+=(-P "$PORT")
fi
if [ -n "$IDENTITY" ]; then
	SSH_OPTS+=(-i "$IDENTITY")
	SCP_OPTS+=(-i "$IDENTITY")
fi

# Only qualify the host when a user was asked for, so a config alias keeps
# whatever User its Host block sets.
if [ -n "$USER" ]; then
	TARGET="$USER@$HOST"
else
	TARGET="$HOST"
fi
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

say() { printf '\033[1m==>\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31mdeploy.sh:\033[0m %s\n' "$*" >&2; exit 1; }

remote() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }

check_ssh() {
	say "checking ssh to $TARGET"
	if ! remote true 2>/dev/null; then
		cat >&2 <<EOF

Cannot ssh to $TARGET.

Check first that plain "ssh $HOST" works. If it does and this does not, the
options passed here are fighting your ~/.ssh/config.

If this is a fresh VPS, the public half of your key is not installed yet.
The public key is not secret — paste it anywhere, including a web console:

    cat ~/.ssh/id_ed25519.pub

Then, in the provider's web console, on the server:

    mkdir -p ~/.ssh && chmod 700 ~/.ssh
    echo '<paste the public key here>' >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys

If you have no key yet:  ssh-keygen -t ed25519 -C wwwscan-vps
EOF
		exit 1
	fi
}

build_and_push() {
	say "building static linux/amd64 binary"
	# CGO off means no libc dependency, so one binary runs on any Linux
	# without installing a toolchain on the far end.
	( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags="-s -w" -o /tmp/wwwscan.linux ./cmd/wwwscan ) \
		|| die "build failed"

	say "shipping to $TARGET:$REMOTE_DIR"
	remote "mkdir -p '$REMOTE_DIR'" || die "cannot create $REMOTE_DIR"
	scp "${SCP_OPTS[@]}" -q /tmp/wwwscan.linux "$TARGET:$REMOTE_DIR/wwwscan" || die "scp failed"
	remote "chmod +x '$REMOTE_DIR/wwwscan'"

	# Materialize the corpus on the remote rather than uploading it. The
	# download is a few seconds on a datacentre link and would be minutes
	# on a home upstream.
	local corpus="$REMOTE_DIR/corpora/tranco.txt"
	if remote "test -s '$corpus'"; then
		say "corpus already present ($(remote "wc -l < '$corpus'" | tr -d ' ') domains)"
	else
		say "materializing corpus on the remote (limit ${CORPUS_LIMIT})"
		remote "cd '$REMOTE_DIR' && ./wwwscan corpus -out corpora/tranco.txt -limit $CORPUS_LIMIT" \
			|| die "corpus fetch failed on the remote"
	fi
}

# doctor prints the facts needed to interpret a throughput number. Every wall
# hit on the laptop was one of these, and reading a bench result without them
# is guesswork.
doctor() {
	say "remote machine facts"
	remote 'bash -s' <<'EOF'
set -u
printf '\n--- cpu / memory ---\n'
printf 'cores          %s\n' "$(nproc)"
printf 'model          %s\n' "$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | sed 's/^ *//')"
printf 'memory         %s\n' "$(awk '/MemTotal/{printf "%.1f GB", $2/1048576}' /proc/meminfo)"

printf '\n--- limits that have actually bitten ---\n'
printf 'open files     %s (soft)  %s (hard)\n' "$(ulimit -Sn)" "$(ulimit -Hn)"
printf 'ephemeral ports %s  => %s ports\n' \
    "$(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null | tr '\t' '-')" \
    "$(awk '{print $2-$1+1}' /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo '?')"
if [ -r /proc/sys/net/netfilter/nf_conntrack_max ]; then
    printf 'conntrack      %s / %s in use\n' \
        "$(cat /proc/sys/net/netfilter/nf_conntrack_count)" \
        "$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
else
    printf 'conntrack      not loaded (good: no NAT table to fill)\n'
fi

printf '\n--- network ---\n'
IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
printf 'interface      %s\n' "${IFACE:-unknown}"
if [ -n "${IFACE:-}" ] && [ -r "/sys/class/net/$IFACE/speed" ]; then
    printf 'link speed     %s Mbps (as reported)\n' "$(cat "/sys/class/net/$IFACE/speed" 2>/dev/null || echo '?')"
fi
printf 'public ip      %s\n' "$(curl -s --max-time 5 https://api.ipify.org || echo '?')"
printf 'resolv.conf    %s\n' "$(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf)"

printf '\n--- what this means ---\n'
printf 'A billion domains daily needs 11574/sec sustained.\n'
printf 'At ~5 DNS queries and ~2 TLS handshakes per domain that is\n'
printf '~58k qps and ~1 Gbps, so read the bench numbers against the link above.\n'
EOF
}

run_remote() {
	local cmd=$1
	shift
	say "running: wwwscan $cmd $*"
	echo >&2
	# -t gives a TTY so the progress line redraws in place and Ctrl-C
	# reaches the remote process instead of just closing the pipe.
	ssh -t "${SSH_OPTS[@]}" "$TARGET" \
		"cd '$REMOTE_DIR' && ulimit -n \$(ulimit -Hn) 2>/dev/null; ./wwwscan $cmd $*"
}

check_ssh

case "$COMMAND" in
push)
	build_and_push
	say "deployed; nothing run"
	;;
doctor)
	build_and_push
	doctor
	;;
shell)
	say "opening a shell in $REMOTE_DIR"
	ssh -t "${SSH_OPTS[@]}" "$TARGET" "cd '$REMOTE_DIR' && exec \$SHELL -l"
	;;
bench)
	build_and_push
	doctor
	echo >&2
	if [ $# -eq 0 ]; then
		run_remote bench -workers 200,1000,4000 -duration 20s
	else
		run_remote bench "$@"
	fi
	;;
scan | probe | report | corpus | diff)
	build_and_push
	run_remote "$COMMAND" "$@"
	;;
*)
	die "unknown command '$COMMAND' (try: bench, doctor, scan, probe, shell, push)"
	;;
esac
