// Command dns-sink is a minimal, high-throughput DNS responder.
//
// It answers EVERY A query with 192.0.2.1 and every AAAA query with
// 2001:db8::1 (both reserved/documentation ranges). The answers are
// meaningless on purpose — the point is a responder with NO rate limiting and
// NO recursion, so a resolver benchmark is bounded only by packets-per-second,
// not by an upstream's policy. Point your DNS tools/scanner at this box's IP
// as their resolver and measure the ceiling.
//
// It uses SO_REUSEPORT to run one listener per core so the sink itself does
// not become the bottleneck. It prints its own answered-queries/sec once a
// second — if that number is well above your tool's rate, the sink is not the
// limit.
//
// Build:  go build -o dns-sink .
// Run:    sudo ./dns-sink -addr :53          (port <1024 needs root)
//
//	./dns-sink -addr :5353             (unprivileged, point tools at :5353)
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
)

// SO_REUSEPORT is 0x0f on Linux; hardcoded to avoid a golang.org/x/sys dep.
const soReusePort = 0x0f

var answered uint64

// AAAA payload for 2001:db8::1
var aaaaRData = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

func main() {
	addr := flag.String("addr", ":53", "UDP address to listen on")
	workers := flag.Int("workers", runtime.NumCPU(), "number of SO_REUSEPORT listeners")
	flag.Parse()

	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}

	for i := 0; i < *workers; i++ {
		pc, err := lc.ListenPacket(nil, "udp", *addr) //nolint:staticcheck // nil ctx ok for setup
		if err != nil {
			log.Fatalf("listen %s: %v", *addr, err)
		}
		go serve(pc.(*net.UDPConn))
	}

	go func() {
		var prev uint64
		for range time.Tick(time.Second) {
			cur := atomic.LoadUint64(&answered)
			log.Printf("answered %d q/s (total %d)", cur-prev, cur)
			prev = cur
		}
	}()

	log.Printf("dns-sink listening on %s with %d workers", *addr, *workers)
	select {}
}

func serve(conn *net.UDPConn) {
	req := make([]byte, 512)
	resp := make([]byte, 0, 512)
	for {
		n, peer, err := conn.ReadFromUDP(req)
		if err != nil {
			continue
		}
		resp = buildResponse(req[:n], resp[:0])
		if resp == nil {
			continue
		}
		if _, err := conn.WriteToUDP(resp, peer); err == nil {
			atomic.AddUint64(&answered, 1)
		}
	}
}

// buildResponse turns a query into a minimal authoritative answer. Returns nil
// if the query is malformed.
func buildResponse(q, out []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	// Walk the QNAME labels to find the end of the question section.
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	if i >= len(q) {
		return nil
	}
	qend := i + 1 + 4 // 0x00 terminator + QTYPE(2) + QCLASS(2)
	if qend > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[i+1 : i+3])

	// Header: copy ID, set QR+AA, one question, one answer.
	out = append(out, q[0], q[1]) // transaction ID
	out = append(out, 0x84, 0x00) // flags: QR=1, AA=1, RCODE=0
	out = append(out, 0x00, 0x01) // QDCOUNT
	out = append(out, 0x00, 0x01) // ANCOUNT
	out = append(out, 0x00, 0x00) // NSCOUNT
	out = append(out, 0x00, 0x00) // ARCOUNT

	out = append(out, q[12:qend]...) // question, verbatim

	// Answer: pointer to QNAME at offset 12.
	out = append(out, 0xc0, 0x0c)
	if qtype == 28 { // AAAA
		out = append(out, 0x00, 0x1c)
	} else { // treat everything else as A
		out = append(out, 0x00, 0x01)
	}
	out = append(out, 0x00, 0x01)             // CLASS IN
	out = append(out, 0x00, 0x00, 0x00, 0x3c) // TTL 60
	if qtype == 28 {
		out = append(out, 0x00, 0x10) // RDLENGTH 16
		out = append(out, aaaaRData...)
	} else {
		out = append(out, 0x00, 0x04)   // RDLENGTH 4
		out = append(out, 192, 0, 2, 1) // 192.0.2.1
	}
	return out
}
