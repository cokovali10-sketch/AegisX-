package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10

	synBufSize = 4096
)

// synScanner is a raw-packet TCP SYN scanner. It crafts SYN segments against a
// single target, listens on a claimed low source port and correlates SYN-ACKs
// back to in-flight probes by their sequence number.
//
// Raw sockets require elevated privileges (CAP_NET_RAW on Linux) and are
// unavailable on Windows; openSynScanner reports that so callers can fall back
// to the connect scan.
type synScanner struct {
	dst     net.IP
	srcIP   net.IP
	srcPort int
	v4      *ipv4.RawConn
	v6      net.PacketConn // raw "ip6:tcp" socket; x/net has no ipv6 RawConn
	seq     uint32
	probes  sync.Map // uint32 sentSeq -> *synProbe
	claim   net.PacketConn
	done    chan struct{}
	once    sync.Once
}

// synProbe is one in-flight SYN awaiting a response for port.
type synProbe struct {
	seq  uint32
	port int
	res  chan synState
}

type synState int

const (
	synClosed synState = iota
	synOpen
)

func (s synState) String() string {
	if s == synOpen {
		return "open"
	}
	return "closed"
}

// openSynScanner prepares raw sockets and claims a low source port for the
// scan. It returns a non-nil error when the raw socket cannot be opened.
func openSynScanner(ctx context.Context, dst net.IP, seq uint32) (*synScanner, error) {
	srcIP, err := localAddr(dst)
	if err != nil {
		return nil, fmt.Errorf("resolve source ip: %w", err)
	}

	s := &synScanner{
		dst:    dst,
		srcIP:  srcIP,
		seq:    seq,
		probes: sync.Map{},
		done:   make(chan struct{}),
	}

	// Claim an ephemeral port so nothing else in the kernel uses it while raw
	// SYN segments carry it as their source port.
	claim, err := net.ListenPacket("udp4", net.JoinHostPort(srcIP.String(), "0"))
	if err == nil {
		if ua, ok := claim.LocalAddr().(*net.UDPAddr); ok {
			s.srcPort = ua.Port
		}
		s.claim = claim
	} else {
		s.srcPort = 1024 + rand.Intn(5000) // unprivileged fallback
	}

	if ip4 := dst.To4(); ip4 != nil {
		c, err := net.ListenPacket("ip4:tcp", srcIP.String())
		if err != nil {
			s.close()
			return nil, fmt.Errorf("open ip4 raw socket: %w", err)
		}
		rc, err := ipv4.NewRawConn(c)
		if err != nil {
			c.Close()
			s.close()
			return nil, fmt.Errorf("open ip4 raw conn: %w", err)
		}
		s.v4 = rc
		go s.readLoop()
		return s, nil
	}

	c, err := net.ListenPacket("ip6:tcp", srcIP.String())
	if err != nil {
		s.close()
		return nil, fmt.Errorf("open ip6 raw socket: %w", err)
	}
	s.v6 = c
	go s.readLoop()
	return s, nil
}

func (s *synScanner) close() {
	s.once.Do(func() {
		close(s.done)
		if s.v4 != nil {
			s.v4.Close()
		}
		if s.v6 != nil {
			s.v6.Close()
		}
		if s.claim != nil {
			s.claim.Close()
		}
	})
}

// probe sends one SYN and classifies the reply as open/closed/filtered.
func (s *synScanner) probe(ctx context.Context, port int, timeout time.Duration) Result {
	res := Result{Host: s.dst.String(), Port: port, Protocol: "tcp", State: "filtered"}

	seq := s.nextSeq()
	pr := &synProbe{seq: seq, port: port, res: make(chan synState, 1)}
	s.probes.Store(seq, pr)
	defer s.probes.Delete(seq)

	if err := s.sendSYN(port, seq); err != nil {
		res.Err = fmt.Errorf("send syn: %w", err)
		return res
	}

	start := time.Now()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return res
	case st := <-pr.res:
		res.State = st.String()
		res.RTTMs = time.Since(start).Milliseconds()
		return res
	case <-timer.C:
		return res
	}
}

func (s *synScanner) nextSeq() uint32 {
	s.seq++
	return s.seq
}

// sendSYN crafts and emits a SYN segment with a fixed sequence number.
func (s *synScanner) sendSYN(port int, seq uint32) error {
	if s.v4 != nil {
		return s.sendSYNv4(port, seq)
	}
	return s.sendSYNv6(port, seq)
}

func (s *synScanner) sendSYNv4(port int, seq uint32) error {
	tcp := tcpSegmentV4(s.srcIP, s.dst, uint16(s.srcPort), uint16(port), seq, 0, tcpSYN)
	hdr := &ipv4.Header{
		Version:  4,
		Len:      20,
		TOS:      0,
		TotalLen: 20 + len(tcp),
		ID:       int(rand.Uint32()),
		Flags:    ipv4.DontFragment,
		FragOff:  0,
		TTL:      64,
		Protocol: 6,
		Src:      s.srcIP,
		Dst:      s.dst,
	}
	// x/net sets an ID if zero but never recomputes a set checksum, so compute
	// the checksum over the exact marshalled header bytes.
	if b, err := hdr.Marshal(); err == nil {
		hdr.Checksum = checksumIPv4Header(b)
	}
	return s.v4.WriteTo(hdr, tcp, nil)
}

func (s *synScanner) sendSYNv6(port int, seq uint32) error {
	tcp := tcpSegmentV6(s.srcIP, s.dst, uint16(s.srcPort), uint16(port), seq, 0, tcpSYN)
	_, err := s.v6.WriteTo(tcp, &net.IPAddr{IP: s.dst})
	return err
}

// sendRST closes a confirmed-open port so the target releases its half-open
// connection state. seq/ack echo the observed SYN-ACK.
func (s *synScanner) sendRST(port int, seq, ack uint32) {
	if s.v4 != nil {
		tcp := tcpSegmentV4(s.srcIP, s.dst, uint16(s.srcPort), uint16(port), seq, ack, tcpRST|tcpACK)
		hdr := &ipv4.Header{
			Version:  4,
			Len:      20,
			TotalLen: 20 + len(tcp),
			TTL:      64,
			Protocol: 6,
			Src:      s.srcIP,
			Dst:      s.dst,
		}
		if b, err := hdr.Marshal(); err == nil {
			hdr.Checksum = int(onesComplementChecksum(b))
		}
		_ = s.v4.WriteTo(hdr, tcp, nil)
		return
	}
	tcp := tcpSegmentV6(s.srcIP, s.dst, uint16(s.srcPort), uint16(port), seq, ack, tcpRST|tcpACK)
	_, _ = s.v6.WriteTo(tcp, &net.IPAddr{IP: s.dst})
}

// readLoop is the single goroutine that consumes raw TCP segments and resolves
// pending probes by matching the observed sequence number against sent seqs.
func (s *synScanner) readLoop() {
	if s.v4 != nil {
		s.readLoopv4()
		return
	}
	s.readLoopv6()
}

func (s *synScanner) readLoopv4() {
	buf := make([]byte, synBufSize)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		_, p, _, err := s.v4.ReadFrom(buf)
		if err != nil {
			if isTemporary(err) {
				continue
			}
			return
		}
		s.handleTCP(p)
	}
}

func (s *synScanner) readLoopv6() {
	buf := make([]byte, synBufSize)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		n, _, err := s.v6.ReadFrom(buf)
		if err != nil {
			if isTemporary(err) {
				continue
			}
			return
		}
		if p := v6TCPPayload(buf[:n]); p != nil {
			s.handleTCP(p)
		}
	}
}

// v6TCPPayload strips the IPv6 base and extension headers off a received
// datagram and returns the TCP segment, or nil when the payload is not TCP.
func v6TCPPayload(b []byte) []byte {
	if len(b) < 40 || b[0]>>4 != 6 {
		return nil
	}
	off := 40
	next := int(b[6])
	for {
		switch next {
		case 6: // TCP
			return b[off:]
		case 59: // no next header
			return nil
		case 44: // fragment header, fixed size
			off += 8
		case 51: // AH
			if off+2 > len(b) {
				return nil
			}
			off += (int(b[off+1]) + 2) * 4
		case 0, 43, 60: // hop-by-hop, routing, dest options
			if off+2 > len(b) {
				return nil
			}
			off += (int(b[off+1]) + 1) * 8
		case 50: // ESP, opaque payload
			return nil
		default:
			return nil
		}
		if off >= len(b) {
			return nil
		}
		next = int(b[off])
		off++
	}
}

// handleTCP inspects a TCP segment, matching SYN-ACKs/RSTs to in-flight probes.
func (s *synScanner) handleTCP(p []byte) {
	if len(p) < 20 {
		return
	}
	srcPort := binary.BigEndian.Uint16(p[0:2])
	dstPort := binary.BigEndian.Uint16(p[2:4])
	if dstPort != uint16(s.srcPort) {
		return
	}
	seq := binary.BigEndian.Uint32(p[4:8])
	ack := binary.BigEndian.Uint32(p[8:12])
	flags := p[13]

	// The response's ACK field echoes our sent seq+1, so correlate probes by
	// ack-1 (the received segment's own seq is the target's ISN and random).
	v, ok := s.probes.Load(ack - 1)
	if !ok {
		return
	}
	pr, ok := v.(*synProbe)
	if !ok || srcPort != uint16(pr.port) {
		return
	}

	switch {
	case flags&(tcpSYN|tcpACK) == tcpSYN|tcpACK:
		pr.res <- synOpen
		s.sendRST(pr.port, seq, ack)
	case flags&tcpRST != 0:
		pr.res <- synClosed
	}
}

func isTemporary(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// localAddr picks the source address used to reach dst by peeking through a
// throwaway UDP dial (no packets are actually sent).
func localAddr(dst net.IP) (net.IP, error) {
	network := "udp4"
	if dst.To4() == nil {
		network = "udp6"
	}
	c, err := net.Dial(network, net.JoinHostPort(dst.String(), "0"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected local addr %T", c.LocalAddr())
	}
	return ua.IP, nil
}

// tcpSegmentV4 builds a TCP segment (without IP header) carrying the proper
// IPv4 pseudo-header checksum.
func tcpSegmentV4(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4 // data offset 20 bytes, no options
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // window
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumV4(srcIP, dstIP, tcp))
	binary.BigEndian.PutUint16(tcp[18:20], 0) // urgent
	return tcp
}

// tcpSegmentV6 builds a TCP segment carrying the IPv6 pseudo-header checksum.
func tcpSegmentV6(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumV6(srcIP, dstIP, tcp))
	binary.BigEndian.PutUint16(tcp[18:20], 0)
	return tcp
}

// checksumIPv4Header computes the 16-bit one's-complement checksum over a
// marshalled IPv4 header whose checksum field is still zero.
func checksumIPv4Header(hdr []byte) int {
	return int(onesComplementChecksum(hdr))
}

// tcpChecksumV4 folds the IPv4 pseudo-header into the TCP segment checksum.
func tcpChecksumV4(srcIP, dstIP net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	return onesComplementChecksum(pseudo)
}

// tcpChecksumV6 folds the IPv6 pseudo-header into the TCP segment checksum.
func tcpChecksumV6(srcIP, dstIP net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 40+len(tcp))
	copy(pseudo[0:16], srcIP.To16())
	copy(pseudo[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(tcp)))
	pseudo[39] = 6
	copy(pseudo[40:], tcp)
	return onesComplementChecksum(pseudo)
}

// onesComplementChecksum computes the standard Internet checksum.
func onesComplementChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
