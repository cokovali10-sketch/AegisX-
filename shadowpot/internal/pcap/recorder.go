package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Recorder owns the captures directory and appends per-flow PCAP files.
// A zero-value Recorder is disabled and silently drops every record, so it is
// always safe to pass into a listener even when PCAP capture is turned off.
type Recorder struct {
	dir     string
	enabled bool
	localIP net.IP
	mu      sync.Mutex
	seqs    map[string]uint32
}

// New returns a Recorder that writes captures under dir. When enabled is
// false the returned recorder is a no-op. If the capture directory cannot be
// created the caller still gets a usable (disabled) recorder plus the error.
func New(dir string, enabled bool) (*Recorder, error) {
	if !enabled {
		return &Recorder{}, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return &Recorder{}, fmt.Errorf("create pcap dir %s: %w", dir, err)
	}
	return &Recorder{dir: dir, enabled: true, localIP: detectLocalIP(), seqs: make(map[string]uint32)}, nil
}

// Enabled reports whether the recorder is writing captures to disk.
func (r *Recorder) Enabled() bool {
	return r != nil && r.enabled
}

// WriteFlow appends one PCAP packet record to captures/ev-<id>.pcap. srcIP and
// srcPort are the remote peer; dstPort is the decoy service port. direction is
// "c2s" (client -> server) or "s2c" (server -> client) and decides which side
// of the synthesized segment the payload is attributed to. A fresh file is
// created with a PCAP global header the first time an id is seen.
func (r *Recorder) WriteFlow(id, srcIP string, srcPort, dstPort int, direction string, data []byte) error {
	if r == nil || !r.enabled || id == "" || len(data) == 0 {
		return nil
	}
	src := net.ParseIP(srcIP)
	if src == nil {
		src = net.IPv4zero.To4()
	}
	dst := r.localIP
	if dst == nil {
		dst = net.IPv4(127, 0, 0, 1)
	}
	if src.To4() == nil || dst.To4() == nil {
		// Only IPv4 captures are synthesized; skip cleanly.
		return nil
	}

	var sIP, dIP net.IP
	var sPort, dPort int
	switch strings.ToLower(direction) {
	case "s2c":
		sIP, dIP, sPort, dPort = dst, src, dstPort, srcPort
	default: // "c2s"
		sIP, dIP, sPort, dPort = src, dst, srcPort, dstPort
	}

	r.mu.Lock()
	seq := r.seqs[id]
	r.seqs[id] = seq + uint32(len(data))
	r.mu.Unlock()

	hdr := PcapHeader{
		SrcIP:   sIP,
		DstIP:   dIP,
		SrcPort: uint16(sPort),
		DstPort: uint16(dPort),
		Seq:     seq,
	}
	return r.appendRecord(id, time.Now(), hdr.Build(data))
}

// appendRecord writes a single packet record (16-byte record header followed
// by the packet) to the flow's file, prepending the global header when needed.
func (r *Recorder) appendRecord(id string, ts time.Time, packet []byte) error {
	name := filepath.Join(r.dir, "ev-"+id+".pcap")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open pcap %s: %w", name, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat pcap %s: %w", name, err)
	}
	if st.Size() == 0 {
		if _, err := f.Write(globalHeader); err != nil {
			return fmt.Errorf("write pcap header %s: %w", name, err)
		}
	}

	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:8], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(packet)))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(packet)))
	if _, err := f.Write(rec); err != nil {
		return fmt.Errorf("write pcap record %s: %w", name, err)
	}
	if _, err := f.Write(packet); err != nil {
		return fmt.Errorf("write pcap packet %s: %w", name, err)
	}
	return nil
}

// Flow is a per-connection capture sink. Wrapping a connection in an
// io.TeeReader with a Flow captures every raw inbound byte as a c2s packet.
// Bytes are buffered and flushed in 4 KiB chunks to keep syscalls bounded.
type Flow struct {
	rec     *Recorder
	id      string
	srcIP   string
	srcPort int
	dstPort int
	buf     bytes.Buffer
}

// NewFlow creates a capture sink for a single connection. srcIP/srcPort are
// the remote peer; dstPort is the local decoy service port.
func NewFlow(rec *Recorder, id, srcIP string, srcPort, dstPort int) *Flow {
	return &Flow{rec: rec, id: id, srcIP: srcIP, srcPort: srcPort, dstPort: dstPort}
}

// Write implements io.Writer, buffering the captured bytes for this flow.
func (f *Flow) Write(p []byte) (int, error) {
	if f.rec == nil || !f.rec.enabled {
		return len(p), nil
	}
	f.buf.Write(p)
	if f.buf.Len() >= 4096 {
		if err := f.Flush(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush writes any buffered bytes for this flow as one PCAP packet record.
func (f *Flow) Flush() error {
	if f.rec == nil || !f.rec.enabled || f.buf.Len() == 0 {
		f.buf.Reset()
		return nil
	}
	err := f.rec.WriteFlow(f.id, f.srcIP, f.srcPort, f.dstPort, "c2s", f.buf.Bytes())
	f.buf.Reset()
	return err
}

// detectLocalIP resolves the host's first non-loopback IPv4 address, used as
// the destination endpoint in synthesized captures. Falls back to loopback.
func detectLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return net.IPv4(127, 0, 0, 1)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				return ip4
			}
		}
	}
	return net.IPv4(127, 0, 0, 1)
}
