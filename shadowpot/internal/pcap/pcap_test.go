package pcap

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestGlobalHeaderMagic(t *testing.T) {
	if len(globalHeader) != 24 {
		t.Fatalf("global header must be 24 bytes, got %d", len(globalHeader))
	}
	magic := binary.LittleEndian.Uint32(globalHeader[0:4])
	if magic != 0xa1b2c3d4 {
		t.Fatalf("magic = %#08x, want little-endian 0xa1b2c3d4", magic)
	}
	if binary.LittleEndian.Uint16(globalHeader[4:6]) != 2 ||
		binary.LittleEndian.Uint16(globalHeader[6:8]) != 4 {
		t.Fatal("version must be 2.4")
	}
	if binary.LittleEndian.Uint32(globalHeader[20:24]) != 1 {
		t.Fatal("linktype must be Ethernet (1)")
	}
}

func TestBuildFrameShape(t *testing.T) {
	h := PcapHeader{
		SrcIP:   netIP("192.168.1.10"),
		DstIP:   netIP("10.0.0.1"),
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1,
		Ack:     2,
	}
	payload := []byte("GET / HTTP/1.1\r\n")
	pkt := h.Build(payload)

	if len(pkt) != 14+20+20+len(payload) {
		t.Fatalf("packet length = %d, want %d", len(pkt), 14+20+20+len(payload))
	}

	// Ethernet: ethertype 0x0800.
	if pkt[12] != 0x08 || pkt[13] != 0x00 {
		t.Fatalf("ethertype = %#04x, want 0x0800", binary.BigEndian.Uint16(pkt[12:14]))
	}

	// IPv4: version/IHL, protocol TCP.
	if pkt[14] != 0x45 {
		t.Fatalf("ip version/ihl = %#02x, want 0x45", pkt[14])
	}
	if pkt[23] != 6 {
		t.Fatalf("ip proto = %d, want 6 (TCP)", pkt[23])
	}
	// IP header checksum must fold to 0.
	if got := onesChecksum(pkt[14:34]); got != 0 {
		t.Fatalf("ip header checksum invalid: 0x%04x", got)
	}

	// TCP: ports, flags PSH|ACK.
	if binary.BigEndian.Uint16(pkt[34:36]) != 12345 {
		t.Fatal("tcp src port mismatch")
	}
	if binary.BigEndian.Uint16(pkt[36:38]) != 80 {
		t.Fatal("tcp dst port mismatch")
	}
	if pkt[47] != 0x18 {
		t.Fatalf("tcp flags = %#02x, want PSH|ACK (0x18)", pkt[47])
	}

	// Payload lands at offset 54.
	if string(pkt[54:]) != string(payload) {
		t.Fatal("payload not copied after headers")
	}
}

func TestBuildChecksumFoldsToZero(t *testing.T) {
	h := PcapHeader{SrcIP: netIP("172.16.0.2"), DstIP: netIP("172.16.0.1"),
		SrcPort: 4444, DstPort: 22, Seq: 99, Ack: 100}
	pkt := h.Build([]byte("hello"))

	tcp := pkt[34:54]
	payload := pkt[54:]
	pseudo := make([]byte, 0, 12+len(tcp)+len(payload)+1)
	pseudo = append(pseudo, h.SrcIP.To4()...)
	pseudo = append(pseudo, h.DstIP.To4()...)
	pseudo = append(pseudo, 0, 6)
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)+len(payload)))
	pseudo = append(pseudo, tcp...)
	pseudo = append(pseudo, payload...)
	if len(pseudo)%2 == 1 {
		pseudo = append(pseudo, 0)
	}
	if got := onesChecksum(pseudo); got != 0 {
		t.Fatalf("tcp checksum invalid: 0x%04x", got)
	}
}

func TestBuildDefaultsIPv4Zero(t *testing.T) {
	h := PcapHeader{SrcPort: 1, DstPort: 2}
	pkt := h.Build(nil)
	// nil IPs fall back to 0.0.0.0, not an error.
	if len(pkt) != 54 {
		t.Fatalf("len = %d, want 54", len(pkt))
	}
}

func netIP(s string) net.IP {
	return net.ParseIP(s)
}
