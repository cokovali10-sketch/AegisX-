// Package pcap provides a dependency-free PCAP (libpcap classic format)
// writer for capturing raw honeypot traffic. It has no external dependencies
// and synthesizes Ethernet + IPv4 + TCP headers around the raw connection
// bytes so the captures can be opened directly in Wireshark.
package pcap

import (
	"encoding/binary"
	"net"
)

// PCAP global header for the classic (little-endian) format: magic 0xa1b2c3d4,
// version 2.4, no timezone correction, snaplen 65535, linktype 1 (Ethernet).
var globalHeader = []byte{
	0xd4, 0xc3, 0xb2, 0xa1, // magic 0xa1b2c3d4
	0x02, 0x00, // major version 2
	0x04, 0x00, // minor version 4
	0x00, 0x00, 0x00, 0x00, // thiszone
	0x00, 0x00, 0x00, 0x00, // sigfigs
	0xff, 0xff, 0x00, 0x00, // snaplen 65535
	0x01, 0x00, 0x00, 0x00, // network = 1 (Ethernet)
}

// PcapHeader describes a synthetic TCP segment to wrap captured raw bytes in.
// It is used to build fake Ethernet + IPv4 + TCP framing around payloads so a
// honeypot session becomes a self-contained, analyzable packet capture.
type PcapHeader struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
}

// Build renders the 14-byte Ethernet, 20-byte IPv4 and 20-byte TCP headers,
// followed by payload, as a single packet ready to be stored in a PCAP record.
// TCP checksum is computed over the IPv4 pseudo-header per RFC 793.
func (h PcapHeader) Build(payload []byte) []byte {
	src4 := h.SrcIP.To4()
	dst4 := h.DstIP.To4()
	if src4 == nil {
		src4 = net.IPv4zero.To4()
	}
	if dst4 == nil {
		dst4 = net.IPv4zero.To4()
	}

	pkt := make([]byte, 14+20+20+len(payload))

	// Ethernet II frame (fabricated addresses, ethertype 0x0800).
	copy(pkt[0:6], dst4)
	copy(pkt[6:12], src4)
	pkt[0] = 0x02 // locally administered bit
	pkt[12] = 0x08
	pkt[13] = 0x00

	// IPv4 header.
	ip := pkt[14:34]
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	binary.BigEndian.PutUint16(ip[4:6], uint16(h.SrcPort)*uint16(h.DstPort)) // pseudo id
	ip[8] = 64                                                               // TTL
	ip[9] = 6                                                                // TCP
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	binary.BigEndian.PutUint16(ip[10:12], onesChecksum(ip))

	// TCP header.
	tcp := pkt[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(tcp[2:4], h.DstPort)
	binary.BigEndian.PutUint32(tcp[4:8], h.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], h.Ack)
	tcp[12] = 0x50                                // data offset 5
	tcp[13] = 0x18                                // flags: PSH|ACK
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // window

	// TCP checksum over pseudo-header + segment.
	pseudo := make([]byte, 0, 12+len(tcp)+len(payload)+1)
	pseudo = append(pseudo, src4...)
	pseudo = append(pseudo, dst4...)
	pseudo = append(pseudo, 0, 6)
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)+len(payload)))
	pseudo = append(pseudo, tcp...)
	pseudo = append(pseudo, payload...)
	if len(pseudo)%2 == 1 {
		pseudo = append(pseudo, 0)
	}
	binary.BigEndian.PutUint16(tcp[16:18], onesChecksum(pseudo))

	copy(pkt[54:], payload)
	return pkt
}

// onesChecksum computes the Internet one's-complement checksum.
func onesChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
