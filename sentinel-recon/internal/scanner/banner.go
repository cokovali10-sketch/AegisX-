package scanner

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

// Probe sequences per candidate service. Servers that speak first (SSH, FTP,
// SMTP, MySQL, ...) are captured immediately; stateful protocols (HTTP,
// Redis) receive a matching probe to elicit a banner.
var probes = []string{
	"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: AegisX/1.0\r\n\r\n", // HTTP
	"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n",
	"*1\r\n$4\r\nPING\r\n\r\n", // Redis
	"",                         // passive (server speaks first)
	"\x05\x00\x00\x00",         // DNS query header, may elicit response
}

// GrabBanner identifies the listening service and captures its banner.
// It is protocol-agnostic: it first sniffs whatever the server emits, then
// optionally sends probes if nothing arrived (probe-driven services).
func GrabBanner(conn net.Conn, timeout time.Duration, tryProbe bool) (service, banner string) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)

	// Pass 1: wait for a server-initiated banner (SSH, FTP, SMTP, HTTP/1.1+).
	n, err := conn.Read(tmp)
	if err == nil && n > 0 {
		buf = append(buf, tmp[:n]...)
	} else if !tryProbe {
		return "", ""
	}

	if tryProbe {
		for _, p := range probes {
			if len(buf) > 0 && serviceGuess(string(buf)) != "" {
				break
			}
			if strings.TrimSpace(p) == "" {
				continue
			}
			if _, werr := conn.Write([]byte(p)); werr != nil {
				break
			}
			_ = conn.SetReadDeadline(time.Now().Add(timeout / 2))
			for {
				n, rerr := conn.Read(tmp)
				if rerr != nil || n == 0 {
					break
				}
				buf = append(buf, tmp[:n]...)
				if bytes.Contains(buf, []byte("\r\n\r\n")) {
					break
				}
				if len(buf) > 8192 {
					break
				}
			}
		}
	}

	text := sanitizeBanner(string(buf))
	service = serviceGuess(text)
	if service == "" {
		service = "unknown"
	}
	return service, text
}

// serviceGuess classifies a banner fragment into a concrete service name.
func serviceGuess(b string) string {
	lower := strings.ToLower(b)
	switch {
	case strings.HasPrefix(lower, "ssh-"):
		return "ssh"
	case strings.HasPrefix(lower, "http/"), strings.HasPrefix(lower, "www."),
		strings.Contains(lower, "content-type:"), strings.Contains(lower, "server:"):
		return "http"
	case strings.HasPrefix(lower, "220 "):
		if strings.Contains(lower, "smtp") || strings.Contains(lower, "esmtp") {
			return "smtp"
		}
		return "ftp"
	case strings.HasPrefix(lower, "ftp"), strings.Contains(lower, "vsftpd"),
		strings.Contains(lower, "proftpd"):
		return "ftp"
	case strings.HasPrefix(lower, "*1\r\n$4\r\nping") || strings.Contains(lower, "redis_version"):
		return "redis"
	case strings.HasPrefix(lower, "+ok"):
		return "redis"
	case strings.HasPrefix(lower, "\x05\x00\x00\x00"):
		return "dns"
	case strings.HasPrefix(lower, "ehlo"), strings.HasPrefix(lower, "helo"):
		return "smtp"
	case strings.Contains(lower, "mysql"), strings.HasPrefix(lower, "\x0a"):
		return "mysql"
	case strings.Contains(lower, "postgresql"), strings.HasPrefix(lower, "s"):
		return "postgresql"
	case strings.Contains(lower, "nginx"), strings.Contains(lower, "apache"):
		return "http"
	}
	return ""
}

// sniffService is the UDP companion of serviceGuess (banners are shorter).
func sniffService(b string) (service, banner string) {
	text := sanitizeBanner(b)
	return serviceGuess(text), text
}

// sanitizeBanner strips control bytes and caps length to keep logs clean.
func sanitizeBanner(b string) string {
	b = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return '.'
		}
		return r
	}, b)
	if len(b) > 2048 {
		b = b[:2048]
	}
	return strings.TrimRight(b, "\r\n ")
}

var _ = fmt.Sprintf // keep fmt import for future structured errors
