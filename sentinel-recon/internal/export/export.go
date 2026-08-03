package export

import (
	"encoding/json"
	"os"
	"time"

	"aegisx.local/sentinel-recon/internal/scanner"
	"aegisx/proto/gen/go"
	"google.golang.org/protobuf/proto"
)

// Report is the versioned JSON envelope persisted to disk.
type Report struct {
	SchemaVersion string           `json:"schema_version"`
	ScanID        string           `json:"scan_id"`
	Target        string           `json:"target"`
	StartedAt     int64            `json:"started_at_ms"`
	FinishedAt    int64            `json:"finished_at_ms"`
	DurationMs    int64            `json:"duration_ms"`
	PortsScanned  uint32           `json:"ports_scanned"`
	OpenTCP       []scanner.Result `json:"open_tcp"`
	OpenUDP       []scanner.Result `json:"open_udp"`
	FilteredCount uint64           `json:"filtered_count"`
	Errors        []scanner.Result `json:"errors"`
}

var scanSeq int64

func nextScanID() string {
	scanSeq++
	return "scan-" + time.Now().UTC().Format("20060102T150405.000") +
		"-" + itoa(scanSeq)
}

func BuildReport(cfg scanner.Config, openTCP, openUDP []scanner.Result,
	filtered uint64, errs []scanner.Result) Report {
	now := time.Now().UTC().UnixMilli()
	return Report{
		SchemaVersion: "1.0",
		ScanID:        nextScanID(),
		Target:        cfg.Target,
		StartedAt:     now,
		FinishedAt:    now,
		OpenTCP:       openTCP,
		OpenUDP:       openUDP,
		FilteredCount: filtered,
		Errors:        errs,
	}
}

func WriteJSON(path string, r Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteProto emits the protobuf projection of the scan (portable across the
// gRPC boundary without the JSON envelope).
func WriteProto(path string, r Report) error {
	msg := &aegisxpb.ScanResponse{
		ScanId:       r.ScanID,
		Target:       r.Target,
		StartedAt:    r.StartedAt,
		DurationMs:   r.DurationMs,
		PortsScanned: r.PortsScanned,
	}
	for _, p := range append(append([]scanner.Result{}, r.OpenTCP...), r.OpenUDP...) {
		msg.OpenPorts = append(msg.OpenPorts, &aegisxpb.OpenPort{
			Host:     p.Host,
			Port:     int32(p.Port),
			Protocol: p.Protocol,
			State:    p.State,
			Service:  p.Service,
			Banner:   p.Banner,
			RttMs:    p.RTTMs,
		})
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
