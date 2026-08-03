package event

import (
	"sync"
	"time"

	"aegisx/proto/gen/go"
)

// Event carries a normalized decoy observation. It is the single internal
// representation shared by all protocol listeners before serialization.
type Event struct {
	ID                 string
	Timestamp          time.Time
	SourceIP           string
	SourcePort         uint32
	Protocol           string
	TargetPort         uint32
	Username           string
	Password           string
	UserAgent          string
	Payload            string
	Method             string
	Path               string
	Metadata           map[string]string
	ConnectionDuration time.Duration
}

// ToProto projects an internal Event onto the wire contract.
func (e *Event) ToProto() *aegisxpb.HoneypotEvent {
	meta := e.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	return &aegisxpb.HoneypotEvent{
		Id:                   e.ID,
		Timestamp:            e.Timestamp.UTC().UnixMilli(),
		SourceIp:             e.SourceIP,
		SourcePort:           e.SourcePort,
		Protocol:             e.Protocol,
		TargetPort:           e.TargetPort,
		Username:             e.Username,
		Password:             e.Password,
		UserAgent:            e.UserAgent,
		Payload:              e.Payload,
		Method:               e.Method,
		Path:                 e.Path,
		Metadata:             meta,
		ConnectionDurationMs: float64(e.ConnectionDuration.Milliseconds()),
	}
}

// Bus is a bounded, fan-out event bus with backpressure. The streamer (gRPC)
// and the local event logger both subscribe; a slow consumer drops events
// rather than stalling the decoy listeners.
type Bus struct {
	mu     sync.RWMutex
	subs   map[chan *Event]struct{}
	closed bool
}

func NewBus() *Bus {
	return &Bus{subs: make(map[chan *Event]struct{})}
}

func (b *Bus) Subscribe() chan *Event {
	ch := make(chan *Event, 1024)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		close(ch)
		return ch
	}
	b.subs[ch] = struct{}{}
	return ch
}

func (b *Bus) Unsubscribe(ch chan *Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[ch]; ok {
		delete(b.subs, ch)
		close(ch)
	}
}

func (b *Bus) Publish(e *Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default: // slow consumer: drop, do not block decoys
		}
	}
}

func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for ch := range b.subs {
		close(ch)
	}
	b.subs = map[chan *Event]struct{}{}
}
