package event

import (
	"testing"
	"time"
)

func newTestEvent(id string) *Event {
	return &Event{ID: id, SourceIP: "203.0.113.1", Protocol: "ssh"}
}

func TestSubscribePublish(t *testing.T) {
	b := NewBus()
	ch := b.Subscribe()
	defer b.Close()

	e := newTestEvent("ev-1")
	b.Publish(e)

	select {
	case got := <-ch:
		if got.ID != "ev-1" {
			t.Fatalf("got event %s", got.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("event not delivered to subscriber")
	}
}

func TestFanOutToMultipleSubscribers(t *testing.T) {
	b := NewBus()
	defer b.Close()
	ch1 := b.Subscribe()
	ch2 := b.Subscribe()

	e := newTestEvent("ev-2")
	b.Publish(e)

	for i, ch := range []chan *Event{ch1, ch2} {
		select {
		case got := <-ch:
			if got.ID != "ev-2" {
				t.Fatalf("subscriber %d got wrong event", i)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d missed event", i)
		}
	}
}

func TestUnsubscribeClosesChannel(t *testing.T) {
	b := NewBus()
	ch := b.Subscribe()
	b.Unsubscribe(ch)
	if _, ok := <-ch; ok {
		t.Fatal("unsubscribed channel should be closed")
	}
}

func TestSlowConsumerDropsNotBlocks(t *testing.T) {
	b := NewBus()
	// Subscribe but never drain -> the bounded 1024 buffer fills.
	_ = b.Subscribe()
	done := make(chan struct{})
	go func() {
		// Rapid publications must not block even though the consumer drains nothing.
		for i := 0; i < 5000; i++ {
			b.Publish(newTestEvent("x"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked behind slow consumer; should drop instead")
	}
}

func TestCloseCapsNewPublications(t *testing.T) {
	b := NewBus()
	ch := b.Subscribe()
	b.Close()
	if _, ok := <-ch; ok {
		t.Fatal("Close should close existing subscriber channels")
	}
	// subscribe after close returns a closed channel immediately.
	ch2 := b.Subscribe()
	if _, ok := <-ch2; ok {
		t.Fatal("subscribe-after-close should return closed channel")
	}
}

func TestToProtobuf(t *testing.T) {
	e := &Event{
		ID: "ev-9", SourceIP: "198.51.100.2", SourcePort: 44444,
		Protocol: "mysql", TargetPort: 3306, Username: "root",
		Password: "hunter2", UserAgent: "test", Payload: "p",
		Method: "AUTH", Path: "/", Metadata: map[string]string{"k": "v"},
	}
	p := e.ToProto()
	if p.Username != "root" || p.SourceIp != "198.51.100.2" || p.Protocol != "mysql" || p.TargetPort != 3306 {
		t.Fatalf("proto projection mismatch: %+v", p)
	}
	if p.Metadata["k"] != "v" {
		t.Fatal("metadata lost in projection")
	}
	if p.Timestamp != e.Timestamp.UTC().UnixMilli() {
		t.Fatal("timestamp projection mismatch")
	}
}