package scanner

import (
	"sync"
	"time"
)

const (
	defaultMaxPPS        = 1000
	defaultMinDelay      = 5 * time.Millisecond
	maxAdaptiveDelay     = 500 * time.Millisecond
	lossPenaltyFactor    = 10.0
	rttHighWatermark     = 1 * time.Second
	rttCriticalWatermark = 2 * time.Second
)

// Pacer adaptively throttles probe launches to stay under a packets-per-second
// budget while moving as fast as the network tolerates. Concurrency is bounded
// by a fixed-capacity slot semaphore; the adaptive delay between launches
// effectively shrinks in-flight concurrency when RTT is high or loss is
// elevated, so the worker pool self-constrains without a resizable channel.
type Pacer struct {
	slots    chan struct{}
	base     time.Duration // nominal delay implied by maxPPS
	maxDelay time.Duration
	adaptive bool

	mu      sync.Mutex
	ewmaRTT time.Duration
	loss    float64 // EWMA of the timed-out fraction, 0..1
	samples uint64
}

// NewPacer returns a Pacer budgeting at most maxPPS launches per second with a
// semaphore of at most concurrency in-flight probes. When adaptive is true the
// budget is relaxed/restrained based on observed RTT and loss.
func NewPacer(maxPPS, concurrency int, adaptive bool) *Pacer {
	if maxPPS <= 0 {
		maxPPS = defaultMaxPPS
	}
	if concurrency <= 0 {
		concurrency = 256
	}
	base := time.Second / time.Duration(maxPPS)
	if base < defaultMinDelay {
		base = defaultMinDelay
	}
	return &Pacer{
		slots:    make(chan struct{}, concurrency),
		base:     base,
		maxDelay: maxAdaptiveDelay,
		adaptive: adaptive,
	}
}

// Slots is the concurrency semaphore; producers acquire before launching and
// consumers release after a probe completes.
func (p *Pacer) Slots() chan struct{} {
	return p.slots
}

// Delay blocks for the current admission interval. Call it before each probe
// launch to keep the sustained rate within budget.
func (p *Pacer) Delay() {
	time.Sleep(p.currentInterval())
}

// Observe feeds a single probe outcome back into the adaptive model. timedOut
// marks probes that produced no response (loss signal); very slow probes raise
// the inferred RTT.
func (p *Pacer) Observe(rtt time.Duration, timedOut bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.samples++
	if p.ewmaRTT == 0 {
		p.ewmaRTT = rtt
	} else {
		p.ewmaRTT = (p.ewmaRTT*3 + rtt) / 4
	}
	if timedOut {
		p.loss = p.loss*0.9 + 0.1
	} else {
		p.loss *= 0.9
	}
}

// currentInterval computes the admission interval based on the current
// network health. Returns the base interval when adaptive pacing is disabled.
func (p *Pacer) currentInterval() time.Duration {
	if !p.adaptive {
		return p.base
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	// loss>~5% drives the interval up sharply; rtt>~1s adds a fixed surcharge.
	factor := 1.0
	if p.loss > 0.05 {
		factor += p.loss * lossPenaltyFactor
	}
	if p.ewmaRTT > 0 {
		switch {
		case p.ewmaRTT > rttCriticalWatermark:
			factor += 2.0
		case p.ewmaRTT > rttHighWatermark:
			factor += 1.0
		}
	}
	interval := time.Duration(float64(p.base) * factor)
	if interval > p.maxDelay {
		return p.maxDelay
	}
	return interval
}
