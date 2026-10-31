// Package ratelimit is an in-memory token bucket per key (hub, device, IP).
package ratelimit

import (
	"sync"
	"time"
)

// Limiter allows perMinute events per key, with bursts up to burst.
// A perMinute of 0 or less turns the limit off.
type Limiter struct {
	rate  float64 // tokens per second
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func New(perMinute, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:    float64(perMinute) / 60,
		burst:   float64(burst),
		now:     time.Now,
		buckets: map[string]*bucket{},
	}
}

// Allow takes n tokens from key's bucket. It returns false, and takes
// nothing, when there are not enough.
func (l *Limiter) Allow(key string, n int) bool {
	if l == nil || l.rate <= 0 {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
		b.last = now
	}
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// Sweep drops the buckets that are full again, so memory stays small.
func (l *Limiter) Sweep() {
	if l == nil || l.rate <= 0 {
		return
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// Len is the number of buckets kept.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
