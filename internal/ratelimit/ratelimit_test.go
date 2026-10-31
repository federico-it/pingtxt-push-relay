package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(60, 3) // 1 per second
	l.now = func() time.Time { return now }

	for i := range 3 {
		if !l.Allow("a", 1) {
			t.Fatalf("event %d refused", i)
		}
	}
	if l.Allow("a", 1) {
		t.Fatal("burst exceeded")
	}
	if !l.Allow("b", 1) {
		t.Fatal("other key refused")
	}
	now = now.Add(time.Second)
	if !l.Allow("a", 1) || l.Allow("a", 1) {
		t.Fatal("refill wrong")
	}
	if l.Allow("c", 4) {
		t.Fatal("n above burst allowed")
	}

	now = now.Add(time.Minute)
	l.Sweep()
	if l.Len() != 0 {
		t.Fatalf("%d buckets after sweep", l.Len())
	}
}

func TestLimiterOff(t *testing.T) {
	l := New(0, 0)
	for range 1000 {
		if !l.Allow("a", 5) {
			t.Fatal("refused with limit off")
		}
	}
}
