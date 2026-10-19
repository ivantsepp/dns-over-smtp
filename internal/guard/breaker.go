package guard

import (
	"sync"
	"time"
)

// Breaker pauses an unhealthy dependency after five consecutive failures.
type Breaker struct {
	mu       sync.Mutex
	failures int
	until    time.Time
}

func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !time.Now().Before(b.until)
}

func (b *Breaker) Record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.failures = 0
		b.until = time.Time{}
		return
	}
	b.failures++
	if b.failures >= 5 {
		b.until = time.Now().Add(30 * time.Second)
	}
}
