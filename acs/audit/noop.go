package audit

import (
	"context"
	"fmt"
	"sync"
)

type NoopSink struct {
	mu      sync.RWMutex
	started bool
}

func NewNoopSink() *NoopSink {
	return &NoopSink{}
}

func (s *NoopSink) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = true
	return nil
}

func (s *NoopSink) Emit(_ context.Context, _ string, _ any) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.started {
		return fmt.Errorf("audit sink is not started")
	}
	return nil
}

func (s *NoopSink) Healthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.started
}

func (s *NoopSink) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = false
	return nil
}
