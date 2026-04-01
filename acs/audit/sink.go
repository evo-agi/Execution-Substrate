package audit

import "context"

type Sink interface {
	Start(ctx context.Context) error
	Emit(ctx context.Context, eventType string, payload any) error
	Healthy() bool
	Close(ctx context.Context) error
}
