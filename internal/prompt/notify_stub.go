package prompt

import (
	"context"
	"errors"
)

// StaticNotifier returns a fixed action — useful for tests.
type StaticNotifier struct {
	A   Action
	Err error
}

func (s *StaticNotifier) Notify(ctx context.Context, _ Request) (Action, error) {
	if s.Err != nil {
		return ActionDeny, s.Err
	}
	return s.A, nil
}

// TimeoutNotifier never returns; useful for testing the Decider's timeout path.
type TimeoutNotifier struct{}

func (TimeoutNotifier) Notify(ctx context.Context, _ Request) (Action, error) {
	<-ctx.Done()
	return ActionDeny, errors.New("timeout: default-deny")
}
