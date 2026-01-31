package store

import (
	"context"

	"github.com/linkflow/engine/internal/history"
	"github.com/linkflow/engine/internal/history/engine"
)

type EventStore interface {
	AppendEvents(ctx context.Context, key history.ExecutionKey, events []*history.HistoryEvent, expectedVersion int64) error
	GetEvents(ctx context.Context, key history.ExecutionKey, firstEventID, lastEventID int64) ([]*history.HistoryEvent, error)
}

type MutableStateStore interface {
	GetMutableState(ctx context.Context, key history.ExecutionKey) (*engine.MutableState, error)
	UpdateMutableState(ctx context.Context, key history.ExecutionKey, state *engine.MutableState, expectedVersion int64) error
}
