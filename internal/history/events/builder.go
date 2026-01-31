package events

import (
	"time"

	"github.com/linkflow/engine/internal/history"
)

type EventBuilder struct {
	namespaceID string
	workflowID  string
	runID       string
	version     int64
	taskID      int64
}

func NewEventBuilder(namespaceID, workflowID, runID string) *EventBuilder {
	return &EventBuilder{
		namespaceID: namespaceID,
		workflowID:  workflowID,
		runID:       runID,
		version:     1,
		taskID:      0,
	}
}

func (b *EventBuilder) WithVersion(version int64) *EventBuilder {
	b.version = version
	return b
}

func (b *EventBuilder) WithTaskID(taskID int64) *EventBuilder {
	b.taskID = taskID
	return b
}

func (b *EventBuilder) newEvent(eventID int64, eventType history.EventType, attrs any) *history.HistoryEvent {
	return &history.HistoryEvent{
		EventID:    eventID,
		EventType:  eventType,
		Timestamp:  time.Now(),
		Version:    b.version,
		TaskID:     b.taskID,
		Attributes: attrs,
	}
}

func (b *EventBuilder) BuildExecutionStarted(
	eventID int64,
	workflowType, taskQueue string,
	input []byte,
	executionTimeout, runTimeout, taskTimeout time.Duration,
	parentExecution *history.ExecutionKey,
	initiator string,
) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeExecutionStarted, &history.ExecutionStartedAttributes{
		WorkflowType:     workflowType,
		TaskQueue:        taskQueue,
		Input:            input,
		ExecutionTimeout: executionTimeout,
		RunTimeout:       runTimeout,
		TaskTimeout:      taskTimeout,
		ParentExecution:  parentExecution,
		Initiator:        initiator,
	})
}

func (b *EventBuilder) BuildExecutionCompleted(eventID int64, result []byte) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeExecutionCompleted, &history.ExecutionCompletedAttributes{
		Result: result,
	})
}

func (b *EventBuilder) BuildExecutionFailed(eventID int64, reason string, details []byte) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeExecutionFailed, &history.ExecutionFailedAttributes{
		Reason:  reason,
		Details: details,
	})
}

func (b *EventBuilder) BuildExecutionTerminated(eventID int64, reason, identity string) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeExecutionTerminated, &history.ExecutionTerminatedAttributes{
		Reason:   reason,
		Identity: identity,
	})
}

func (b *EventBuilder) BuildNodeScheduled(eventID int64, nodeID, nodeType string, input []byte, taskQueue string) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeNodeScheduled, &history.NodeScheduledAttributes{
		NodeID:    nodeID,
		NodeType:  nodeType,
		Input:     input,
		TaskQueue: taskQueue,
	})
}

func (b *EventBuilder) BuildNodeStarted(eventID int64, nodeID string, scheduledEventID int64, identity string) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeNodeStarted, &history.NodeStartedAttributes{
		NodeID:           nodeID,
		ScheduledEventID: scheduledEventID,
		Identity:         identity,
	})
}

func (b *EventBuilder) BuildNodeCompleted(eventID int64, nodeID string, scheduledEventID, startedEventID int64, result []byte) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeNodeCompleted, &history.NodeCompletedAttributes{
		NodeID:           nodeID,
		ScheduledEventID: scheduledEventID,
		StartedEventID:   startedEventID,
		Result:           result,
	})
}

func (b *EventBuilder) BuildNodeFailed(eventID int64, nodeID string, scheduledEventID, startedEventID int64, reason string, details []byte, retryState int32) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeNodeFailed, &history.NodeFailedAttributes{
		NodeID:           nodeID,
		ScheduledEventID: scheduledEventID,
		StartedEventID:   startedEventID,
		Reason:           reason,
		Details:          details,
		RetryState:       retryState,
	})
}

func (b *EventBuilder) BuildTimerStarted(eventID int64, timerID string, startToFire time.Duration) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeTimerStarted, &history.TimerStartedAttributes{
		TimerID:     timerID,
		StartToFire: startToFire,
	})
}

func (b *EventBuilder) BuildTimerFired(eventID int64, timerID string, startedEventID int64) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeTimerFired, &history.TimerFiredAttributes{
		TimerID:        timerID,
		StartedEventID: startedEventID,
	})
}

func (b *EventBuilder) BuildTimerCanceled(eventID int64, timerID string, startedEventID int64, identity string) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeTimerCanceled, &history.TimerCanceledAttributes{
		TimerID:        timerID,
		StartedEventID: startedEventID,
		Identity:       identity,
	})
}

func (b *EventBuilder) BuildActivityScheduled(
	eventID int64,
	activityID, activityType, taskQueue string,
	input []byte,
	scheduleToClose, scheduleToStart, startToClose, heartbeatTimeout time.Duration,
	retryPolicy *history.RetryPolicy,
) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeActivityScheduled, &history.ActivityScheduledAttributes{
		ActivityID:       activityID,
		ActivityType:     activityType,
		TaskQueue:        taskQueue,
		Input:            input,
		ScheduleToClose:  scheduleToClose,
		ScheduleToStart:  scheduleToStart,
		StartToClose:     startToClose,
		HeartbeatTimeout: heartbeatTimeout,
		RetryPolicy:      retryPolicy,
	})
}

func (b *EventBuilder) BuildActivityStarted(eventID int64, scheduledEventID int64, identity string, attempt int32) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeActivityStarted, &history.ActivityStartedAttributes{
		ScheduledEventID: scheduledEventID,
		Identity:         identity,
		Attempt:          attempt,
	})
}

func (b *EventBuilder) BuildActivityCompleted(eventID int64, scheduledEventID, startedEventID int64, result []byte) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeActivityCompleted, &history.ActivityCompletedAttributes{
		ScheduledEventID: scheduledEventID,
		StartedEventID:   startedEventID,
		Result:           result,
	})
}

func (b *EventBuilder) BuildActivityFailed(eventID int64, scheduledEventID, startedEventID int64, reason string, details []byte, retryState int32) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeActivityFailed, &history.ActivityFailedAttributes{
		ScheduledEventID: scheduledEventID,
		StartedEventID:   startedEventID,
		Reason:           reason,
		Details:          details,
		RetryState:       retryState,
	})
}

func (b *EventBuilder) BuildSignalReceived(eventID int64, signalName string, input []byte, identity string) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeSignalReceived, &history.SignalReceivedAttributes{
		SignalName: signalName,
		Input:      input,
		Identity:   identity,
	})
}

func (b *EventBuilder) BuildMarkerRecorded(eventID int64, markerName string, details map[string][]byte) *history.HistoryEvent {
	return b.newEvent(eventID, history.EventTypeMarkerRecorded, &history.MarkerRecordedAttributes{
		MarkerName: markerName,
		Details:    details,
	})
}
