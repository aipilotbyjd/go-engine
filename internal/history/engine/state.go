package engine

import (
	"time"

	"github.com/linkflow/engine/internal/history"
)

type MutableState struct {
	ExecutionInfo     *history.ExecutionInfo
	NextEventID       int64
	PendingActivities map[int64]*history.ActivityInfo
	PendingTimers     map[string]*history.TimerInfo
	CompletedNodes    map[string]*history.NodeResult
	BufferedEvents    []*history.HistoryEvent
	DBVersion         int64
}

func NewMutableState(info *history.ExecutionInfo) *MutableState {
	return &MutableState{
		ExecutionInfo:     info,
		NextEventID:       1,
		PendingActivities: make(map[int64]*history.ActivityInfo),
		PendingTimers:     make(map[string]*history.TimerInfo),
		CompletedNodes:    make(map[string]*history.NodeResult),
		BufferedEvents:    make([]*history.HistoryEvent, 0),
		DBVersion:         0,
	}
}

func (ms *MutableState) Clone() *MutableState {
	clone := &MutableState{
		ExecutionInfo:     ms.cloneExecutionInfo(),
		NextEventID:       ms.NextEventID,
		PendingActivities: make(map[int64]*history.ActivityInfo, len(ms.PendingActivities)),
		PendingTimers:     make(map[string]*history.TimerInfo, len(ms.PendingTimers)),
		CompletedNodes:    make(map[string]*history.NodeResult, len(ms.CompletedNodes)),
		BufferedEvents:    make([]*history.HistoryEvent, len(ms.BufferedEvents)),
		DBVersion:         ms.DBVersion,
	}

	for k, v := range ms.PendingActivities {
		clone.PendingActivities[k] = ms.cloneActivityInfo(v)
	}
	for k, v := range ms.PendingTimers {
		clone.PendingTimers[k] = ms.cloneTimerInfo(v)
	}
	for k, v := range ms.CompletedNodes {
		clone.CompletedNodes[k] = ms.cloneNodeResult(v)
	}
	copy(clone.BufferedEvents, ms.BufferedEvents)

	return clone
}

func (ms *MutableState) cloneExecutionInfo() *history.ExecutionInfo {
	if ms.ExecutionInfo == nil {
		return nil
	}
	info := *ms.ExecutionInfo
	if ms.ExecutionInfo.Input != nil {
		info.Input = make([]byte, len(ms.ExecutionInfo.Input))
		copy(info.Input, ms.ExecutionInfo.Input)
	}
	return &info
}

func (ms *MutableState) cloneActivityInfo(ai *history.ActivityInfo) *history.ActivityInfo {
	if ai == nil {
		return nil
	}
	clone := *ai
	if ai.Input != nil {
		clone.Input = make([]byte, len(ai.Input))
		copy(clone.Input, ai.Input)
	}
	if ai.HeartbeatDetails != nil {
		clone.HeartbeatDetails = make([]byte, len(ai.HeartbeatDetails))
		copy(clone.HeartbeatDetails, ai.HeartbeatDetails)
	}
	return &clone
}

func (ms *MutableState) cloneTimerInfo(ti *history.TimerInfo) *history.TimerInfo {
	if ti == nil {
		return nil
	}
	clone := *ti
	return &clone
}

func (ms *MutableState) cloneNodeResult(nr *history.NodeResult) *history.NodeResult {
	if nr == nil {
		return nil
	}
	clone := *nr
	if nr.Output != nil {
		clone.Output = make([]byte, len(nr.Output))
		copy(clone.Output, nr.Output)
	}
	if nr.FailureDetails != nil {
		clone.FailureDetails = make([]byte, len(nr.FailureDetails))
		copy(clone.FailureDetails, nr.FailureDetails)
	}
	return &clone
}

func (ms *MutableState) ApplyEvent(event *history.HistoryEvent) error {
	switch event.EventType {
	case history.EventTypeExecutionStarted:
		return ms.applyExecutionStarted(event)
	case history.EventTypeExecutionCompleted:
		return ms.applyExecutionCompleted(event)
	case history.EventTypeExecutionFailed:
		return ms.applyExecutionFailed(event)
	case history.EventTypeExecutionTerminated:
		return ms.applyExecutionTerminated(event)
	case history.EventTypeNodeScheduled:
		return ms.applyNodeScheduled(event)
	case history.EventTypeNodeCompleted:
		return ms.applyNodeCompleted(event)
	case history.EventTypeNodeFailed:
		return ms.applyNodeFailed(event)
	case history.EventTypeTimerStarted:
		return ms.applyTimerStarted(event)
	case history.EventTypeTimerFired:
		return ms.applyTimerFired(event)
	case history.EventTypeTimerCanceled:
		return ms.applyTimerCanceled(event)
	case history.EventTypeActivityScheduled:
		return ms.applyActivityScheduled(event)
	case history.EventTypeActivityStarted:
		return ms.applyActivityStarted(event)
	case history.EventTypeActivityCompleted:
		return ms.applyActivityCompleted(event)
	case history.EventTypeActivityFailed:
		return ms.applyActivityFailed(event)
	}

	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyExecutionStarted(event *history.HistoryEvent) error {
	attrs, ok := event.Attributes.(*history.ExecutionStartedAttributes)
	if !ok {
		return nil
	}
	ms.ExecutionInfo.WorkflowTypeName = attrs.WorkflowType
	ms.ExecutionInfo.TaskQueue = attrs.TaskQueue
	ms.ExecutionInfo.Input = attrs.Input
	ms.ExecutionInfo.ExecutionTimeout = attrs.ExecutionTimeout
	ms.ExecutionInfo.RunTimeout = attrs.RunTimeout
	ms.ExecutionInfo.TaskTimeout = attrs.TaskTimeout
	ms.ExecutionInfo.Status = history.ExecutionStatusRunning
	ms.ExecutionInfo.StartTime = event.Timestamp
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyExecutionCompleted(event *history.HistoryEvent) error {
	ms.ExecutionInfo.Status = history.ExecutionStatusCompleted
	ms.ExecutionInfo.CloseTime = event.Timestamp
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyExecutionFailed(event *history.HistoryEvent) error {
	ms.ExecutionInfo.Status = history.ExecutionStatusFailed
	ms.ExecutionInfo.CloseTime = event.Timestamp
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyExecutionTerminated(event *history.HistoryEvent) error {
	ms.ExecutionInfo.Status = history.ExecutionStatusTerminated
	ms.ExecutionInfo.CloseTime = event.Timestamp
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyNodeScheduled(event *history.HistoryEvent) error {
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyNodeCompleted(event *history.HistoryEvent) error {
	attrs, ok := event.Attributes.(*history.NodeCompletedAttributes)
	if !ok {
		return nil
	}
	ms.CompletedNodes[attrs.NodeID] = &history.NodeResult{
		NodeID:        attrs.NodeID,
		CompletedTime: event.Timestamp,
		Output:        attrs.Result,
	}
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyNodeFailed(event *history.HistoryEvent) error {
	attrs, ok := event.Attributes.(*history.NodeFailedAttributes)
	if !ok {
		return nil
	}
	ms.CompletedNodes[attrs.NodeID] = &history.NodeResult{
		NodeID:         attrs.NodeID,
		CompletedTime:  event.Timestamp,
		FailureReason:  attrs.Reason,
		FailureDetails: attrs.Details,
	}
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyTimerStarted(event *history.HistoryEvent) error {
	attrs, ok := event.Attributes.(*history.TimerStartedAttributes)
	if !ok {
		return nil
	}
	ms.PendingTimers[attrs.TimerID] = &history.TimerInfo{
		TimerID:        attrs.TimerID,
		StartedEventID: event.EventID,
		FireTime:       event.Timestamp.Add(attrs.StartToFire),
		ExpiryTime:     event.Timestamp.Add(attrs.StartToFire),
	}
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyTimerFired(event *history.HistoryEvent) error {
	attrs, ok := event.Attributes.(*history.TimerFiredAttributes)
	if !ok {
		return nil
	}
	delete(ms.PendingTimers, attrs.TimerID)
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyTimerCanceled(event *history.HistoryEvent) error {
	attrs, ok := event.Attributes.(*history.TimerCanceledAttributes)
	if !ok {
		return nil
	}
	delete(ms.PendingTimers, attrs.TimerID)
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyActivityScheduled(event *history.HistoryEvent) error {
	attrs, ok := event.Attributes.(*history.ActivityScheduledAttributes)
	if !ok {
		return nil
	}
	ms.PendingActivities[event.EventID] = &history.ActivityInfo{
		ScheduledEventID: event.EventID,
		ActivityID:       attrs.ActivityID,
		ActivityType:     attrs.ActivityType,
		TaskQueue:        attrs.TaskQueue,
		Input:            attrs.Input,
		ScheduledTime:    event.Timestamp,
		HeartbeatTimeout: attrs.HeartbeatTimeout,
		ScheduleTimeout:  attrs.ScheduleToClose,
		StartToClose:     attrs.StartToClose,
	}
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyActivityStarted(event *history.HistoryEvent) error {
	attrs, ok := event.Attributes.(*history.ActivityStartedAttributes)
	if !ok {
		return nil
	}
	if ai, exists := ms.PendingActivities[attrs.ScheduledEventID]; exists {
		ai.StartedEventID = event.EventID
		ai.StartedTime = event.Timestamp
		ai.Attempt = attrs.Attempt
	}
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyActivityCompleted(event *history.HistoryEvent) error {
	attrs, ok := event.Attributes.(*history.ActivityCompletedAttributes)
	if !ok {
		return nil
	}
	delete(ms.PendingActivities, attrs.ScheduledEventID)
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) applyActivityFailed(event *history.HistoryEvent) error {
	attrs, ok := event.Attributes.(*history.ActivityFailedAttributes)
	if !ok {
		return nil
	}
	delete(ms.PendingActivities, attrs.ScheduledEventID)
	ms.NextEventID = event.EventID + 1
	return nil
}

func (ms *MutableState) AddPendingActivity(scheduledEventID int64, info *history.ActivityInfo) {
	ms.PendingActivities[scheduledEventID] = info
}

func (ms *MutableState) GetPendingActivity(scheduledEventID int64) (*history.ActivityInfo, bool) {
	info, ok := ms.PendingActivities[scheduledEventID]
	return info, ok
}

func (ms *MutableState) DeletePendingActivity(scheduledEventID int64) {
	delete(ms.PendingActivities, scheduledEventID)
}

func (ms *MutableState) AddPendingTimer(timerID string, info *history.TimerInfo) {
	ms.PendingTimers[timerID] = info
}

func (ms *MutableState) GetPendingTimer(timerID string) (*history.TimerInfo, bool) {
	info, ok := ms.PendingTimers[timerID]
	return info, ok
}

func (ms *MutableState) DeletePendingTimer(timerID string) {
	delete(ms.PendingTimers, timerID)
}

func (ms *MutableState) AddCompletedNode(nodeID string, result *history.NodeResult) {
	ms.CompletedNodes[nodeID] = result
}

func (ms *MutableState) GetCompletedNode(nodeID string) (*history.NodeResult, bool) {
	result, ok := ms.CompletedNodes[nodeID]
	return result, ok
}

func (ms *MutableState) AddBufferedEvent(event *history.HistoryEvent) {
	ms.BufferedEvents = append(ms.BufferedEvents, event)
}

func (ms *MutableState) ClearBufferedEvents() {
	ms.BufferedEvents = ms.BufferedEvents[:0]
}

func (ms *MutableState) GetNextEventID() int64 {
	return ms.NextEventID
}

func (ms *MutableState) IncrementNextEventID() int64 {
	id := ms.NextEventID
	ms.NextEventID++
	return id
}

func (ms *MutableState) IsWorkflowExecutionRunning() bool {
	return ms.ExecutionInfo != nil && ms.ExecutionInfo.Status == history.ExecutionStatusRunning
}

func (ms *MutableState) GetStartTime() time.Time {
	if ms.ExecutionInfo == nil {
		return time.Time{}
	}
	return ms.ExecutionInfo.StartTime
}

func (ms *MutableState) GetCloseTime() time.Time {
	if ms.ExecutionInfo == nil {
		return time.Time{}
	}
	return ms.ExecutionInfo.CloseTime
}
