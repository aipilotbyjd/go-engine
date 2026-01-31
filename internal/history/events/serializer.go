package events

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/linkflow/engine/internal/history"
)

func init() {
	gob.Register(&history.ExecutionStartedAttributes{})
	gob.Register(&history.ExecutionCompletedAttributes{})
	gob.Register(&history.ExecutionFailedAttributes{})
	gob.Register(&history.ExecutionTerminatedAttributes{})
	gob.Register(&history.NodeScheduledAttributes{})
	gob.Register(&history.NodeStartedAttributes{})
	gob.Register(&history.NodeCompletedAttributes{})
	gob.Register(&history.NodeFailedAttributes{})
	gob.Register(&history.TimerStartedAttributes{})
	gob.Register(&history.TimerFiredAttributes{})
	gob.Register(&history.TimerCanceledAttributes{})
	gob.Register(&history.ActivityScheduledAttributes{})
	gob.Register(&history.ActivityStartedAttributes{})
	gob.Register(&history.ActivityCompletedAttributes{})
	gob.Register(&history.ActivityFailedAttributes{})
	gob.Register(&history.SignalReceivedAttributes{})
	gob.Register(&history.MarkerRecordedAttributes{})
	gob.Register(&history.ExecutionKey{})
	gob.Register(&history.RetryPolicy{})
}

type EncodingType int

const (
	EncodingTypeJSON EncodingType = iota
	EncodingTypeGob
)

const currentSerializerVersion = 1

type Serializer struct {
	encoding EncodingType
}

func NewSerializer(encoding EncodingType) *Serializer {
	return &Serializer{
		encoding: encoding,
	}
}

func NewJSONSerializer() *Serializer {
	return NewSerializer(EncodingTypeJSON)
}

func NewGobSerializer() *Serializer {
	return NewSerializer(EncodingTypeGob)
}

type serializedEvent struct {
	Version    int                    `json:"v"`
	EventID    int64                  `json:"event_id"`
	EventType  int32                  `json:"event_type"`
	Timestamp  int64                  `json:"timestamp"`
	EvtVersion int64                  `json:"evt_version"`
	TaskID     int64                  `json:"task_id"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

func (s *Serializer) Serialize(event *history.HistoryEvent) ([]byte, error) {
	if event == nil {
		return nil, errors.New("cannot serialize nil event")
	}

	switch s.encoding {
	case EncodingTypeJSON:
		return s.serializeJSON(event)
	case EncodingTypeGob:
		return s.serializeGob(event)
	default:
		return nil, fmt.Errorf("unsupported encoding type: %d", s.encoding)
	}
}

func (s *Serializer) serializeJSON(event *history.HistoryEvent) ([]byte, error) {
	se := serializedEvent{
		Version:    currentSerializerVersion,
		EventID:    event.EventID,
		EventType:  int32(event.EventType),
		Timestamp:  event.Timestamp.UnixNano(),
		EvtVersion: event.Version,
		TaskID:     event.TaskID,
	}

	if event.Attributes != nil {
		attrBytes, err := json.Marshal(event.Attributes)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attributes: %w", err)
		}
		var attrMap map[string]interface{}
		if err := json.Unmarshal(attrBytes, &attrMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attributes to map: %w", err)
		}
		se.Attributes = attrMap
	}

	return json.Marshal(se)
}

func (s *Serializer) serializeGob(event *history.HistoryEvent) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(byte(currentSerializerVersion))
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(event); err != nil {
		return nil, fmt.Errorf("failed to gob encode event: %w", err)
	}
	return buf.Bytes(), nil
}

func (s *Serializer) Deserialize(data []byte) (*history.HistoryEvent, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot deserialize empty data")
	}

	switch s.encoding {
	case EncodingTypeJSON:
		return s.deserializeJSON(data)
	case EncodingTypeGob:
		return s.deserializeGob(data)
	default:
		return nil, fmt.Errorf("unsupported encoding type: %d", s.encoding)
	}
}

func (s *Serializer) deserializeJSON(data []byte) (*history.HistoryEvent, error) {
	var se serializedEvent
	if err := json.Unmarshal(data, &se); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}

	event := &history.HistoryEvent{
		EventID:   se.EventID,
		EventType: history.EventType(se.EventType),
		Version:   se.EvtVersion,
		TaskID:    se.TaskID,
	}
	event.Timestamp = event.Timestamp.Add(0)

	if se.Attributes != nil {
		attrs, err := s.deserializeAttributes(history.EventType(se.EventType), se.Attributes)
		if err != nil {
			return nil, err
		}
		event.Attributes = attrs
	}

	return event, nil
}

func (s *Serializer) deserializeAttributes(eventType history.EventType, attrMap map[string]interface{}) (any, error) {
	attrBytes, err := json.Marshal(attrMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attribute map: %w", err)
	}

	var attrs any
	switch eventType {
	case history.EventTypeExecutionStarted:
		attrs = &history.ExecutionStartedAttributes{}
	case history.EventTypeExecutionCompleted:
		attrs = &history.ExecutionCompletedAttributes{}
	case history.EventTypeExecutionFailed:
		attrs = &history.ExecutionFailedAttributes{}
	case history.EventTypeExecutionTerminated:
		attrs = &history.ExecutionTerminatedAttributes{}
	case history.EventTypeNodeScheduled:
		attrs = &history.NodeScheduledAttributes{}
	case history.EventTypeNodeStarted:
		attrs = &history.NodeStartedAttributes{}
	case history.EventTypeNodeCompleted:
		attrs = &history.NodeCompletedAttributes{}
	case history.EventTypeNodeFailed:
		attrs = &history.NodeFailedAttributes{}
	case history.EventTypeTimerStarted:
		attrs = &history.TimerStartedAttributes{}
	case history.EventTypeTimerFired:
		attrs = &history.TimerFiredAttributes{}
	case history.EventTypeTimerCanceled:
		attrs = &history.TimerCanceledAttributes{}
	case history.EventTypeActivityScheduled:
		attrs = &history.ActivityScheduledAttributes{}
	case history.EventTypeActivityStarted:
		attrs = &history.ActivityStartedAttributes{}
	case history.EventTypeActivityCompleted:
		attrs = &history.ActivityCompletedAttributes{}
	case history.EventTypeActivityFailed:
		attrs = &history.ActivityFailedAttributes{}
	case history.EventTypeSignalReceived:
		attrs = &history.SignalReceivedAttributes{}
	case history.EventTypeMarkerRecorded:
		attrs = &history.MarkerRecordedAttributes{}
	default:
		return attrMap, nil
	}

	if err := json.Unmarshal(attrBytes, attrs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attributes for event type %s: %w", eventType, err)
	}

	return attrs, nil
}

func (s *Serializer) deserializeGob(data []byte) (*history.HistoryEvent, error) {
	if len(data) < 2 {
		return nil, errors.New("gob data too short")
	}

	buf := bytes.NewBuffer(data[1:])
	dec := gob.NewDecoder(buf)

	var event history.HistoryEvent
	if err := dec.Decode(&event); err != nil {
		return nil, fmt.Errorf("failed to gob decode event: %w", err)
	}

	return &event, nil
}

func (s *Serializer) SerializeEvents(events []*history.HistoryEvent) ([][]byte, error) {
	result := make([][]byte, len(events))
	for i, event := range events {
		data, err := s.Serialize(event)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize event %d: %w", event.EventID, err)
		}
		result[i] = data
	}
	return result, nil
}

func (s *Serializer) DeserializeEvents(dataList [][]byte) ([]*history.HistoryEvent, error) {
	result := make([]*history.HistoryEvent, len(dataList))
	for i, data := range dataList {
		event, err := s.Deserialize(data)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize event at index %d: %w", i, err)
		}
		result[i] = event
	}
	return result, nil
}
