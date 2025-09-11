// Copyright 2025 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ucon

import (
	"fmt"
	"sync"
	"time"
)

type Session struct {
	id      string
	subject string
	action  string
	object  string

	attributes map[string]interface{}
	active     bool
	startTime  time.Time
	endTime    time.Time
	stopReason string

	mutex sync.RWMutex
}

const (
	NormalStopReason = ""
)

func (s *Session) GetId() string {
	return s.id
}

func (s *Session) GetSubject() string {
	return s.subject
}

func (s *Session) GetAction() string {
	return s.action
}

func (s *Session) GetObject() string {
	return s.object
}

func (s *Session) GetAttribute(key string) interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.attributes[key]
}

func (s *Session) UpdateAttribute(key string, val interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.attributes[key] = val
	return nil
}

func (s *Session) Stop(reason string) error {
	s.mutex.Lock()
	if !s.active {
		s.mutex.Unlock()
		return fmt.Errorf("session already stopped")
	}

	s.active = false
	s.endTime = time.Now()
	s.stopReason = reason
	s.mutex.Unlock()
	return nil
}

func (s *Session) IfActive() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.active
}

func (s *Session) GetStopReason() string {
	return s.stopReason
}

func (s *Session) GetStartTime() time.Time {
	return s.startTime
}

func (s *Session) GetEndTime() time.Time {
	return s.endTime
}

func (s *Session) GetDuration() time.Duration {
	if s.active {
		return time.Since(s.startTime)
	}
	return s.endTime.Sub(s.startTime)
}

type SessionManager struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		mutex:    sync.RWMutex{},
	}
}

func (sm *SessionManager) GetSessionById(id string) (*Session, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	s, exists := sm.sessions[id]
	if !exists {
		return nil, fmt.Errorf("cannot find session with id %s", id)
	}
	return s, nil
}

func (sm *SessionManager) CreateSession(sub string, act string, obj string, attributes map[string]interface{}) (string, error) {
	sessionID := fmt.Sprintf("session_%d", time.Now().UnixNano())
	session := &Session{
		id:         sessionID,
		subject:    sub,
		action:     act,
		object:     obj,
		active:     true,
		attributes: attributes,
		startTime:  time.Now(),
		mutex:      sync.RWMutex{},
	}

	sm.mutex.Lock()
	sm.sessions[sessionID] = session
	sm.mutex.Unlock()
	return sessionID, nil
}

func (sm *SessionManager) UpdateSessionAttribute(sessionID string, key string, val interface{}) error {
	session, err := sm.GetSessionById(sessionID)
	if err != nil {
		return err
	}
	if err := session.UpdateAttribute(key, val); err != nil {
		return err
	}
	return nil
}

func (sm *SessionManager) DeleteSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	delete(sm.sessions, sessionID)
	return nil
}
