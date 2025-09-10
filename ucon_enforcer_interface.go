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
	"github.com/casbin/casbin/v2"
)

// IUconEnforcer is the API interface of UconEnforcer.
type IUconEnforcer interface {
	// Inherit Casbin basic functionality
	casbin.IEnforcer

	// Enhanced enforcement with session context
	EnforceWithSession(sessionID string) (*Session, error)

	// Session management
	CreateSession(sub string, act string, obj string, attributes map[string]interface{}) (string, error)
	GetSession(sessionID string) (*Session, error)
	UpdateSessionAttribute(sessionID string, key string, val interface{}) error
	RevokeSession(sessionID string) error

	// Condition evaluation
	AddCondition(condition *Condition) error
	EvaluateConditions(sessionID string) (bool, error)

	// Obligation management
	AddObligation(obligation *Obligation) error
	ExecuteObligations(sessionID string) error
	ExecuteObligationsByType(sessionID string, phase string) error

	// Continuous monitoring
	StartMonitoring(sessionID string) error
	StopMonitoring(sessionID string) error
}
