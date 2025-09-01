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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
)

// UconEnforcer UCON enforcer that wraps casbin.Enforcer and extends UCON functionality.
type UconEnforcer struct {
	*casbin.Enforcer // Embed casbin.Enforcer for backward compatibility
	sessions         map[string]Session
	conditions       map[string]Condition
	obligations      map[string]Obligation
	monitoringActive map[string]bool // Track which sessions are being monitored
	mu               sync.RWMutex
}

type Session struct {
	ID      string
	Subject string
	Action  string
	Object  string

	Attributes map[string]interface{}
	Active     bool
	StartTime  time.Time
	EndTime    time.Time
}

type Condition struct {
	ID   string
	Name string
	Kind string // "one", "always"
	Expr string
}

type Obligation struct {
	ID   string
	Name string
	Kind string // "pre", "post", "ongoing"
	Expr string
}

// NewUconEnforcer creates a new UCON enforcer.
func NewUconEnforcer(e *casbin.Enforcer) IUconEnforcer {
	return &UconEnforcer{
		Enforcer:         e,
		sessions:         make(map[string]Session),
		conditions:       make(map[string]Condition),
		obligations:      make(map[string]Obligation),
		monitoringActive: make(map[string]bool),
	}
}

// EnforceWithSession performs enforcement with session context.
func (u *UconEnforcer) EnforceWithSession(sessionID string) (bool, error) {
	// Get session information
	session, err := u.GetSession(sessionID)
	if err != nil {
		return false, err
	}

	// Check if session is active
	if !session.Active {
		return false, errors.New("session is not active")
	}

	// 1. Evaluate conditions first
	conditionsOk, err := u.EvaluateConditions(sessionID)
	if err != nil {
		return false, err
	}
	if !conditionsOk {
		return false, nil
	}

	// 2. Execute pre-access obligations (访问前义务)
	err = u.ExecuteObligationsByType(sessionID, "pre")
	if err != nil {
		// Pre-access obligations failure should deny access
		fmt.Printf("Error: Failed to execute pre-access obligations: %v\n", err)
		return false, err
	}

	// 3. Perform basic Casbin policy enforcement
	ok, err := u.Enforce(session.Subject, session.Object, session.Action)
	if err != nil {
		return false, err
	}

	// 4. Start monitoring if access is granted
	if ok {
		// Start monitoring for ongoing obligations
		_ = u.StartMonitoring(sessionID)
	}
	return ok, nil
}

// CreateSession creates a new session.
func (u *UconEnforcer) CreateSession(sub string, act string, obj string, attributes map[string]interface{}) (string, error) {
	// Generate session ID
	sessionID := fmt.Sprintf("session_%d", time.Now().UnixNano())

	// Create session
	session := Session{
		ID:         sessionID,
		Subject:    sub,
		Action:     act,
		Object:     obj,
		Active:     true,
		Attributes: attributes,
		StartTime:  time.Now(),
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.sessions[sessionID] = session
	return sessionID, nil
}

// GetSession retrieves session information.
func (u *UconEnforcer) GetSession(sessionID string) (*Session, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	session, exists := u.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}
	return &session, nil
}

func (u *UconEnforcer) UpdateSessionAttribute(sessionID string, key string, val interface{}) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	session, exists := u.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}
	session.Attributes[key] = val
	u.sessions[sessionID] = session
	return nil
}

// RevokeSession revokes a session.
func (u *UconEnforcer) RevokeSession(sessionID string) error {
	session, err := u.GetSession(sessionID)
	if err != nil {
		return err
	}

	if !session.Active {
		return errors.New("session has be closed")
	}
	session.Active = false
	session.EndTime = time.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	u.sessions[sessionID] = *session
	return nil
}

// AddCondition adds a condition.
func (u *UconEnforcer) AddCondition(condition *Condition) error {
	if condition == nil {
		return errors.New("condition cannot be nil")
	}
	u.conditions[condition.ID] = *condition
	return nil
}

// EvaluateConditions evaluates all conditions for a session.
func (u *UconEnforcer) EvaluateConditions(sessionID string) (bool, error) {
	// Get session
	session, err := u.GetSession(sessionID)
	if err != nil {
		return false, err
	}

	if len(u.conditions) == 0 {
		return true, nil
	}

	// Copy conditions to avoid holding lock during evaluation
	conditionsCopy := make([]Condition, 0, len(u.conditions))
	for _, condition := range u.conditions {
		conditionsCopy = append(conditionsCopy, condition)
	}

	// Evaluate conditions without holding the lock
	for _, condition := range conditionsCopy {
		cond := condition // Create a copy to avoid memory aliasing
		result, err := u.evaluateCondition(&cond, session)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil // Any condition fails, deny access
		}
	}
	return true, nil
}

// evaluateCondition evaluates a single condition against a session.
func (u *UconEnforcer) evaluateCondition(condition *Condition, session *Session) (bool, error) {
	switch condition.Name {
	case "location":
		return u.checkLocation(condition.Expr, session)
	case "vip_level":
		return u.checkVipLevel(condition.Expr, session)
	default:
		return false, fmt.Errorf("unknown condition type: %s", condition.Kind)
	}
}

func (u *UconEnforcer) checkLocation(expr string, session *Session) (bool, error) {
	location, ok := session.Attributes["location"].(string)
	if !ok {
		return false, errors.New("location attribute not found or not a string")
	}

	return location == expr, nil
}

func (u *UconEnforcer) checkVipLevel(expr string, session *Session) (bool, error) {
	vipLevel, ok := session.Attributes["vip_level"].(int)
	if !ok {
		return false, fmt.Errorf("vip_level attribute not found or not an integer")
	}
	requiredLevel, err := strconv.Atoi(expr)
	if err != nil {
		return false, fmt.Errorf("invalid vip_level expression: %v", err)
	}
	return vipLevel >= requiredLevel, nil
}

// AddObligation adds an obligation.
func (u *UconEnforcer) AddObligation(obligation *Obligation) error {
	if obligation == nil {
		return errors.New("obligation cannot be nil")
	}
	u.obligations[obligation.ID] = *obligation
	return nil
}

// ExecuteObligations executes all obligations for a session (backward compatibility).
func (u *UconEnforcer) ExecuteObligations(sessionID string) error {
	session, err := u.GetSession(sessionID)
	if err != nil {
		return err
	}

	for _, obligation := range u.obligations {
		obl := obligation // Create a copy to avoid memory aliasing
		err := u.executeObligation(&obl, session)
		if err != nil {
			return fmt.Errorf("failed to execute obligation %s: %v", obl.ID, err)
		}
	}

	return nil
}

// ExecuteObligationsByPhase executes obligations for a specific type.
func (u *UconEnforcer) ExecuteObligationsByType(sessionID string, kind string) error {
	session, err := u.GetSession(sessionID)
	if err != nil {
		return err
	}

	for _, obligation := range u.obligations {
		if obligation.Kind == kind {
			obl := obligation // Create a copy to avoid memory aliasing
			err := u.executeObligation(&obl, session)
			if err != nil {
				return fmt.Errorf("failed to execute %s obligation %s: %v", kind, obl.ID, err)
			}
		}
	}

	return nil
}

// executeObligation executes a single obligation.
func (u *UconEnforcer) executeObligation(obligation *Obligation, session *Session) error {
	switch obligation.Name {
	case "user_authentication":
		return u.executeUserAuthentication(obligation.Expr, session)
	case "vip_validation":
		return u.executeVipValidation(obligation.Expr, session)
	case "access_logging":
		return u.executeAccessLogging(obligation.Expr, session)
	default:
		return fmt.Errorf("unknown obligation name: %s", obligation.Name)
	}
}

func (u *UconEnforcer) executeUserAuthentication(expr string, session *Session) error {
	parts := strings.Split(expr, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid expression format: %s, expected 'key:value'", expr)
	}
	key := strings.TrimSpace(parts[0])
	expectedValue := strings.TrimSpace(parts[1])

	actualValue := session.Attributes[key]
	if actualValue != expectedValue {
		return fmt.Errorf("user %s authentication failed: %s (expected: %s, actual: %s)",
			session.Subject, expr, expectedValue, actualValue)
	}

	fmt.Printf("[AUTH] User %s authentication verification passed: %s\n", session.Subject, expr)
	return nil
}

func (u *UconEnforcer) executeVipValidation(expr string, session *Session) error {
	vipLevel := session.Attributes["vip_level"]
	vipExpiry := session.Attributes["vip_expiry"]

	if vipLevel == "" {
		return fmt.Errorf("user %s is not a VIP user", session.Subject)
	}

	if vipExpiry == "expired" {
		return fmt.Errorf("user %s VIP membership has expired", session.Subject)
	}

	fmt.Printf("[VIP] User %s VIP status is valid (level: %s)\n", session.Subject, vipLevel)
	return nil
}

func (u *UconEnforcer) executeAccessLogging(expr string, session *Session) error {
	fmt.Printf("[ACCESS LOG] %s: %s -> %s\n", expr, session.Subject, session.Object)
	return nil
}

// StartMonitoring starts monitoring a session.
func (u *UconEnforcer) StartMonitoring(sessionID string) error {
	// Check if session exists
	_, exists := u.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	if u.monitoringActive[sessionID] {
		return nil
	}

	u.monitoringActive[sessionID] = true
	go u.monitorSession(sessionID)

	return nil
}

// StopMonitoring stops monitoring a session.
func (u *UconEnforcer) StopMonitoring(sessionID string) error {
	session, err := u.GetSession(sessionID)
	if err != nil {
		return err
	}

	if err := u.ExecuteObligationsByType(sessionID, "post"); err != nil {
		fmt.Printf("Warning: Failed to execute post-access obligations during session revocation: %v\n", err)
	}

	if err := u.RevokeSession(sessionID); err != nil {
		fmt.Printf("Warning: Failed to revoke session: %v\n", err)
	}

	fmt.Printf("[MONITOR] Stopped monitoring session %s for %s\n", sessionID, session.Subject)
	return nil
}

// monitorSession continuously monitors a session.
func (u *UconEnforcer) monitorSession(sessionID string) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		// Check if monitoring is still active
		isActive := u.monitoringActive[sessionID]
		if !isActive {
			return
		}

		session, err := u.GetSession(sessionID)
		if err != nil {
			fmt.Printf("[MONITOR] Error getting session %s: %v\n", sessionID, err)
			u.monitoringActive[sessionID] = false
			return
		}
		if !session.Active {
			u.monitoringActive[sessionID] = false
			return
		}

		// Check conditions during ongoing access
		conditionsOk, err := u.EvaluateConditions(sessionID)
		if err != nil {
			fmt.Printf("[MONITOR] Error evaluating conditions for session %s: %v\n", sessionID, err)
			continue
		}

		if !conditionsOk {
			fmt.Printf("[MONITOR] Conditions no longer met for session %s, revoking...\n", sessionID)
			revokeErr := u.RevokeSession(sessionID)
			if revokeErr != nil {
				fmt.Printf("[MONITOR] Error revoking session %s: %v\n", sessionID, revokeErr)
			}
			u.monitoringActive[sessionID] = false
			return
		}

		// Execute ongoing obligations during continuous authorization
		err = u.ExecuteObligationsByType(sessionID, "ongoing")
		if err != nil {
			fmt.Printf("[MONITOR] Warning: Failed to execute ongoing obligations for session %s: %v\n", sessionID, err)
			// Continue monitoring even if ongoing obligations fail
		}

		fmt.Printf("[MONITOR] Session %s is still valid\n", sessionID)
	}
}
