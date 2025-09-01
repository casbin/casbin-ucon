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
// limitations under the License.s

package ucon

import (
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

func GetUconEnforcer() IUconEnforcer {
	m := model.NewModel()
	modelText := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	m.LoadModelFromText(modelText)

	policies := [][]string{
		{"alice", "document1", "read"},
		{"alice", "document1", "write"},
		{"bob", "document1", "read"},
	}

	e, _ := casbin.NewEnforcer(m)
	e.AddPolicies(policies)
	return NewUconEnforcer(e)
}

func TestSession(t *testing.T) {
	uconE := GetUconEnforcer()

	sessionID, err := uconE.CreateSession("alice", "read", "document1", map[string]interface{}{
		"department": "engineering",
		"clearance":  "secret",
	})
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	if sessionID == "" {
		t.Fatal("Session ID should not be empty")
	}

	// Test GetSession
	session, err := uconE.GetSession(sessionID)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	if session.Subject != "alice" {
		t.Errorf("Expected subject 'alice', got '%s'", session.Subject)
	}
	if session.Action != "read" {
		t.Errorf("Expected action 'read', got '%s'", session.Action)
	}
	if session.Object != "document1" {
		t.Errorf("Expected object 'document1', got '%s'", session.Object)
	}
	if !session.Active {
		t.Error("Session should be active")
	}

	// Test RevokeSession
	err = uconE.RevokeSession(sessionID)
	if err != nil {
		t.Fatalf("Failed to revoke session: %v", err)
	}

	// Verify session is revoked
	session, err = uconE.GetSession(sessionID)
	if err != nil {
		t.Fatalf("Failed to get session after revocation: %v", err)
	}
	if session.Active {
		t.Error("Session should be inactive after revocation")
	}
}

func TestCondition(t *testing.T) {
	uconE := GetUconEnforcer()

	// Test AddCondition
	condition := &Condition{
		ID:   "test_condition",
		Name: "location",
		Kind: "one",
		Expr: "office",
	}
	err := uconE.AddCondition(condition)
	if err != nil {
		t.Fatalf("Failed to add condition: %v", err)
	}

	// Create a session for testing condition evaluation
	sessionID, _ := uconE.CreateSession("alice", "read", "document1", map[string]interface{}{
		"location": "office",
	})

	// Test EvaluateConditions
	result, err := uconE.EvaluateConditions(sessionID)
	if err != nil {
		t.Fatalf("Failed to evaluate conditions: %v", err)
	}
	if !result {
		t.Error("Expected conditions to pass")
	}
}

func TestObligation(t *testing.T) {
	uconE := GetUconEnforcer()

	// Test AddObligation
	obligation := &Obligation{
		ID:   "test_obligation",
		Name: "user_authentication",
		Kind: "pre",
		Expr: "authenticated:true",
	}
	err := uconE.AddObligation(obligation)
	if err != nil {
		t.Fatalf("Failed to add obligation: %v", err)
	}

	// Create a session for testing obligation execution
	sessionID, _ := uconE.CreateSession("alice", "read", "document1", map[string]interface{}{
		"authenticated": "true",
	})

	// Test ExecuteObligations
	err = uconE.ExecuteObligations(sessionID)
	if err != nil {
		t.Fatalf("Failed to execute obligations: %v", err)
	}

	// Test ExecuteObligationsByType
	err = uconE.ExecuteObligationsByType(sessionID, "pre")
	if err != nil {
		t.Fatalf("Failed to execute pre obligations: %v", err)
	}
}

func TestMonitoring(t *testing.T) {
	uconE := GetUconEnforcer()

	// Create a session for testing monitoring
	sessionID, _ := uconE.CreateSession("alice", "read", "document1", map[string]interface{}{
		"department": "engineering",
	})

	// Test StartMonitoring
	err := uconE.StartMonitoring(sessionID)
	if err != nil {
		t.Fatalf("Failed to start monitoring: %v", err)
	}

	// Test StopMonitoring
	err = uconE.StopMonitoring(sessionID)
	if err != nil {
		t.Fatalf("Failed to stop monitoring: %v", err)
	}
}

func TestEnforceWithSession(t *testing.T) {
	uconE := GetUconEnforcer()

	condition := &Condition{
		ID:   "location_condition",
		Name: "location",
		Kind: "always",
		Expr: "office",
	}
	uconE.AddCondition(condition)

	preObligation := &Obligation{
		ID:   "pre_auth",
		Name: "user_authentication",
		Kind: "pre",
		Expr: "authenticated:true",
	}
	uconE.AddObligation(preObligation)

	ongoingObligation := &Obligation{
		ID:   "ongoing_monitor",
		Name: "access_logging",
		Kind: "ongoing",
		Expr: "log_level:detailed",
	}
	uconE.AddObligation(ongoingObligation)

	postObligation := &Obligation{
		ID:   "post_log",
		Name: "access_logging",
		Kind: "post",
		Expr: "log_level:detailed",
	}
	uconE.AddObligation(postObligation)

	sessionID, err := uconE.CreateSession("alice", "read", "document1", map[string]interface{}{
		"location":      "office",
		"authenticated": "true",
		"log_level":     "detailed",
	})
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	result, err := uconE.EnforceWithSession(sessionID)
	if !result {
		t.Fatalf("Failed to enforce: %v", err)
	}
	if err != nil {
		t.Fatalf("Failed to enforce with session: %v", err)
	}

	// Simulate ongoing access for a short period
	time.Sleep(500 * time.Millisecond)

	session, err := uconE.GetSession(sessionID)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	if !session.Active {
		t.Error("Session should be active during access")
	}

	err = uconE.StopMonitoring(sessionID)
	if err != nil {
		t.Fatalf("Failed to stop monitoring: %v", err)
	}

	session, err = uconE.GetSession(sessionID)
	if err != nil {
		t.Fatalf("Failed to get session after revocation: %v", err)
	}
	if session.Active {
		t.Error("Session should not be active after revocation")
	}
}

func TestSessionRevokedDuringAccess(t *testing.T) {
	uconE := GetUconEnforcer()

	condition := &Condition{
		ID:   "location_always",
		Name: "location",
		Kind: "always",
		Expr: "office",
	}
	uconE.AddCondition(condition)

	sessionID, _ := uconE.CreateSession("alice", "read", "document1", map[string]interface{}{
		"location":      "office",
		"authenticated": "true",
		"log_level":     "detailed",
	})

	if err := uconE.StartMonitoring(sessionID); err != nil {
		t.Fatalf("Failed to start monitoring: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	uconE.UpdateSessionAttribute(sessionID, "location", "home")

	time.Sleep(300 * time.Millisecond)

	session, err := uconE.GetSession(sessionID)
	if err == nil && session.Active {
		t.Error("Expected session to be revoked due to condition change")
	}
}
