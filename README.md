# casbin-ucon

A [UCON (Usage Control)](https://dl.acm.org/doi/10.1145/984334.984339) extension for Casbin that provides session-based access control with conditions, obligations, and continuous monitoring.

## Overview

Casbin-UCON extends Casbin with UCON (Usage Control) capabilities, enabling:

- **Session-based access control** with dynamic attributes
- **Condition evaluation** for contextual constraints
- **Obligation execution** for required actions
- **Continuous monitoring** for ongoing authorization

## Prerequisites

- Basic knowledge of [Casbin](https://github.com/casbin/casbin) is required,
  since Casbin-UCON extends Casbin with session-based usage control.

## Installation

```bash
go get github.com/casbin/casbin-ucon
```

## Continuous Authorization Behavior

It's important to understand how continuous authorization works in Casbin-UCON:

1. EnforceWithSession(sessionID) performs pre-checks (pre-conditions and pre-obligations) and automatically starts monitoring for ongoing conditions and obligations.

2. StartMonitoring(sessionID) only starts monitoring without pre-checks.

3. If a session no longer satisfies the conditions, session.IfActive() will return false, and you can use session.GetStopReason() to determine why the session stopped.

4. Your application is responsible for handling these notifications and deciding how to terminate the session.

Always call StopMonitoring() to clean up resources when done.
Example:

```go
go func() {
  for {
    if !session.IfActive() {
      if session.GetStopReason() == ucon.NormalStopReason {
        // NormalStopReason means the session was stopped by user code calling StopMonitoring().
        break
      }
      //TODO
      //decide how to handle session termination yourself
      // For example, clean up resources, close connections, write logs, notify the frontend, etc.
      fmt.Printf("%s %s %s is stopped because: %s\n", session.GetSubject(), session.GetAction(), session.GetObject(),session.GetStopReason())
      break
    }
    time.Sleep(200 * time.Millisecond)
  }
}()
```

## Quick Start

Casbin-UCON requires standard Casbin configuration files:

- **model.conf**: defines the access control model (RBAC, ABAC, etc.)
- **policy.csv**: defines the access policies

For example:

**model.conf**

```conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

**policy.csv**

```csv
p, alice, document1, read
```

```go
package main

import (
    "github.com/casbin/casbin/v2"
    "github.com/casbin/casbin-ucon"
	"fmt"
	"time"
)

func main() {
    // Create standard Casbin enforcer
    e, _ := casbin.NewEnforcer("model.conf", "policy.csv")

    // Wrap with UCON functionality
    uconE := ucon.NewUconEnforcer(e)

    // Add conditions
    condition := &ucon.Condition{
        ID:   "location_condition",
		Name: "location",
		Kind: "always",
		Expr: "office",
    }
    uconE.AddCondition(condition)

    // Add obligations
    obligation := &ucon.Obligation{
        ID:   "post_log",
		Name: "access_logging",
		Kind: "post",
		Expr: "log_level:detailed",
    }
    uconE.AddObligation(obligation)

        // Create a session
    sessionID, _ := uconE.CreateSession("alice", "read", "document1", map[string]interface{}{
        "location":      "office",
		"log_level":     "detailed",
    })

    // UCON session-based enforcement
    session, err := uconE.EnforceWithSession(sessionID)
	if session == nil {
        // refused
        fmt.Println("session refused because: ",err )
    }

  go func() {
    for {
      if !session.IfActive() {
        if session.GetStopReason() == ucon.NormalStopReason {
          break
        }
        //TODO
        //decide how to handle session termination yourself
        // For example, clean up resources, close connections, write logs, notify the frontend, etc.
        fmt.Printf("%s %s %s is stopped because: %s\n", session.GetSubject(), session.GetAction(), session.GetObject(),session.GetStopReason())
        break
      }
      time.Sleep(200 * time.Millisecond)
    }
  }()

	/*
	alice read document1
	
	//you could change the attribute by:
	session.UpdateAttribute("location", "home")
	 */


    // Stop the session
    _ = uconE.StopMonitoring(sessionID)

}
```

## Basic API

```go
// Enhanced enforcement
EnforceWithSession(sessionID string) (*Session, error)

// Session management
CreateSession(subject, action, object string, attributes map[string]interface{}) (string, error)
GetSession(sessionID string) (*Session, error)
UpdateSessionAttribute(sessionID string, key string, val interface{}) error
RevokeSession(sessionID string) error

// Condition  management
AddCondition(condition *Condition) error
EvaluateConditions(sessionID string) (bool, error)
// Obligation management
AddObligation(obligation *Obligation) error
ExecuteObligations(sessionID string) error
ExecuteObligationsByType(sessionID string, phase string) error

// Monitoring
StartMonitoring(sessionID string) error
StopMonitoring(sessionID string) error
```

## Status

**Development Status**: This project is in an early development stage and features may change frequently.

**Current Features**:

- Core interface definitions
- Basic session management
- Foundation for conditions, obligations, and monitoring
- Full Casbin compatibility

## Future Plans

- Enhanced Condition & Obligation Management – Allow more flexible and customizable conditions and obligations.

- Improved Session Management – Additional features for session lifecycle and attribute handling.

- Advanced Monitoring – Configurable monitoring options for ongoing authorization and obligations.

- Comprehensive Documentation & Examples – Expanded guides, usage examples, and best practices.

## License

Apache 2.0 License - see [LICENSE](LICENSE) for details.
