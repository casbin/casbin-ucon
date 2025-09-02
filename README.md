# casbin-ucon

A [UCON (Usage Control)](https://dl.acm.org/doi/10.1145/984334.984339) extension for Casbin that provides session-based access control with conditions, obligations, and continuous monitoring.

## Overview

Casbin-UCON extends Casbin with UCON (Usage Control) capabilities, enabling:

- **Session-based access control** with dynamic attributes
- **Condition evaluation** for contextual constraints
- **Obligation execution** for required actions
- **Continuous monitoring** for ongoing authorization

## Installation

```bash
go get github.com/casbin/casbin-ucon
```

## Quick Start

```go
package main

import (
    "github.com/casbin/casbin/v2"
    "github.com/casbin/casbin-ucon"
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
		Type: "always",
		Expr: "office",
    }
    uconE.AddCondition(condition)

    // Add obligations
    obligation := &ucon.Obligation{
        ID:   "post_log",
		Name: "access_logging",
		Type: "post",
		Expr: "log_level:detailed",
    }
    uconE.AddObligation(obligation)

        // Create a session
    sessionID, _ := uconE.CreateSession("alice", "read", "document1", map[string]interface{}{
        "location":      "office",
		"log_level":     "detailed",
    })

    // UCON session-based enforcement
    if res, err := uconE.EnforceWithSession(sessionID); res {
        // the session has started
    }else{
        // deny the request, show an error
    }
    /*
    ongoing access
    */
    
    // Stop the seesion
    _ = uconE.StopMonitoring(sessionID)

}
```

## Basic API

```go
// Enhanced enforcement
EnforceWithSession(sessionID string) (bool, error)

// Session management
CreateSession(subject, action, object string, attributes map[string]interface{}) (string, error)
GetSession(sessionID string) (*SessionImpl, error)
UpdateSessionAttribute(sessionID string, key string, val interface{}) error
RevokeSession(sessionID string) error

// Condition  management
AddCondition(condition *ConditionImpl) error
EvaluateConditions(sessionID string) (bool, error)
// Obligation management
AddObligation(obligation *ObligationImpl) error
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

## License

Apache 2.0 License - see [LICENSE](LICENSE) for details.
