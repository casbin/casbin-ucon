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
        ID:   "time_condition",
        Type: "temporal",
        Expr: "working_hours",
    }
    uconE.AddCondition(condition)

    // Add obligations
    obligation := &ucon.Obligation{
        ID:   "log_access",
        Type: "post",
        Expr: "audit_log",
    }
    uconE.AddObligation(obligation)

        // Create a session
    sessionID, _ := uconE.CreateSession("alice", "read", "document1", map[string]interface{}{
        "department": "engineering",
        "clearance":  "secret",
    })

    // UCON session-based enforcement
    if res, err := uconE.EnforceWithSession(sessionID); res {
        // the session has started
    }else{
        // deny the request, show an error
    }
}
```

## Basic API

```go
// Enhanced enforcement
EnforceWithSession(sessionID string) (bool, error)

// Session management
CreateSession(subject, action, object string, attributes map[string]interface{}) (string, error)
GetSession(sessionID string) (*SessionImpl, error)
RevokeSession(sessionID string) error

// Condition  management
AddCondition(condition *ConditionImpl) error
EvaluateConditions(sessionID string) (bool, error)
//obligation management
AddObligation(obligation *ObligationImpl) error
ExecuteObligations(sessionID string) error

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
