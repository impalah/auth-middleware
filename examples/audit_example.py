"""
Example: Audit Logging

This example demonstrates how to use the audit middleware
to track security events and authentication activity.
"""

import json

from fastapi import Depends, FastAPI, HTTPException, Request

from auth_middleware import JwtAuthMiddleware
from auth_middleware.functions import require_user
from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.authn.cognito_provider import CognitoProvider
from auth_middleware.services import AuditEvent, AuditLogger, AuditMiddleware

app = FastAPI(title="Audit Logging Example")

# Configure Cognito provider
settings = CognitoAuthzProviderSettings(
    user_pool_id="us-east-1_example",
    user_pool_region="us-east-1",
    user_pool_client_id="your-client-id",
)

auth_provider = CognitoProvider(settings=settings)


# Example 1: Custom audit callback for external logging
def custom_audit_callback(event: AuditEvent):
    """Send audit events to external logging service."""
    # Here you could send to CloudWatch, Datadog, Elasticsearch, etc.
    print(f"AUDIT LOG: {event.to_json()}")

    # Example: Send to external service
    # requests.post("https://logs.example.com/api/events", json=event.to_dict())


# Create audit logger with custom callback
audit_logger = AuditLogger(log_to_console=True, log_callback=custom_audit_callback)

# Add audit middleware (before auth middleware)
app.add_middleware(
    AuditMiddleware,
    enabled=True,
    audit_logger=audit_logger,
    exclude_paths=["/health", "/metrics"],  # Don't log health checks
)

# Add auth middleware
app.add_middleware(JwtAuthMiddleware, auth_provider=auth_provider)


# Example 2: Manual audit logging
@app.post("/api/sensitive-operation", dependencies=[Depends(require_user())])
async def sensitive_operation(request: Request, data: dict):
    """Endpoint with manual audit logging for specific events."""
    user = request.state.current_user

    # Log the sensitive operation start
    audit_logger.log_auth_success(
        user_id=user.id,
        is_m2m=user.is_m2m,
        client_id=user.client_id,
        path="/api/sensitive-operation",
        operation="data_modification",
        data_type=data.get("type"),
    )

    try:
        # Perform operation
        result = {"status": "success", "data": data}

        # Log success
        event = AuditEvent(
            event_type="operation_success",
            user_id=user.id,
            path="/api/sensitive-operation",
            operation="data_modification",
            result="success",
        )
        audit_logger.log(event)

        return result

    except Exception as e:
        # Log failure
        event = AuditEvent(
            event_type="operation_failure",
            user_id=user.id,
            path="/api/sensitive-operation",
            operation="data_modification",
            error=str(e),
        )
        audit_logger.log(event)
        raise


# Example 3: Access denial logging
@app.get("/api/admin-only", dependencies=[Depends(require_user())])
async def admin_only(request: Request):
    """Endpoint with access control and audit logging."""
    user = request.state.current_user

    # Check if user has admin role
    if "admin" not in (user.groups or []):
        # Log access denial
        audit_logger.log_access_denied(
            user_id=user.id,
            path="/api/admin-only",
            reason="insufficient_permissions",
            required_groups=["admin"],
            user_groups=user.groups or [],
        )

        raise HTTPException(status_code=403, detail="Admin access required")

    return {"message": "Admin access granted"}


# Example 4: Track specific user actions
@app.post("/api/resource/{resource_id}", dependencies=[Depends(require_user())])
async def modify_resource(resource_id: str, request: Request, changes: dict):
    """Track resource modifications in audit log."""
    user = request.state.current_user

    # Log the modification with details
    event = AuditEvent(
        event_type="resource_modified",
        user_id=user.id,
        is_m2m=user.is_m2m,
        path=f"/api/resource/{resource_id}",
        method="POST",
        resource_id=resource_id,
        changes=json.dumps(changes),
        timestamp=None,  # Will be auto-generated
    )
    audit_logger.log(event)

    return {"status": "modified", "resource_id": resource_id}


# Example 5: Query audit logs (simplified - in production use proper storage)
audit_events = []  # In-memory storage (use database in production)


def store_audit_event(event: AuditEvent):
    """Store audit events for querying."""
    audit_events.append(event.to_dict())
    print(f"AUDIT: {event.to_json()}")


# Create logger with storage callback
persistent_audit_logger = AuditLogger(
    log_to_console=False, log_callback=store_audit_event
)


@app.get("/admin/audit-logs")
async def get_audit_logs(
    user_id: str | None = None,
    event_type: str | None = None,
    limit: int = 100,
):
    """Retrieve audit logs with filtering."""
    filtered_events = audit_events

    if user_id:
        filtered_events = [e for e in filtered_events if e.get("user_id") == user_id]

    if event_type:
        filtered_events = [
            e for e in filtered_events if e.get("event_type") == event_type
        ]

    return {"events": filtered_events[:limit], "total": len(filtered_events)}


# Health check (excluded from audit logs)
@app.get("/health")
async def health():
    """Health check endpoint - not logged."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
