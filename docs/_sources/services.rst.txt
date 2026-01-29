.. _services:

Services Module
===============

The services module provides cross-cutting functionality for authentication and authorization including M2M token detection, rate limiting, audit logging, and metrics collection.

.. contents:: Table of Contents
   :local:
   :depth: 2

M2M Token Detection
===================

The M2M (Machine-to-Machine) Token Detector helps identify service account tokens versus human user tokens.

Overview
--------

M2M authentication is commonly used for:

- Service-to-service communication
- API integrations
- Background jobs and automated processes
- Microservice authentication

The detector analyzes JWT claims to determine if a token represents a service account or a human user.

M2MTokenDetector Class
---------------------

.. class:: auth_middleware.services.M2MTokenDetector

   Static utility class for detecting M2M tokens.

   .. staticmethod:: is_m2m_token(claims: dict) -> bool

      Determines if JWT token represents M2M authentication.

      **Detection Criteria:**
      
      - Missing ``cognito:username`` claim
      - ``token_use`` is "access" (not "id")
      - Has ``client_id`` claim
      - Missing typical user claims (email, name, etc.)

      :param claims: JWT token claims dictionary
      :return: True if token is M2M, False otherwise

      **Example:**

      .. code-block:: python

         from auth_middleware.services import M2MTokenDetector

         claims = {
             "token_use": "access",
             "client_id": "service-account-123",
             "scope": "api/read api/write"
         }

         is_m2m = M2MTokenDetector.is_m2m_token(claims)
         # Returns: True

   .. staticmethod:: get_client_id(claims: dict) -> str | None

      Extracts client ID from token claims.

      :param claims: JWT token claims dictionary
      :return: Client ID or None if not found

      **Example:**

      .. code-block:: python

         client_id = M2MTokenDetector.get_client_id(claims)
         # Returns: "service-account-123"

   .. staticmethod:: get_token_metadata(claims: dict) -> dict

      Extracts comprehensive metadata from token.

      :return: Dictionary with token_use, client_id, scopes, and user context
      
      **Example:**

      .. code-block:: python

         metadata = M2MTokenDetector.get_token_metadata(claims)
         # Returns: {
         #     "token_use": "access",
         #     "client_id": "service-account-123",
         #     "scopes": ["api/read", "api/write"],
         #     "has_user_context": False
         # }

   .. staticmethod:: requires_user_context(claims: dict) -> bool

      Checks if token has user context (for user operations).

      :param claims: JWT token claims dictionary
      :return: True if user context is present

Usage with User Model
---------------------

The User model includes M2M detection fields:

.. code-block:: python

   from fastapi import FastAPI, Depends, Request, HTTPException
   from auth_middleware.functions import require_user

   app = FastAPI()

   @app.get("/data", dependencies=[Depends(require_user())])
   async def get_data(request: Request):
       user = request.state.current_user

       if user.is_m2m:
           # Service account access
           return {
               "message": "Service account authenticated",
               "client_id": user.client_id,
               "service_id": user.id
           }
       else:
           # Human user access
           return {
               "message": f"Hello {user.email}",
               "user_id": user.id
           }

   @app.get("/human-only", dependencies=[Depends(require_user())])
   async def human_only(request: Request):
       user = request.state.current_user
       
       if user.is_m2m:
           raise HTTPException(
               status_code=403,
               detail="This endpoint requires human user authentication"
           )
       
       return {"message": "Human user access granted"}

Rate Limiting
=============

Built-in rate limiting helps protect endpoints from abuse and excessive usage.

RateLimiter Class
----------------

.. class:: auth_middleware.services.RateLimiter

   Sliding window rate limiter with async support.

   .. method:: __init__(max_requests: int, window_seconds: int)

      Initialize rate limiter.

      :param max_requests: Maximum requests allowed in window
      :param window_seconds: Time window in seconds

      **Example:**

      .. code-block:: python

         from auth_middleware.services import RateLimiter

         # 100 requests per minute
         limiter = RateLimiter(max_requests=100, window_seconds=60)

   .. method:: async is_allowed(identifier: str) -> bool

      Check if request is allowed for identifier.

      :param identifier: Unique identifier (user ID, IP, etc.)
      :return: True if request is allowed

      **Example:**

      .. code-block:: python

         allowed = await limiter.is_allowed("user-123")
         if not allowed:
             # Rate limit exceeded
             raise HTTPException(status_code=429)

   .. method:: async get_remaining(identifier: str) -> int

      Get remaining requests allowed in current window.

      :param identifier: Unique identifier
      :return: Number of remaining requests

   .. method:: async reset(identifier: str)

      Reset rate limit for specific identifier.

      :param identifier: Unique identifier to reset

   .. method:: async clear_all()

      Clear all rate limit data.

rate_limit Decorator
-------------------

.. function:: auth_middleware.services.rate_limit(max_requests: int, window_seconds: int, identifier: Callable = None)

   Decorator for endpoint rate limiting.

   :param max_requests: Maximum requests allowed
   :param window_seconds: Time window in seconds
   :param identifier: Optional function to extract identifier from request

   **Example:**

   .. code-block:: python

      from auth_middleware.services import rate_limit

      @app.get("/api/data")
      @rate_limit(max_requests=10, window_seconds=60)
      async def get_data():
          return {"data": "value"}

      # Custom identifier
      @app.get("/api/user-data")
      @rate_limit(
          max_requests=50,
          window_seconds=3600,
          identifier=lambda req: req.state.current_user.id
      )
      async def get_user_data(request: Request):
          return {"data": "user specific"}

Manual Rate Limiting
-------------------

For fine-grained control:

.. code-block:: python

   from auth_middleware.services import RateLimiter
   from fastapi import Response

   api_limiter = RateLimiter(max_requests=100, window_seconds=60)

   @app.get("/api/custom")
   async def custom_endpoint(request: Request, response: Response):
       client_id = request.client.host
       
       if not await api_limiter.is_allowed(client_id):
           remaining = await api_limiter.get_remaining(client_id)
           response.headers["X-RateLimit-Remaining"] = str(remaining)
           raise HTTPException(status_code=429, detail="Rate limit exceeded")
       
       # Add rate limit headers
       remaining = await api_limiter.get_remaining(client_id)
       response.headers["X-RateLimit-Limit"] = "100"
       response.headers["X-RateLimit-Remaining"] = str(remaining)
       
       return {"data": "success"}

Audit Logging
=============

Comprehensive audit logging for security and compliance requirements.

AuditEvent Class
---------------

.. class:: auth_middleware.services.AuditEvent

   Represents a security audit event.

   .. attribute:: timestamp
      :type: datetime

      Event timestamp (UTC)

   .. attribute:: event_type
      :type: str

      Event type (auth_success, auth_failure, access_denied, etc.)

   .. attribute:: user_id
      :type: str | None

      User or service account ID

   .. attribute:: client_id
      :type: str | None

      Client ID for M2M tokens

   .. attribute:: is_m2m
      :type: bool

      Whether this is M2M authentication

   .. attribute:: path
      :type: str | None

      Request path

   .. attribute:: method
      :type: str | None

      HTTP method

   .. attribute:: status_code
      :type: int | None

      Response status code

   .. attribute:: ip_address
      :type: str | None

      Client IP address

   .. attribute:: user_agent
      :type: str | None

      Client user agent

   .. attribute:: metadata
      :type: dict

      Additional event-specific data

   .. method:: to_dict() -> dict

      Convert event to dictionary for logging.

   .. method:: to_json() -> str

      Convert event to JSON string.

AuditLogger Class
----------------

.. class:: auth_middleware.services.AuditLogger

   Service for logging audit events.

   .. method:: __init__(log_to_console: bool = True, log_callback: Callable = None)

      Initialize audit logger.

      :param log_to_console: Whether to log to console
      :param log_callback: Optional callback function for custom logging

      **Example:**

      .. code-block:: python

         from auth_middleware.services import AuditLogger

         def send_to_cloudwatch(event):
             # Send to external logging service
             pass

         audit = AuditLogger(
             log_to_console=True,
             log_callback=send_to_cloudwatch
         )

   .. method:: log(event: AuditEvent)

      Log an audit event.

   .. method:: log_auth_success(user_id: str, is_m2m: bool = False, **kwargs)

      Log successful authentication.

   .. method:: log_auth_failure(reason: str, **kwargs)

      Log failed authentication.

   .. method:: log_access_denied(user_id: str, path: str, reason: str, **kwargs)

      Log access denial.

AuditMiddleware Class
--------------------

.. class:: auth_middleware.services.AuditMiddleware

   Middleware for automatic request auditing.

   .. code-block:: python

      from fastapi import FastAPI
      from auth_middleware.services import AuditMiddleware, AuditLogger

      app = FastAPI()

      # Add audit middleware
      app.add_middleware(
          AuditMiddleware,
          enabled=True,
          audit_logger=AuditLogger(),
          exclude_paths=["/health", "/metrics"]
      )

Manual Audit Logging
-------------------

For specific operations:

.. code-block:: python

   from auth_middleware.services import AuditLogger, AuditEvent

   audit_logger = AuditLogger()

   @app.post("/sensitive-operation")
   async def sensitive_op(request: Request, data: dict):
       user = request.state.current_user
       
       # Log operation start
       event = AuditEvent(
           event_type="sensitive_operation",
           user_id=user.id,
           is_m2m=user.is_m2m,
           path="/sensitive-operation",
           operation="data_modification",
           data_type=data.get("type")
       )
       audit_logger.log(event)
       
       # Perform operation
       result = process_data(data)
       
       # Log success
       audit_logger.log_auth_success(
           user_id=user.id,
           operation="data_modification",
           result="success"
       )
       
       return result

Metrics Collection
==================

Monitor authentication performance and track success rates.

MetricsCollector Class
---------------------

.. class:: auth_middleware.services.MetricsCollector

   Collector for authentication metrics.

   .. method:: __init__()

      Initialize metrics collector.

      **Example:**

      .. code-block:: python

         from auth_middleware.services import MetricsCollector

         metrics = MetricsCollector()

   .. method:: async record_validation_success(duration_ms: float)

      Record successful token validation.

      :param duration_ms: Validation duration in milliseconds

   .. method:: async record_validation_failure(error_type: str, duration_ms: float)

      Record failed validation.

      :param error_type: Type/category of error
      :param duration_ms: Validation duration in milliseconds

   .. method:: async get_metrics() -> dict

      Get current metrics snapshot.

      **Returns:**

      .. code-block:: python

         {
             "uptime_seconds": 3600.5,
             "tokens_validated": 10000,
             "tokens_failed": 150,
             "total_tokens": 10150,
             "success_rate": 98.52,
             "validation_time_avg_ms": 25.3,
             "validation_time_p95_ms": 45.7,
             "validation_time_p99_ms": 89.2,
             "errors_by_type": {
                 "expired_token": 100,
                 "invalid_signature": 50
             }
         }

   .. method:: async reset()

      Reset all metrics to initial state.

Usage Example
------------

.. code-block:: python

   from fastapi import FastAPI, Request
   from auth_middleware.services import MetricsCollector
   import time

   app = FastAPI()
   metrics = MetricsCollector()

   @app.middleware("http")
   async def metrics_middleware(request: Request, call_next):
       start = time.time()
       
       try:
           response = await call_next(request)
           duration_ms = (time.time() - start) * 1000
           
           if hasattr(request.state, "current_user"):
               await metrics.record_validation_success(duration_ms)
           elif response.status_code == 401:
               await metrics.record_validation_failure("unauthorized", duration_ms)
           
           return response
       except Exception as e:
           duration_ms = (time.time() - start) * 1000
           await metrics.record_validation_failure(type(e).__name__, duration_ms)
           raise

   @app.get("/metrics")
   async def get_metrics():
       return await metrics.get_metrics()

   @app.get("/metrics/prometheus")
   async def prometheus_metrics():
       snapshot = await metrics.get_metrics()
       
       return f"""
       # HELP auth_tokens_validated_total Total validated tokens
       # TYPE auth_tokens_validated_total counter
       auth_tokens_validated_total {snapshot['tokens_validated']}
       
       # HELP auth_success_rate Authentication success rate
       # TYPE auth_success_rate gauge
       auth_success_rate {snapshot['success_rate']}
       
       # HELP auth_validation_duration_avg_ms Average validation time
       # TYPE auth_validation_duration_avg_ms gauge
       auth_validation_duration_avg_ms {snapshot['validation_time_avg_ms']}
       """

Best Practices
==============

M2M Token Detection
------------------

1. **Validate M2M tokens differently** - Service accounts may not have email/name
2. **Use client_id for identification** - Don't rely on user_id for M2M
3. **Separate permissions** - M2M tokens may need different scopes
4. **Block M2M from user endpoints** - Verify ``is_m2m`` flag for user-only operations

Rate Limiting
-------------

1. **Choose appropriate limits** - Balance security and user experience
2. **Use per-user limits** - More accurate than IP-based
3. **Return rate limit headers** - Help clients manage their requests
4. **Monitor limit hits** - Adjust limits based on usage patterns

Audit Logging
-------------

1. **Log security-relevant events** - Authentication, authorization, sensitive operations
2. **Include context** - User ID, IP, timestamp, action details
3. **Protect audit logs** - Ensure logs cannot be tampered with
4. **Regular review** - Monitor logs for suspicious activity
5. **Compliance** - Ensure logging meets regulatory requirements

Metrics Collection
-----------------

1. **Track key metrics** - Success rate, latency, error types
2. **Set up alerts** - Monitor for anomalies
3. **Export to monitoring systems** - Prometheus, CloudWatch, Datadog
4. **Analyze trends** - Identify performance issues early
5. **Capacity planning** - Use metrics to predict growth

See Also
========

* :doc:`jwt_auth_middleware` - Main middleware documentation
* :doc:`functions` - Authorization dependency functions
* :doc:`user-property` - User model lazy loading
* :doc:`jwks-cache` - JWKS caching strategies

Example Code
------------

Complete examples can be found in the repository:

- ``examples/m2m_detection_example.py`` - M2M token detection
- ``examples/rate_limiting_example.py`` - Rate limiting patterns
- ``examples/audit_example.py`` - Audit logging integration
- ``examples/metrics_example.py`` - Metrics collection
