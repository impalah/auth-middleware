.. _jwks-cache:

JWKS Cache Strategies
======================

The JWKS (JSON Web Key Set) cache system has been improved with multiple caching strategies and background refresh capabilities for better performance and reliability.

.. contents:: Table of Contents
   :local:
   :depth: 2

Overview
--------

JWKS caching is critical for JWT validation performance. Instead of fetching public keys from the identity provider for every token validation, the middleware caches them locally with configurable refresh strategies.

**Benefits:**

- Reduced latency for token validation
- Lower load on identity provider endpoints
- Better resilience to identity provider outages
- Configurable refresh strategies for different use cases

Cache Strategies
================

The middleware supports three caching strategies that can be configured based on your application's needs.

Time-Based Strategy
-------------------

Refresh cache after a specified time interval.

**Configuration:**

.. code-block:: python

   from auth_middleware.providers.authn.cognito_authz_provider_settings import (
       CognitoAuthzProviderSettings
   )

   settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_example",
       user_pool_region="us-east-1",
       user_pool_client_id="your-client-id",
       jwks_cache_strategy="time",
       jwks_cache_interval=20,  # Refresh every 20 minutes
   )

**Pros:**

- Predictable refresh schedule
- Simple to reason about
- Consistent behavior regardless of traffic

**Cons:**

- May refresh unnecessarily during low traffic
- May not refresh quickly enough during high traffic

**Use Case:** Applications with consistent, predictable traffic patterns.

Usage-Based Strategy
--------------------

Refresh cache after a specified number of token validations.

**Configuration:**

.. code-block:: python

   settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_example",
       user_pool_region="us-east-1",
       user_pool_client_id="your-client-id",
       jwks_cache_strategy="usage",
       jwks_cache_usages=1000,  # Refresh after 1000 validations
   )

**Pros:**

- Adapts to traffic volume
- No unnecessary refreshes during idle periods
- Cache stays fresh under high load

**Cons:**

- Unpredictable refresh timing
- May go long periods without refresh during low traffic

**Use Case:** Applications with highly variable traffic patterns.

Combined Strategy (Recommended)
-------------------------------

Refresh cache when either time OR usage threshold is reached (whichever comes first).

**Configuration:**

.. code-block:: python

   settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_example",
       user_pool_region="us-east-1",
       user_pool_client_id="your-client-id",
       jwks_cache_strategy="both",  # Default
       jwks_cache_interval=20,      # 20 minutes OR
       jwks_cache_usages=1000,      # 1000 validations
   )

**Pros:**

- Combines benefits of both strategies
- Ensures timely refresh in all scenarios
- Recommended for most applications

**Cons:**

- Slightly more complex configuration

**Use Case:** Recommended for most production applications.

Background Refresh
==================

Background refresh proactively refreshes the JWKS cache before it expires, preventing cache expiry delays.

How It Works
-----------

1. When cache is loaded, a background task is scheduled
2. Task waits until ``threshold`` of cache lifetime has elapsed
3. Cache is refreshed silently in the background
4. New requests continue using cached keys without delay

Configuration
-------------

.. code-block:: python

   settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_example",
       user_pool_region="us-east-1",
       user_pool_client_id="your-client-id",
       jwks_cache_strategy="both",
       jwks_cache_interval=20,
       jwks_background_refresh=True,          # Enable background refresh
       jwks_background_refresh_threshold=0.8, # Refresh at 80% of lifetime
   )

**Threshold Examples:**

- ``0.8`` (default): Refresh at 80% of cache interval
  
  - With 20min interval: refresh happens at 16min
  
- ``0.9``: Aggressive refresh at 90%
  
  - With 20min interval: refresh happens at 18min
  
- ``0.5``: Conservative refresh at 50%
  
  - With 20min interval: refresh happens at 10min

Benefits
--------

**Prevents Latency Spikes:**

Without background refresh:

.. code-block:: text

   Request 1: Cache valid → Fast (10ms)
   Request 2: Cache valid → Fast (10ms)
   ...
   Request N: Cache expired → Slow (200ms - fetch new keys)
   Request N+1: Cache valid → Fast (10ms)

With background refresh:

.. code-block:: text

   Request 1: Cache valid → Fast (10ms)
   Request 2: Cache valid → Fast (10ms)
   [Background: Cache refreshed at 80% lifetime]
   ...
   Request N: Cache valid → Fast (10ms)
   Request N+1: Cache valid → Fast (10ms)

**Always Enabled:** Recommended for all production deployments.

Configuration Examples
=====================

High-Traffic Application
------------------------

For applications with thousands of requests per minute:

.. code-block:: python

   settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_example",
       user_pool_region="us-east-1",
       user_pool_client_id="your-client-id",
       
       # Use both strategies for reliability
       jwks_cache_strategy="both",
       
       # Longer cache time for stability
       jwks_cache_interval=30,  # 30 minutes
       
       # High usage threshold
       jwks_cache_usages=10000,  # 10,000 validations
       
       # Aggressive background refresh
       jwks_background_refresh=True,
       jwks_background_refresh_threshold=0.9,  # Refresh at 90%
   )

Low-Traffic / High-Security Application
---------------------------------------

For applications requiring frequent key rotation:

.. code-block:: python

   settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_example",
       user_pool_region="us-east-1",
       user_pool_client_id="your-client-id",
       
       # Time-based only for predictability
       jwks_cache_strategy="time",
       
       # Short cache interval
       jwks_cache_interval=5,  # 5 minutes
       
       # Early background refresh
       jwks_background_refresh=True,
       jwks_background_refresh_threshold=0.5,  # Refresh at 50%
   )

Development / Testing
--------------------

For local development and testing:

.. code-block:: python

   settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_example",
       user_pool_region="us-east-1",
       user_pool_client_id="your-client-id",
       
       # Usage-based for variable dev traffic
       jwks_cache_strategy="usage",
       jwks_cache_usages=100,  # Low threshold for testing
       
       # Optional: disable background refresh for simpler debugging
       jwks_background_refresh=False,
   )

Monitoring Cache Performance
============================

Custom Metrics
--------------

Track cache effectiveness:

.. code-block:: python

   from auth_middleware.providers.authn.cognito_provider import CognitoProvider
   from auth_middleware.services import MetricsCollector
   
   provider = CognitoProvider(settings=settings)
   metrics = MetricsCollector()
   
   # Track JWKS refresh events
   class MonitoredProvider(CognitoProvider):
       async def load_jwks(self):
           start = time.time()
           try:
               jwks = await super().load_jwks()
               duration_ms = (time.time() - start) * 1000
               await metrics.record_validation_success(duration_ms)
               logger.info(f"JWKS refreshed in {duration_ms:.2f}ms")
               return jwks
           except Exception as e:
               duration_ms = (time.time() - start) * 1000
               await metrics.record_validation_failure("jwks_load_error", duration_ms)
               raise

Logging
-------

Enable debug logging to monitor cache behavior:

.. code-block:: python

   import logging
   
   # Enable debug logging for JWT provider
   logging.getLogger("auth_middleware.providers.authn.jwt_provider").setLevel(logging.DEBUG)

**Example Output:**

.. code-block:: text

   2026-01-29 10:00:00 DEBUG JWKS loaded
   2026-01-29 10:00:00 DEBUG Background JWKS refresh task scheduled
   2026-01-29 10:16:00 DEBUG Background refresh will wait 4.00 seconds
   2026-01-29 10:16:04 INFO Performing background JWKS refresh
   2026-01-29 10:16:04 INFO Background JWKS refresh completed

Best Practices
==============

1. **Always Enable Background Refresh**
   
   Background refresh prevents latency spikes and is recommended for all production deployments:
   
   .. code-block:: python
   
      jwks_background_refresh=True

2. **Use Combined Strategy**
   
   The ``"both"`` strategy provides the best balance:
   
   .. code-block:: python
   
      jwks_cache_strategy="both"

3. **Adjust Based on Traffic Patterns**
   
   - **High traffic:** Longer intervals, higher usage thresholds
   - **Low traffic:** Shorter intervals, lower usage thresholds
   - **Irregular traffic:** Use ``"both"`` strategy

4. **Set Appropriate Thresholds**
   
   - **Conservative (0.5-0.7):** More frequent refreshes, higher load on IdP
   - **Balanced (0.8):** Recommended default
   - **Aggressive (0.9):** Fewer refreshes, risking cache expiry

5. **Monitor Refresh Failures**
   
   Implement logging and alerting for JWKS refresh failures:
   
   .. code-block:: python
   
      try:
          jwks = await provider.load_jwks()
      except Exception as e:
          logger.error(f"JWKS refresh failed: {e}")
          # Alert monitoring system
          send_alert("JWKS refresh failure")

6. **Test Configuration Changes**
   
   Before deploying new cache settings:
   
   - Test under realistic load
   - Monitor cache hit rates
   - Verify background refresh behavior
   - Check for latency spikes

Troubleshooting
===============

Cache Not Refreshing
--------------------

**Symptoms:**

- Tokens failing validation
- "Key not found" errors
- Old keys being used

**Solutions:**

1. Check cache strategy configuration
2. Verify background refresh is enabled
3. Check logs for refresh errors
4. Ensure network connectivity to identity provider

High Latency Spikes
------------------

**Symptoms:**

- Periodic slow responses
- Regular latency spikes at intervals

**Solutions:**

1. Enable background refresh
2. Lower refresh threshold (e.g., 0.7 instead of 0.9)
3. Increase cache interval if refreshing too frequently

Frequent Refreshes
-----------------

**Symptoms:**

- Excessive load on identity provider
- High network traffic
- Logs showing constant JWKS loads

**Solutions:**

1. Increase cache interval
2. Increase usage threshold
3. Consider if traffic justifies current settings

Error: "Background refresh failed"
---------------------------------

**Symptoms:**

- Warning logs about background refresh failures
- Cache functioning but not refreshing proactively

**Solutions:**

1. Check network connectivity
2. Verify identity provider availability
3. Review identity provider rate limits
4. Implement retry logic

Performance Comparison
=====================

**Without JWKS Caching:**

- Every token validation fetches public keys
- Average latency: 150-300ms per validation
- High load on identity provider

**With Time-Based Caching (20min):**

- Keys fetched every 20 minutes
- Average latency: 10-15ms per validation
- Occasional 200ms spike every 20 minutes

**With Combined Strategy + Background Refresh:**

- Keys fetched proactively before expiry
- Consistent latency: 10-15ms per validation
- No latency spikes
- **Recommended configuration**

See Also
========

* :doc:`jwt_auth_provider` - JWT provider documentation
* :doc:`cognito_provider` - Cognito provider specifics
* :doc:`services` - Metrics collection for monitoring

Example Code
------------

Complete configuration examples can be found in the repository:

- ``examples/jwks_cache_example.py`` - JWKS cache configuration examples
