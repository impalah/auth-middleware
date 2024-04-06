Middleware Configuration
========================

The middleware configuration is done by environment variables (or using and .env file if your project uses python-dotenv).

The main variables are shown in the table below:

.. list-table::
   :header-rows: 1

   * - Name
     - Description
     - Values
     - Default
   * - AUTH_MIDDLEWARE_LOG_LEVEL
     - Log level for the application
     - DEBUG, INFO, WARNING, ERROR, CRITICAL
     - INFO
   * - AUTH_MIDDLEWARE_LOG_FORMAT
     - Log format
     - See python logger documentation
     - %(log_color)s%(levelname)-9s%(reset)s %(asctime)s %(name)s %(message)s
   * - AUTH_MIDDLEWARE_LOGGER_NAME
     - Auth middleware logger name
     - A string
     - auth_middleware
   * - AUTH_MIDDLEWARE_DISABLED
     - Auth middleware enabled/disabled
     - false, true
     - false
   * - AUTH_MIDDLEWARE_JWKS_CACHE_INTERVAL_MINUTES
     - JWKS keys file refreshing interval
     - An integer value
     - 20
   * - AUTH_MIDDLEWARE_JWKS_CACHE_USAGES
     - JWKS keys refreshing interval (counter)
     - An integer value
     - 1000