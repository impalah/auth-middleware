Installation
============

Auth Middleware can be installed using various Python package managers. Choose the method that best fits your development workflow.

Requirements
------------

* **Python**: 3.10 or higher
* **FastAPI**: 0.115.6 or higher (for FastAPI applications)
* **Starlette**: Compatible with Starlette-based applications

Package Installation
--------------------

**Using pip** (recommended):

.. code-block:: bash

   pip install auth-middleware

**Using UV** (fastest):

.. code-block:: bash

   uv add auth-middleware

**Using Poetry**:

.. code-block:: bash

   poetry add auth-middleware

**Using pipenv**:

.. code-block:: bash

   pipenv install auth-middleware

Provider-Specific Dependencies
------------------------------

Some authentication providers require additional dependencies:

**AWS Cognito**:

.. code-block:: bash

   # All dependencies are included in the base package
   pip install auth-middleware

**Azure Entra ID**:

.. code-block:: bash

   # Additional Azure-specific packages may be needed
   pip install auth-middleware

**Google Identity**:

.. code-block:: bash

   # Additional Google-specific packages may be needed
   pip install auth-middleware

Development Installation
------------------------

If you want to contribute to the project or need the latest development version:

.. code-block:: bash

   # Clone the repository
   git clone https://github.com/impalah/auth-middleware.git
   cd auth-middleware

   # Install in development mode with UV
   uv sync

   # Or with pip
   pip install -e .

Verification
------------

Verify your installation by importing the package:

.. code-block:: python

   import auth_middleware
   print(auth_middleware.__version__)

You should see the version number printed without any errors.

Docker Installation
-------------------

For containerized applications, add auth-middleware to your requirements:

**requirements.txt**:

.. code-block:: text

   auth-middleware>=0.2.0
   fastapi>=0.115.6
   uvicorn>=0.35.0

**Dockerfile example**:

.. code-block:: dockerfile

   FROM python:3.12-slim

   WORKDIR /app

   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt

   COPY . .

   CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

Next Steps
----------

After installation, continue with the :doc:`user-guide` to learn how to configure and use auth-middleware in your application.