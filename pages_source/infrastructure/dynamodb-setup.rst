.. _dynamodb-infrastructure-setup:

DynamoDB Setup for Scoped Permissions
=====================================

*Draft: the final text is part of the 0.7.0 documentation pass.*

``DynamoDbAssignmentStore`` (``pip install 'auth-middleware[dynamodb]'``, built on
`PynamoDB <https://pynamodb.readthedocs.io/>`_) keeps one item per principal and scope in a
single table. Creating the table is a deployment concern: the runtime role never needs
table-level permissions.

Table definition
----------------

.. code-block:: python

   from auth_middleware.authz.stores import DynamoDbAssignmentStore

   DynamoDbAssignmentStore.table_definition("authz-assignments")  # boto3 create_table kwargs

======================  =======  ======================================
Attribute               Type     Role
======================  =======  ======================================
``pk``                  S        HASH, ``SCOPE#<kind>#<id>``
``sk``                  S        RANGE, ``PRINCIPAL#<principal_id>``
``gsi1pk``              S        GSI ``by-principal`` HASH
``gsi1sk``              S        GSI ``by-principal`` RANGE
======================  =======  ======================================

Billing mode ``PAY_PER_REQUEST`` is recommended; the GSI projects ``ALL`` attributes.
A Terraform equivalent:

.. code-block:: hcl

   resource "aws_dynamodb_table" "authz" {
     name         = "authz-assignments"
     billing_mode = "PAY_PER_REQUEST"
     hash_key     = "pk"
     range_key    = "sk"

     attribute { name = "pk"     type = "S" }
     attribute { name = "sk"     type = "S" }
     attribute { name = "gsi1pk" type = "S" }
     attribute { name = "gsi1sk" type = "S" }

     global_secondary_index {
       name            = "by-principal"
       hash_key        = "gsi1pk"
       range_key       = "gsi1sk"
       projection_type = "ALL"
     }
   }

IAM policy for the runtime role (least privilege)
-------------------------------------------------

.. code-block:: json

   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"],
       "Resource": [
         "arn:aws:dynamodb:REGION:ACCOUNT:table/authz-assignments",
         "arn:aws:dynamodb:REGION:ACCOUNT:table/authz-assignments/index/by-principal"
       ]
     }]
   }

No ``Scan``, no ``DeleteItem`` (assignments are revoked, never deleted) and no table-level
actions.

Consistency caveats
-------------------

* ``get_assignment`` (the guard path) always sends ``ConsistentRead=True``: an eventually
  consistent read could admit a principal that was just revoked. Turning it off
  (``consistent_read=False``) is an explicit acceptance of that risk.
* ``list_assignments`` ("my scopes") uses the GSI, which only supports eventually consistent
  reads: it may lag by a moment. The guard never calls it.
* Every write is conditional on ``revision``; losers get ``RevisionConflictError``.
* Throttling that survives botocore's retries raises ``StoreUnavailableError`` so the error
  policy can answer 503. Configure botocore retries with ``max_retry_attempts``.
* Ids may contain any character (the scope id is the last component of every composite key, so ``#`` is
  unambiguous); assignment attributes are limited to 4 KB of JSON.
* Each call runs in a worker thread. By default that is the event loop's default executor, shared with the rest of the
  application: a slow DynamoDB can occupy it. Pass ``max_workers=N`` to give the store its own bounded pool, and keep
  ``read_timeout_seconds`` and ``max_retry_attempts`` modest.

Tests
-----

``tests/authz/integration/test_dynamodb_store.py`` runs against an in-process ``moto`` server by
default. Set ``AUTHZ_TEST_DYNAMODB_ENDPOINT=http://localhost:8000`` to run the same tests against
``amazon/dynamodb-local`` (the CI ``integration-dynamodb`` job does). ``make test-floci`` runs it against Floci too.
