The User Property
=================

After authentication the Request object contains information about the current user in the state.current_user variable.

The table below shows the properties of the user object.

.. list-table::
   :header-rows: 1

   * - Property
     - Description
   * - id
     - Id of the user in the identity provider
   * - name
     - User name (or id if not defined)
   * - email
     - User email (if any)
   * - groups
     - Array of user groups as sent by the identity provider