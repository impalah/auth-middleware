# FastAPI Cognito Demo

Testing auth middleware with Entra Id and fastapi.

## Infrastructure

Unfortunately, not all needed azure resources are implemented on Terraform API. In the case of Entra ID it is easier to create the resources manually from the Azure Portal.

### Create Application

Go to the Azure Portal

![Azure Portal 000](docs/portal-img-azure-ad-000.png)

Select Azure Entra Id
![Azure Portal 001](docs/portal-img-azure-ad-001.png)

Select "App Registrations"
![Azure Portal 002](docs/portal-img-azure-ad-002.png)

Select the "All Applications tab" to view all the defined applications
![Azure Portal 003](docs/portal-img-azure-ad-003.png)

Use the button "New Registration"
![Azure Portal 004](docs/portal-img-azure-ad-004.png)

In the New Registration screen set:
- The name for the application.
- The "Supported account type" to "Accounts in this organizational directory only"
- Redirect uri to 'http://localhost:8000' for testing purposes

Press "register" when you finish.
![Azure Portal 005](docs/portal-img-azure-ad-005.png)

The screen above shows the data you will later need to configure auth-middleware:
- Application (Client) Id.
- Directory (tenant) ID

Press 'Authentication' on the left side.

![Azure Portal 006](docs/portal-img-azure-ad-006.png)

Go down to the "Implicit grant and hybrid flow" section

![Azure Portal 007](docs/portal-img-azure-ad-007.png)

Mark the two checks
- Access Token
- Id Token

And press the Save button.

![Azure Portal 008](docs/portal-img-azure-ad-008.png)

Select "Certificates and Secrets" on the left pane.

![Azure Portal 009](docs/portal-img-azure-ad-009.png)

Select "Client Secrets" and then "New client secret".

![Azure Portal 010](docs/portal-img-azure-ad-010.png)

Set the values for Description and Expires and then press Save.

![Azure Portal 011](docs/portal-img-azure-ad-011.png)

On the left pane select Token Configuration and then "Add Groups claim"

![Azure Portal 012](docs/portal-img-azure-ad-012.png)

Mark "Security Groups" and the press the Add button.

![Azure Portal 013](docs/portal-img-azure-ad-013.png)

On the left pane select "Api Permissions" and then "Add a permission".

![Azure Portal 014](docs/portal-img-azure-ad-014.png)

Select "Microsoft Graph"

![Azure Portal 015](docs/portal-img-azure-ad-015.png)

Select "Delegated permissions"

![Azure Portal 016](docs/portal-img-azure-ad-016.png)

Mark "id", "openid" and "profile".

![Azure Portal 017](docs/portal-img-azure-ad-017.png)

In the select permissions box type "group".

![Azure Portal 018](docs/portal-img-azure-ad-018.png)

Expand "Group Member" and mark the permission GroupMember.Read.All.
Press the "Add permissions" button

![Azure Portal 019](docs/portal-img-azure-ad-019.png)

Press "Grant admin consent for default directory".

![Azure Portal 020](docs/portal-img-azure-ad-020.png)
![Azure Portal 021](docs/portal-img-azure-ad-021.png)
![Azure Portal 022](docs/portal-img-azure-ad-022.png)
![Azure Portal 023](docs/portal-img-azure-ad-023.png)
![Azure Portal 024](docs/portal-img-azure-ad-024.png)
![Azure Portal 025](docs/portal-img-azure-ad-025.png)
![Azure Portal 026](docs/portal-img-azure-ad-026.png)

Confirm on the message.

![Azure Portal 027](docs/portal-img-azure-ad-027.png)



![Azure Portal 028](docs/portal-img-azure-ad-028.png)
![Azure Portal 029](docs/portal-img-azure-ad-029.png)

On the left panel select "Expose an API".

![Azure Portal 030](docs/portal-img-azure-ad-030.png)

Select "Add a Scope".

![Azure Portal 031](docs/portal-img-azure-ad-031.png)

Press "Save and continue".

![Azure Portal 032](docs/portal-img-azure-ad-032.png)

![Azure Portal 033](docs/portal-img-azure-ad-033.png)

Set the scope name (access_as_user), select "Admin and groups", set "Admin consent Display" and press Save. 

![Azure Portal 034](docs/portal-img-azure-ad-034.png)

![Azure Portal 035](docs/portal-img-azure-ad-035.png)

On the left pane select "Manifest".

![Azure Portal 036](docs/portal-img-azure-ad-036.png)

Change the value "accessTolenAcceptedVersion" from null to 2 and press Save at the bottom of the page.

![Azure Portal 037](docs/portal-img-azure-ad-037.png)


![Azure Portal 038](docs/portal-img-azure-ad-038.png)

You can access the new application URLS pressiing the boton "Endpoints" on the "Overview" option of the left panel.

![Azure Portal 039](docs/portal-img-azure-ad-039.png)


## Assign groups to users and get groups uuids

Entra Id will include the uuids of the groups assigned to the user in the jwt token.

Go to the users panel and assign the required security groups to the users.

The groups uuid can be viewed in the Groups section of the Default Directory.

Then set the groups on the source code of the application (customer and administrator) to test the group access.


## API server

### Create a configuration file

Rename or copy ".env.template" file to ".env" and set the values according with the data returned by terraform.

```bash

AUTH_MIDDLEWARE_LOG_LEVEL=DEBUG
AUTH_MIDDLEWARE_DISABLED=false
AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID=<azure-tenant-id>
AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID=<app-audience-id>(<app-client-id>)

# VARIABLES FOR CLIENT WEBPAGE CONFIGURATION
ENTRA_ID_TENANT_ID=<azure-tenant-id>
ENTRA_ID_CLIENT_ID=<app-client-id>



```

### Launch server

From the root folder launch the command:

```bash
poetry run dotenv run python -m uvicorn demo.main:app --host 0.0.0.0 --port 8000 --reload
```

("run dotenv" allows python te read and decode the .env file)



## Test the server

### Main page

- Access [http://localhost:8000](http://localhost:8000)
- Use the "Login" button to go to the login page.
- Use the credentials of a valid user to log-in.
- If everything goes ok Cognito will go back to the same page returning access and id tokens and they will be shown.
- You can use the copy buttons to cpy the token to the clipboard.

### Postman

A Postman collection is provided to test the API endpoints.

Import the collection. Edit the colelction, go to variables and set the apropriate values.

The authorization Bearer token can be get from the Main Page (see previous section) or using the "Cognito - Get access token" request on Postman.







