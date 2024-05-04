# FastAPI Basic Authentication Demo

Testing auth middleware with basic authentication and fastapi.

## Infrastructure

### Requirements

- Postman.


## API server

### Create a configuration file

Rename or copy ".env.template" file to ".env" and set the values according with the data returned by terraform.

```bash

AUTH_MIDDLEWARE_LOG_LEVEL=DEBUG
AUTH_MIDDLEWARE_DISABLED=false

```

### Launch server

From the root folder launch the command:

```bash
poetry run dotenv run python -m uvicorn demo.main:app --host 0.0.0.0 --port 8000 --reload
```

("run dotenv" allows python to read and decode the .env file)



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







