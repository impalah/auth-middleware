# auth-middleware

Async Auth Middleware for FastAPI/Starlette.

## Technology Stack:

- FastAPI
- Pytest (\*)

## Development environment

### Requirements:

- Python >= 3.12 (Pyenv, best option)
- Poetry as dependency manager

### Activate development environment

```
poetry install
```

This will create a new virtual environment (if it does not exists) and will install all the dependencies.

To activate the virtual environment use:

```
poetry shell
```

### Add/remove dependencies

```
poetry add PIP_PACKAGE [-G group.name]
```

Add dependency to the given group. If not specified will be added to the default group.

```
poetry remove PIP_PACKAGE [-G group.name]
```

Remove dependency from the given group


## Documentation generation

Initialize sphinx

```bash
poetry run sphinx-quickstart docs
```





## Tests

### Debug From VS Code

Get the path of the virtual environment created by poetry:

```bash
poetry env info -p
```

Set in visual studio code the default interpreter to the virtual environment created by poetry.(SHIT+CTRL+P Select interpreter)

Launch "Pytest launch" from the run/debug tab.

You can set breakpoints and inspections

### Launch tests from command line

```
poetry run pytest --cov-report term-missing --cov=auth_middleware ./tests
```

This will launch tests and creates a code coverage report.

### Exclude code from coverage

When you need to exclude code from the code coverage report set, in the lines or function to be excluded, the line:

```
# pragma: no cover
```

See: https://coverage.readthedocs.io/en/6.4.4/excluding.html


## Install dependenciaes manually

```bash
poetry add fastapi
poetry add python-dotenv
poetry add svix-ksuid
poetry add "python-jose[cryptography]"
poetry add "pydantic[email]"
poetry add loguru
poetry add httpx
poetry add "sqlalchemy[asyncio]"
poetry add asyncpg
poetry add aiomysql
poetry add click
```




Development dependencies

```bash
poetry add --group dev pytest
poetry add --group dev pytest-mock
poetry add --group dev pytest-asyncio
poetry add --group dev mock
poetry add --group dev pytest-cov
poetry add --group dev black
poetry add --group dev pytest-env
poetry add --group dev mypy
poetry add --group dev sphinx
poetry add --group dev sphinx-rtd-theme
poetry add --group dev flake8
poetry add --group dev flake8-bugbear
poetry add --group dev flake8-annotations
poetry add --group dev autoflake
poetry add --group dev alembic
poetry add --group dev psycopg2
poetry add --group dev mysqlclient
```

## Export dependencies

Include dev dependencies

```bash
poetry export -f requirements.txt --output requirements.txt --with dev --without-hashes


