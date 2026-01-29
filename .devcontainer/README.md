# Dev Container Configuration

This directory contains the configuration for VS Code Dev Containers, allowing you to develop the Apuntador Backend in a consistent, reproducible environment.

## What's Included

- **Python 3.14**: Latest Python version
- **uv**: Fast Python package installer and resolver
- **AWS CLI v2**: For managing AWS resources (Secrets Manager, DynamoDB, etc.)
- **Terraform 1.10.4**: Infrastructure as Code for AWS deployments
- **jq**: JSON processor for testing API responses
- **VS Code Extensions**:
  - Python (with Pylance)
  - Ruff (linting and formatting)
  - Mypy (type checking)
  - Docker support
  - TOML/YAML language support

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [VS Code](https://code.visualstudio.com/)
- [Dev Containers Extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

> **Nota**: Los directorios `~/.aws`, `~/.ssh` y el archivo `~/.gitconfig` se crean automáticamente si no existen. No necesitas configurar AWS antes de iniciar el contenedor.

## Quick Start

### Opción 1: Desde VS Code (Recomendado)

1. Open VS Code
2. Open the command palette (Cmd/Ctrl + Shift + P)
3. Select **"Dev Containers: Reopen in Container"**
4. Wait for the container to build and dependencies to install (5-10 min primera vez)

### Opción 2: Usando el script

```bash
# Desde la raíz del proyecto
bash .devcontainer/start.sh
```

### Verificar instalación

Una vez dentro del contenedor:

```bash
# Verificar que todo está configurado
bash .devcontainer/verify-setup.sh
# o simplemente
verify

# Iniciar servidor de desarrollo
dev
# o
uv run uvicorn apuntador.main:app --reload
```

> **Nota importante**: Este proyecto usa `uv run` para ejecutar comandos.
> No necesitas activar el entorno virtual manualmente. El directorio `.venv`
> está mapeado a tu disco local, por lo que las dependencias persisten
> entre rebuilds del contenedor.

The `postCreateCommand` automatically:
- Creates a virtual environment (`.venv`)
- Installs all dependencies via `uv sync`

## Features

### Port Forwarding

Port **8000** is automatically forwarded for the FastAPI backend. Start the server with:

```bash
dev
# o
uv run uvicorn apuntador.main:app --reload --host 0.0.0.0 --port 8000
# o usando make
make dev
```

### Persistent Virtual Environment

El directorio `.venv` está mapeado a tu sistema de archivos local (`${localWorkspaceFolder}/.venv`).
Esto significa que:
- Las dependencias instaladas persisten entre rebuilds del contenedor
- No necesitas reinstalar paquetes cada vez
- Puedes borrar y recrear el contenedor sin perder tu entorno
- El primer `uv sync` creará el `.venv` en tu disco local

### uv run - No Activation Needed

Este proyecto usa `uv run` en lugar de activar el entorno virtual:

```bash
# Ejecutar cualquier comando Python
uv run python mi_script.py
uv run pytest
uv run uvicorn apuntador.main:app

# uv run detecta automáticamente .venv
# No necesitas: source .venv/bin/activate
```

### AWS Credentials

Your local AWS credentials, Git config, and SSH keys are automatically mounted into the container:
- `~/.aws` → `/home/vscode/.aws`
- `~/.gitconfig` → `/home/vscode/.gitconfig`
- `~/.ssh` → `/home/vscode/.ssh`

**Importante**: Si estos directorios no existen, se crean automáticamente al iniciar el contenedor (vacíos). Para configurar AWS dentro del contenedor, ejecuta:

```bash
aws configure
```

### Python Tools

All tools are pre-configured:
- **Pytest**: Run tests with `pytest` or use VS Code Test Explorer
- **Ruff**: Auto-format on save, organize imports
- **Mypy**: Type checking from virtual environment

## Common Tasks

```bash
# Install dependencies
uv sync

# Run development server
make dev

# Run tests
pytest

# Lint and format
ruff check .
ruff format .

# Type checking
mypy src/apuntador

# Build Docker image
make docker-build

# Deploy to AWS
cd iac/stacks/01.applications
terraform apply -var-file=configuration.application.tfvars
```

## Environment Variables

Create a `.env` file in the project root (see `.env.example`):

```bash
cp .env.example .env
# Edit .env with your credentials
```

## Verificación del Entorno

Después de que el contenedor se inicie, puedes verificar que todo esté configurado correctamente:

```bash
bash .devcontainer/verify-setup.sh
```

Este script verifica:
- Python 3.14+ instalado
- uv instalado y funcionando
- Entorno virtual creado
- Dependencias instaladas
- Archivo .env configurado
- Credenciales AWS (opcional)

## Actualización de Dependencias

```bash
# Agregar nueva dependencia
uv add nombre-paquete

# Agregar dependencia de desarrollo
uv add --dev nombre-paquete

# Sincronizar dependencias
uv sync

# Actualizar todas las dependencias
uv lock --upgrade
uv sync
```

## Troubleshooting

### Container won't start

```bash
# Rebuild without cache
docker compose -f .devcontainer/docker-compose.yml build --no-cache
```

### Dependencies not installing

```bash
# Inside container
uv sync --reinstall

# Or recreate virtual environment
rm -rf .venv
uv sync
```

### Python version mismatch

Si el entorno virtual usa una versión incorrecta de Python:

```bash
# Remove and recreate with correct Python
rm -rf .venv
uv venv --python 3.14
uv sync
```

### Port 8000 already in use

```bash
# Find and kill process using port 8000
lsof -ti:8000 | xargs kill -9

# Or use a different port
uvicorn apuntador.main:app --reload --port 8001
```

### AWS credentials not working

Check that `~/.aws/credentials` exists and has valid credentials:

```bash
aws sts get-caller-identity
```

## Architecture Detection

The Dockerfile automatically detects your CPU architecture (x86_64 or ARM64) and installs the correct AWS CLI version.

## Extensions Installed

- `ms-python.python` - Python language support
- `ms-python.vscode-pylance` - Fast Python language server
- `charliermarsh.ruff` - Python linter and formatter
- `ms-python.mypy-type-checker` - Static type checker
- `tamasfe.even-better-toml` - TOML language support
- `redhat.vscode-yaml` - YAML language support
- `ms-azuretools.vscode-docker` - Docker support
