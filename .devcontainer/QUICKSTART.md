# Guía Rápida - Dev Container

## Inicio Rápido

```bash
# Opción 1: Desde VS Code
# Cmd/Ctrl + Shift + P → "Dev Containers: Reopen in Container"

# Opción 2: Script automático
bash .devcontainer/start.sh
```

## Verificar Configuración

```bash
# Dentro del contenedor
verify
# o
bash .devcontainer/verify-setup.sh
```

## Comandos Esenciales

### Desarrollo (usando uv run)
```bash
dev          # uv run uvicorn ... - Inicia servidor de desarrollo
test         # uv run pytest - Ejecuta tests
lint         # uv run ruff check - Ejecuta linter
fmt          # uv run ruff format - Formatea código
check        # uv run ruff + mypy - Ejecuta todas las verificaciones
```

### Python (con uv run)
```bash
py           # uv run python - Ejecuta Python REPL
uv run <cmd> # Ejecuta cualquier comando en el entorno del proyecto
```

### uv (Gestor de paquetes)
```bash
uv add <pkg>          # Agregar dependencia
uv add --dev <pkg>    # Agregar dependencia de desarrollo
uv sync               # Sincronizar dependencias
uv lock --upgrade     # Actualizar lock file
```

### AWS
```bash
aws-whoami   # Ver identidad AWS
aws configure # Configurar credenciales
```

## Solución de Problemas

### Reinstalar dependencias
```bash
rm -rf .venv
uv sync
```

### Reconstruir contenedor
```bash
# Desde VS Code: Cmd/Ctrl + Shift + P
# → "Dev Containers: Rebuild Container"
```

### Puerto en uso
```bash
# Cambiar puerto en make dev
uvicorn apuntador.main:app --reload --port 8001
```

## Archivos de Configuración

- `.devcontainer/devcontainer.json` - Configuración del contenedor
- `.devcontainer/Dockerfile` - Imagen Docker
- `pyproject.toml` - Dependencias del proyecto
- `.env` - Variables de entorno (crear desde .env.example)

## Workflow Típico

```bash
# 1. Verificar que todo funciona
verify

# 2. Iniciar desarrollo
dev

# 3. En otra terminal: ejecutar tests
uv run pytest

# 4. Ejecutar comando Python específico
uv run python mi_script.py

# 5. Antes de commit
lint && test
```

> **Tip**: No necesitas activar el entorno virtual. `uv run` automáticamente
> detecta y usa `.venv` del proyecto. Las dependencias se persisten en tu
> disco local, no se pierden al reconstruir el contenedor.

## Más Información

- [README completo](.devcontainer/README.md)
- [Documentación del proyecto](../README.md)
- [Guía de testing](../TESTING_GUIDE.md)
