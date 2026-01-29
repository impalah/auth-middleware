#!/bin/bash
# Script de verificación del entorno de desarrollo
# Uso: bash .devcontainer/verify-setup.sh

set -e

echo "Verificando configuración del entorno de desarrollo..."
echo ""

# Colores para output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 está instalado"
        if [ "$2" = "version" ]; then
            echo "  → $($1 --version 2>&1 | head -n1)"
        fi
    else
        echo -e "${RED}✗${NC} $1 NO está instalado"
        return 1
    fi
}

check_python_version() {
    PYTHON_VERSION=$(python --version 2>&1 | cut -d' ' -f2)
    MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    
    if [ "$MAJOR" -eq 3 ] && [ "$MINOR" -ge 14 ]; then
        echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION (>= 3.14 requerido)"
    else
        echo -e "${RED}✗${NC} Python $PYTHON_VERSION (3.14+ requerido)"
        return 1
    fi
}

check_venv() {
    if [ -d ".venv" ]; then
        echo -e "${GREEN}✓${NC} Entorno virtual (.venv) existe"
        if [ -f ".venv/bin/python" ]; then
            VENV_PYTHON=$(.venv/bin/python --version)
            echo "  → $VENV_PYTHON"
        fi
    else
        echo -e "${YELLOW}[WARN]${NC} Entorno virtual (.venv) no existe"
        echo "  → Ejecuta: uv sync"
        return 1
    fi
}

check_dependencies() {
    if [ -f "uv.lock" ]; then
        echo -e "${GREEN}✓${NC} uv.lock existe"
    else
        echo -e "${YELLOW}[WARN]${NC} uv.lock no existe"
        echo "  → Ejecuta: uv sync"
        return 1
    fi
    
    if [ -f ".venv/bin/pytest" ]; then
        echo -e "${GREEN}✓${NC} Dependencias de desarrollo instaladas"
    else
        echo -e "${YELLOW}[WARN]${NC} Dependencias no completamente instaladas"
        echo "  → Ejecuta: uv sync --all-extras"
        return 1
    fi
}

check_env_file() {
    if [ -f ".env" ]; then
        echo -e "${GREEN}✓${NC} Archivo .env existe"
    else
        echo -e "${YELLOW}[WARN]${NC} Archivo .env no existe"
        echo "  → Copia .env.example: cp .env.example .env"
        return 1
    fi
}

echo "[1] Verificando herramientas del sistema..."
check_command "python" "version"
check_python_version
check_command "uv" "version"
check_command "git" "version"
check_command "aws" "version"
check_command "terraform" "version"
check_command "jq" "version"
echo ""

echo "[2] Verificando entorno Python..."
check_venv
check_dependencies
echo ""

echo "[3] Verificando configuración del proyecto..."
check_env_file
if [ -f "pyproject.toml" ]; then
    echo -e "${GREEN}✓${NC} pyproject.toml existe"
fi
if [ -f "Makefile" ]; then
    echo -e "${GREEN}✓${NC} Makefile existe"
fi
echo ""

echo "[4] Verificando acceso a AWS (si configurado)..."
if aws sts get-caller-identity &> /dev/null; then
    echo -e "${GREEN}✓${NC} Credenciales AWS configuradas correctamente"
    aws sts get-caller-identity --query '[Account,Arn]' --output text | while read -r line; do
        echo "  → $line"
    done
else
    echo -e "${YELLOW}[WARN]${NC} Credenciales AWS no configuradas o inválidas"
    echo "  → Configura con: aws configure"
fi
echo ""

echo "[5] Comandos disponibles..."
echo "  make dev          - Inicia el servidor de desarrollo"
echo "  make test         - Ejecuta los tests"
echo "  make lint         - Ejecuta el linter"
echo "  make format       - Formatea el código"
echo "  make type-check   - Verifica tipos con mypy"
echo ""

echo -e "${GREEN}[OK] Verificación completada!${NC}"
echo ""
echo "Para activar el entorno virtual manualmente:"
echo "  source .venv/bin/activate"
echo ""
echo "Para iniciar el servidor de desarrollo:"
echo "  make dev"
