#!/bin/bash
# Script para iniciar el Dev Container
# Uso: bash .devcontainer/start.sh

set -e

echo "Iniciando Dev Container para Apuntador Backend..."
echo ""

# Verificar que Docker está corriendo
if ! docker info > /dev/null 2>&1; then
    echo "[ERROR] Docker no está corriendo. Por favor inicia Docker Desktop."
    exit 1
fi

echo "[OK] Docker está corriendo"
echo ""

# Verificar que la extensión Dev Containers está instalada
if ! code --list-extensions | grep -q "ms-vscode-remote.remote-containers"; then
    echo "[WARN] La extensión 'Dev Containers' no está instalada."
    echo "   Instalando..."
    code --install-extension ms-vscode-remote.remote-containers
fi

echo "Abriendo proyecto en Dev Container..."
echo ""
echo "Se abrirá VS Code y construirá el contenedor."
echo "Esto puede tomar unos minutos la primera vez."
echo ""

# Abrir VS Code en el contenedor
code --folder-uri "vscode-remote://dev-container+$(echo -n "$PWD" | xxd -plain | tr -d '\n' | sed 's/\(..\)/%\1/g')/workspace"

echo ""
echo "[OK] Dev Container iniciado!"
echo ""
echo "Una vez dentro del contenedor, ejecuta:"
echo "  bash .devcontainer/verify-setup.sh"
echo ""
