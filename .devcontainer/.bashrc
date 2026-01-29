# Tareas comunes del Dev Container
# Estos son shortcuts útiles para desarrollo
# Nota: Este proyecto usa 'uv run' en lugar de activar el entorno virtual

# Shortcuts de desarrollo (usando uv run)
alias dev='uv run uvicorn apuntador.main:app --reload --host 0.0.0.0 --port 8000'
alias test='uv run pytest'
alias lint='uv run ruff check .'
alias fmt='uv run ruff format .'
alias check='uv run ruff check . && uv run mypy src/apuntador'

# uv shortcuts
alias uv-sync='uv sync'
alias uv-add='uv add'
alias uv-update='uv lock --upgrade && uv sync'
alias uv-run='uv run'

# AWS shortcuts
alias aws-whoami='aws sts get-caller-identity'
alias aws-profile='echo $AWS_PROFILE'

# Python (con uv run)
alias py='uv run python'
alias ipy='uv run ipython'

# Git shortcuts
alias gs='git status'
alias gp='git pull'
alias gc='git commit'

# Logs
alias logs='tail -f *.log'

# Verificación
alias verify='bash .devcontainer/verify-setup.sh'

echo "Apuntador Backend Dev Container"
echo "   Python $(uv run python --version 2>/dev/null | cut -d' ' -f2 || echo '3.13')"
echo "   uv $(uv --version | cut -d' ' -f2)"
echo ""
echo "Comandos útiles (usa 'uv run' automáticamente):"
echo "   dev       - Inicia servidor de desarrollo"
echo "   test      - Ejecuta tests"
echo "   verify    - Verifica configuración"
echo "   py        - Python REPL (uv run python)"
echo "   make help - Ver todos los comandos disponibles"
echo ""
echo "Tip: No necesitas activar .venv, usa 'uv run <comando>'"
echo ""
