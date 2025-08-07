# Variables
PROFILE="pak"
DOMAIN="impalah"
AWS_REGION="us-east-1"
REGISTRY_URI="public.ecr.aws/e2b2x4l7"
REPOSITORY_NAME="auth-middleware"
PLATFORM="linux/amd64"
BUILDER_NAME="mybuilder"
PART ?= patch  # can be overwritten with: make bump-version PART=minor

# Delete the virtual environment and force a sync
venv:
	rm -rf .venv && \
	echo "✅ Deleted virtual environment" && \
	uv sync && \
	echo "✅ Created virtual environment" && \
	uvx --from=toml-cli toml get --toml-path=pyproject.toml project.version

# Bump patch/minor/major version
bump-version:
	@v=$$(uvx --from=toml-cli toml get --toml-path=pyproject.toml project.version) && \
	echo "🔧 Current version: $$v" && \
	uvx --from bump2version bumpversion --allow-dirty --current-version "$$v" $(PART) pyproject.toml && \
	echo "✅ Version bumped to new $(PART)"

# Build python package
build: bump-version
	uv build

# Clean build artifacts
clean:
	rm -rf dist *.egg-info build && \
	echo "✅ Cleaned build artifacts"

# Publish package on PyPI (use UV_PYPI_TOKEN or .pypirc for authentication)
publish: build
	uv publish

# Publish on TestPyPI
publish-test: build
	uv publish --repository testpypi

# Build docker image
docker-build: bump-version
	@BASE_VERSION=$$(uvx --from=toml-cli toml get --toml-path=pyproject.toml project.version) && \
	echo "✅ Bumped version to $$BASE_VERSION" && \
	if docker buildx inspect $(BUILDER_NAME) >/dev/null 2>&1; then \
		echo "✅ Builder '$(BUILDER_NAME)' exists. Activating..."; \
		docker buildx use $(BUILDER_NAME); \
	else \
		echo "🔧 Creating new builder '$(BUILDER_NAME)'..."; \
		docker buildx create --name $(BUILDER_NAME) --use; \
	fi && \
	echo "🐳 Building Docker image with buildx..." && \
	docker buildx build \
		--platform $(PLATFORM) \
		--push \
		-t $(REGISTRY_URI)/$(DOMAIN)/$(REPOSITORY_NAME):$$BASE_VERSION \
		-t $(REGISTRY_URI)/$(DOMAIN)/$(REPOSITORY_NAME):latest \
		. && \
	echo "✅ Docker image built and pushed successfully"

# Release to docker registry with version tags
docker-release: docker-build
	@BASE_VERSION=$$(uvx --from=toml-cli toml get --toml-path=pyproject.toml project.version) && \
	echo "✅ Released Docker image: $(REGISTRY_URI)/$(DOMAIN)/$(REPOSITORY_NAME):$$BASE_VERSION"

# Run linting with ruff
lint:
	uv run ruff check src/ tests/

# Format code with black
format:
	uv run black src/ tests/

# Run type checking with mypy
type-check:
	uv run mypy src/

# Run security checks with bandit
security-check:
	uv run bandit -r src/

# Run all quality checks
check: lint format type-check security-check
	echo "✅ All checks completed"

# Run tests with pytest
test:
	uv run pytest tests/ --cov=src/ --cov-report=term --cov-report=html --cov-report=xml --junitxml=junit.xml -v

# Install project in development mode
install:
	uv sync

# Install project with all optional dependencies
install-all:
	uv sync --all-extras

# Run the application
run:
	uv run python -m auth_middleware

# Open Python REPL with project environment
shell:
	uv run python

# Show project info
info:
	@echo "📦 Project: auth-middleware"
	@echo "🔢 Version: $$(uvx --from=toml-cli toml get --toml-path=pyproject.toml project.version)"
	@echo "🐍 Python: $$(uv run python --version)"
	@echo "📁 Virtual env: $$(if [ -d .venv ]; then echo ".venv exists"; else echo ".venv not found"; fi)"

# Build documentation
docs:
	uv run sphinx-build docs_source docs

# Serve documentation locally
docs-serve: docs
	uv run python -m http.server 8000 --directory docs

# Help target
help:
	@echo "Available targets:"
	@echo "  venv          - Delete and recreate virtual environment"
	@echo "  install       - Install project dependencies"
	@echo "  install-all   - Install with all optional dependencies"
	@echo "  bump-version  - Bump version (PART=patch|minor|major)"
	@echo "  build         - Build package"
	@echo "  publish       - Publish to PyPI"
	@echo "  publish-test  - Publish to TestPyPI"
	@echo "  test          - Run tests with coverage"
	@echo "  lint          - Run linting"
	@echo "  format        - Format code"
	@echo "  type-check    - Run type checking"
	@echo "  security-check- Run security checks"
	@echo "  check         - Run all quality checks"
	@echo "  docker-build  - Build and push Docker image"
	@echo "  docker-release- Release Docker image"
	@echo "  docs          - Build documentation"
	@echo "  docs-serve    - Serve documentation locally"
	@echo "  run           - Run the application"
	@echo "  shell         - Open Python REPL"
	@echo "  clean         - Clean build artifacts"
	@echo "  info          - Show project information"
	@echo "  help          - Show this help"

.PHONY: venv bump-version build clean publish publish-test docker-build docker-release lint format type-check security-check check test install install-all run shell info docs docs-serve help
