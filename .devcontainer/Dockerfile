FROM mcr.microsoft.com/devcontainers/python:2-3.14-bookworm

# Remove Yarn repository (has expired GPG key and is not needed)
RUN rm -f /etc/apt/sources.list.d/yarn.list

# Install system dependencies
RUN apt-get update && \
    apt-get install -y unzip curl groff less jq git && \
    rm -rf /var/lib/apt/lists/*

# Install uv globally
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mv /root/.local/bin/uv /usr/local/bin/ && \
    mv /root/.local/bin/uvx /usr/local/bin/ && \
    chmod +x /usr/local/bin/uv /usr/local/bin/uvx

# Install AWS CLI v2 with automatic architecture detection
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        AWS_CLI_URL="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        AWS_CLI_URL="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip"; \
    else \
        echo "[ERROR] Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    curl "$AWS_CLI_URL" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws

# Install Terraform with automatic architecture detection
RUN ARCH=$(uname -m) && \
    TERRAFORM_VERSION="1.10.4" && \
    if [ "$ARCH" = "x86_64" ]; then \
        TERRAFORM_ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        TERRAFORM_ARCH="arm64"; \
    else \
        echo "[ERROR] Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    curl -LO "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${TERRAFORM_ARCH}.zip" && \
    unzip "terraform_${TERRAFORM_VERSION}_linux_${TERRAFORM_ARCH}.zip" && \
    mv terraform /usr/local/bin/ && \
    chmod +x /usr/local/bin/terraform && \
    rm -f "terraform_${TERRAFORM_VERSION}_linux_${TERRAFORM_ARCH}.zip"

# Ensure vscode user has proper permissions
USER vscode

# Set working directory
WORKDIR /workspace

# Verify installations
RUN python --version && uv --version && aws --version && terraform --version
