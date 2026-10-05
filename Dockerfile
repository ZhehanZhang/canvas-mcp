# Use Python 3.12 slim image for smaller size
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install uv package manager for faster dependency installation
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml ./
COPY LICENSE ./
COPY README.md ./
COPY env.template ./
COPY src/ ./src/

# Install dependencies using uv.
# Build with --build-arg WITH_PENNKEY_AUTH=true to include headless Chromium
# for CANVAS_AUTH_MODE=pennkey (automated PennKey + Duo token retrieval).
ARG WITH_PENNKEY_AUTH=false
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN if [ "$WITH_PENNKEY_AUTH" = "true" ]; then \
        uv pip install --system --no-cache -e ".[pennkey]" && \
        python -m playwright install --with-deps chromium && \
        chmod -R a+rX /ms-playwright; \
    else \
        uv pip install --system --no-cache -e .; \
    fi

# Create non-root user for security
RUN adduser --disabled-password --gecos '' mcp && \
    mkdir -p /data && \
    chown -R mcp:mcp /app /data

# Set environment variables (users must provide CANVAS_API_TOKEN and CANVAS_API_URL at runtime)
# Example: docker run -e CANVAS_API_TOKEN=xyz -e CANVAS_API_URL=https://... canvas-mcp
ENV MCP_SERVER_NAME="canvas-mcp" \
    CANVAS_AUTH_STATE_DIR="/data" \
    ENABLE_DATA_ANONYMIZATION="false" \
    ANONYMIZATION_DEBUG="false"

# Switch to non-root user
USER mcp

# Health check to verify installation
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import canvas_mcp; print('OK')" || exit 1

# Run the MCP server
CMD ["canvas-mcp-server"]
