

FROM python:3.11-slim

# Install OS packages required for dependencies (PyGithub, Snyk CLI, pyodbc, etc.)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        unixodbc-dev \
        curl \
        git \
        build-essential \
        libssl-dev \
        libffi-dev \
        libpq-dev \
        libsasl2-dev \
        libldap2-dev \
        python3-dev \
        && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy agent code (all files from code/ into /app)
COPY code/ .

# Create non-root user for security
RUN addgroup --system appgroup && adduser --system --ingroup appgroup --no-create-home appuser
USER appuser

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AGENT_NAME=""

# Expose FastAPI port
EXPOSE 8000

# Healthcheck (FastAPI health endpoint)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start the FastAPI app with uvicorn
CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "8000"]

