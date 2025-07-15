FROM python:3.11-slim

LABEL maintainer="bug-bounty-automation@example.com"
LABEL description="Comprehensive Bug Bounty Scanner Tool"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    nmap \
    masscan \
    dnsutils \
    whois \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p bb_projects logs config

# Set permissions
RUN chmod +x bb_scanner.py

# Create non-root user
RUN useradd -m -s /bin/bash scanner
RUN chown -R scanner:scanner /app
USER scanner

# Expose port for web interface (if implemented)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command
CMD ["python", "bb_scanner.py", "--help"]