FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY tracker.py .

# Create non-root user
RUN useradd -m -u 1000 tracker && \
    chown -R tracker:tracker /app

USER tracker

# Expose tracker port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Run tracker
CMD ["python", "tracker.py"]
