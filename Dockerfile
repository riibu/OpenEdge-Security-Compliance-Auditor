# Use official lightweight Python image
FROM python:3.10-slim

# Set working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy and install requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project files
COPY . .

# Default command
CMD ["python", "ingest_audit.py"]