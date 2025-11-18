FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if needed
RUN apt-get update && apt-get install -y \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the script
COPY domain_hunter_railway.py .

# Create directory for logs and state files
RUN mkdir -p /app/data

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the hunter
CMD ["python", "domain_hunter_railway.py"]
