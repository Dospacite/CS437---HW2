FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .
COPY templates/ templates/
COPY datacenters.txt .

# Create directories for data and logs
RUN mkdir -p data logs

EXPOSE $PORT

CMD ["python", "server.py"]
