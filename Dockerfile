FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .
COPY templates/ templates/

# Create directories for data and logs
RUN mkdir -p data logs

EXPOSE 8000

CMD ["python", "server.py"]
