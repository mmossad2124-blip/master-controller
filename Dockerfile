FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    dirb \
    dnsutils \
    whois \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir fastapi uvicorn websockets requests pydantic
RUN pip install -r requirements.txt || true

# Copy project files
COPY . .

# Expose port for HuggingFace Spaces
EXPOSE 7860

# Run the FastAPI app
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "7860"]
