FROM python:3.10-slim

WORKDIR /app

# Install system dependencies if any tools need them (e.g., nmap)
RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements or install directly
COPY requirements.txt .
RUN pip install --no-cache-dir fastapi uvicorn websockets requests pydantic

# Copy the entire project (to include core/ and server/)
COPY . .

# Set working directory to server where main.py lives
WORKDIR /app/server

# Expose port for HuggingFace Spaces
EXPOSE 7860

# Run the FastAPI app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
