FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for llama-cpp-python CPU inference
RUN apt-get update && apt-get install -y \
    build-essential cmake git curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip install --no-cache-dir \
    fastapi==0.111.0 \
    uvicorn==0.30.0 \
    requests==2.31.0 \
    huggingface_hub==0.23.0 \
    "llama-cpp-python==0.2.90" \
    pydantic==2.7.0

COPY app.py .

# HF Spaces expose port 7860
EXPOSE 7860

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]
