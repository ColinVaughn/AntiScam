FROM python:3.11-slim

# Install system dependencies for llama.cpp
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build llama.cpp using CMake
WORKDIR /tmp
RUN git clone https://github.com/ggerganov/llama.cpp.git && \
    cd llama.cpp && \
    mkdir build && \
    cd build && \
    cmake .. -DLLAMA_CURL=OFF && \
    make -j$(nproc) && \
    cp bin/llama-server /usr/local/bin/llama-cpp-server && \
    cd ../.. && rm -rf llama.cpp

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy LLM service code
COPY services/llm/ ./services/llm/
COPY core/ ./core/

# Create models directory
RUN mkdir -p /app/models

# Set environment variables
ENV MODEL_PATH=/app/models/quantized_model.gguf
ENV PYTHONPATH=/app

# Run LLM service
CMD ["python", "-m", "services.llm.main"]
