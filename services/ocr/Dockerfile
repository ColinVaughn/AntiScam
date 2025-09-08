FROM python:3.11-slim

# Install system dependencies for Tesseract and image processing
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-eng \
    libtesseract-dev \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy OCR service code
COPY services/ocr/ ./services/ocr/
COPY core/ ./core/

# Create temp directory for image processing
RUN mkdir -p /app/temp_images

# Set environment variables
ENV TESSERACT_CMD=/usr/bin/tesseract
ENV PYTHONPATH=/app

# Run OCR service
CMD ["python", "-m", "services.ocr.main"]
