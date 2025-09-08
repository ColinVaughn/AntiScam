FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy bot service code
COPY services/bot/ ./services/bot/
COPY core/ ./core/
COPY database/ ./database/
COPY services/ocr/ocr_service.py ./services/ocr/ocr_service.py
COPY services/llm/llm_service.py ./services/llm/llm_service.py

# Create logs directory
RUN mkdir -p /app/logs

# Set environment variables
ENV PYTHONPATH=/app

# Run bot service
CMD ["python", "-m", "services.bot.main"]
