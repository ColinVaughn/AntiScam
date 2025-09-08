FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy dashboard service code
COPY services/dashboard/ ./services/dashboard/
COPY database/ ./database/

# Set environment variables
ENV PYTHONPATH=/app
ENV DASHBOARD_HOST=0.0.0.0
ENV DASHBOARD_PORT=8080

# Expose port
EXPOSE 8080

# Run dashboard service
CMD ["python", "-m", "services.dashboard.main"]
