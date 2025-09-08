import asyncio
import logging
import os
from redis import Redis
from fastapi import FastAPI
import uvicorn
from .ocr_service import OCRService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app: FastAPI | None = None
ocr_service: OCRService | None = None

def build_app() -> FastAPI:
    global app, ocr_service
    logger.info("Starting OCR service (HTTP mode)...")

    # Initialize Redis connection
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    redis_client = Redis.from_url(redis_url, decode_responses=True)

    # Initialize OCR service
    tesseract_cmd = os.getenv('TESSERACT_CMD', '/usr/bin/tesseract')
    ocr_service = OCRService(redis_client, tesseract_cmd)

    app = FastAPI(title="OCR Service", version="1.0.0")

    @app.get("/health")
    async def health():
        return await ocr_service.health_check()

    return app


async def main():
    application = build_app()

    host = os.getenv('OCR_HOST', '0.0.0.0')
    port = int(os.getenv('OCR_PORT', '8001'))
    logger.info(f"OCR service HTTP server on http://{host}:{port}")

    config = uvicorn.Config(application, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
