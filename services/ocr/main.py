import asyncio
import logging
import os
from redis import Redis
from .ocr_service import OCRService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def main():
    """Main entry point for OCR service"""
    logger.info("Starting OCR service...")
    
    # Initialize Redis connection
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    redis_client = Redis.from_url(redis_url, decode_responses=True)
    
    # Initialize OCR service
    tesseract_cmd = os.getenv('TESSERACT_CMD', '/usr/bin/tesseract')
    ocr_service = OCRService(redis_client, tesseract_cmd)
    
    # Health check
    health = await ocr_service.health_check()
    logger.info(f"OCR service health: {health}")
    
    if health['status'] != 'healthy':
        logger.error("OCR service is not healthy, exiting...")
        return
    
    logger.info("OCR service is ready and healthy")
    
    # Keep service running
    try:
        while True:
            await asyncio.sleep(60)  # Heartbeat every minute
            
    except KeyboardInterrupt:
        logger.info("OCR service shutting down...")

if __name__ == "__main__":
    asyncio.run(main())
