import asyncio
import logging
import os
from redis import Redis
from .llm_service import LLMInferenceService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def main():
    """Main entry point for LLM inference service"""
    logger.info("Starting LLM inference service...")
    
    # Initialize Redis connection
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    redis_client = Redis.from_url(redis_url, decode_responses=True)
    
    # Initialize LLM service
    model_path = os.getenv('MODEL_PATH', './models/quantized_model.gguf')
    llm_service = LLMInferenceService(redis_client, model_path)
    
    # Initialize service
    initialized = await llm_service.initialize()
    if not initialized:
        logger.error("Failed to initialize LLM service, exiting...")
        return
    
    # Health check
    health = await llm_service.health_check()
    logger.info(f"LLM service health: {health}")
    
    if health['status'] != 'healthy':
        logger.error("LLM service is not healthy, exiting...")
        return
    
    logger.info("LLM service is ready and healthy")
    
    # Keep service running
    try:
        while True:
            await asyncio.sleep(60)  # Heartbeat every minute
            
    except KeyboardInterrupt:
        logger.info("LLM service shutting down...")

if __name__ == "__main__":
    asyncio.run(main())
