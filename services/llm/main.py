import asyncio
import logging
import os
from redis import Redis
from fastapi import FastAPI
import uvicorn
from .llm_service import LLMInferenceService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app: FastAPI | None = None
llm_service: LLMInferenceService | None = None

def build_app() -> FastAPI:
    """Build FastAPI app exposing /health for LLM service"""
    global app, llm_service

    logger.info("Starting LLM inference service (HTTP mode)...")

    # Initialize Redis connection
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    redis_client = Redis.from_url(redis_url, decode_responses=True)

    # Initialize LLM service
    model_path = os.getenv('MODEL_PATH', './models/quantized_model.gguf')
    llm_service = LLMInferenceService(redis_client, model_path)

    app = FastAPI(title="LLM Service", version="1.0.0")

    @app.on_event("startup")
    async def startup_event():
        initialized = await llm_service.initialize()
        if not initialized:
            logger.error("LLM service failed to initialize at startup")

    @app.get("/health")
    async def health():
        return await llm_service.health_check()

    return app


async def main():
    application = build_app()

    host = os.getenv('LLM_HOST', '0.0.0.0')
    port = int(os.getenv('LLM_PORT', '8002'))
    logger.info(f"LLM service HTTP server on http://{host}:{port}")

    config = uvicorn.Config(application, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
