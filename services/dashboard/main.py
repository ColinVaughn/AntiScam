import asyncio
import logging
import os
import uvicorn
from .dashboard_api import DashboardAPI
from ...database import init_database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def main():
    """Main entry point for dashboard service"""
    logger.info("Starting Anti-Scam Bot Dashboard...")
    
    # Initialize database
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        raise ValueError("DATABASE_URL environment variable not set")
    
    db_manager = init_database(database_url)
    
    # Initialize dashboard API
    dashboard = DashboardAPI(db_manager)
    app = dashboard.get_app()
    
    # Configure server
    host = os.getenv('DASHBOARD_HOST', '0.0.0.0')
    port = int(os.getenv('DASHBOARD_PORT', 8080))
    
    logger.info(f"Dashboard will be available at http://{host}:{port}")
    
    # Run server
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=True
    )
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
