#!/usr/bin/env python3
"""
Health check script for AntiScam Bot deployment
Verifies all services are running correctly
"""

import asyncio
import aiohttp
import asyncpg
import redis.asyncio as redis
import sys
import os
from datetime import datetime

class HealthChecker:
    def __init__(self):
        self.results = {}
        
    async def check_database(self):
        """Check PostgreSQL connectivity"""
        try:
            db_url = os.getenv('DATABASE_URL', 'postgresql://antiscam:password@localhost:5432/antiscam_db')
            conn = await asyncpg.connect(db_url)
            
            # Test basic query
            result = await conn.fetchval('SELECT 1')
            await conn.close()
            
            self.results['database'] = {
                'status': 'healthy' if result == 1 else 'unhealthy',
                'details': 'PostgreSQL connection successful'
            }
            
        except Exception as e:
            self.results['database'] = {
                'status': 'unhealthy',
                'details': f'Database connection failed: {str(e)}'
            }
    
    async def check_redis(self):
        """Check Redis connectivity"""
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            r = redis.from_url(redis_url)
            
            # Test ping
            pong = await r.ping()
            await r.close()
            
            self.results['redis'] = {
                'status': 'healthy' if pong else 'unhealthy',
                'details': 'Redis connection successful'
            }
            
        except Exception as e:
            self.results['redis'] = {
                'status': 'unhealthy',
                'details': f'Redis connection failed: {str(e)}'
            }
    
    async def check_ocr_service(self):
        """Check OCR service health"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('http://localhost:8001/health', timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.results['ocr_service'] = {
                            'status': data.get('status', 'unknown'),
                            'details': data.get('details', 'OCR service responding')
                        }
                    else:
                        self.results['ocr_service'] = {
                            'status': 'unhealthy',
                            'details': f'OCR service returned status {response.status}'
                        }
        except Exception as e:
            self.results['ocr_service'] = {
                'status': 'unhealthy',
                'details': f'OCR service not accessible: {str(e)}'
            }
    
    async def check_llm_service(self):
        """Check LLM service health"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('http://localhost:8002/health', timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.results['llm_service'] = {
                            'status': data.get('status', 'unknown'),
                            'details': data.get('details', 'LLM service responding')
                        }
                    else:
                        self.results['llm_service'] = {
                            'status': 'unhealthy',
                            'details': f'LLM service returned status {response.status}'
                        }
        except Exception as e:
            self.results['llm_service'] = {
                'status': 'unhealthy',
                'details': f'LLM service not accessible: {str(e)}'
            }
    
    async def check_dashboard(self):
        """Check dashboard health"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('http://localhost:8080/api/health', timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.results['dashboard'] = {
                            'status': data.get('status', 'unknown'),
                            'details': data.get('details', 'Dashboard responding')
                        }
                    else:
                        self.results['dashboard'] = {
                            'status': 'unhealthy',
                            'details': f'Dashboard returned status {response.status}'
                        }
        except Exception as e:
            self.results['dashboard'] = {
                'status': 'unhealthy',
                'details': f'Dashboard not accessible: {str(e)}'
            }
    
    async def check_bot_status(self):
        """Check if bot is running via database stats"""
        try:
            db_url = os.getenv('DATABASE_URL', 'postgresql://antiscam:password@localhost:5432/antiscam_db')
            conn = await asyncpg.connect(db_url)
            
            # Check for recent system logs from bot component
            recent_logs = await conn.fetchval(
                "SELECT COUNT(*) FROM system_logs WHERE component = 'bot' AND created_at > NOW() - INTERVAL '5 minutes'"
            )
            
            await conn.close()
            
            self.results['bot_service'] = {
                'status': 'healthy' if recent_logs > 0 else 'warning',
                'details': f'Bot activity detected: {recent_logs} recent log entries' if recent_logs > 0 
                          else 'No recent bot activity (may be starting or idle)'
            }
            
        except Exception as e:
            self.results['bot_service'] = {
                'status': 'unknown',
                'details': f'Cannot check bot status: {str(e)}'
            }
    
    async def run_all_checks(self):
        """Run all health checks concurrently"""
        print(f"🔍 Running health checks at {datetime.utcnow().isoformat()}...")
        print("=" * 60)
        
        # Run checks concurrently
        await asyncio.gather(
            self.check_database(),
            self.check_redis(),
            self.check_ocr_service(),
            self.check_llm_service(),
            self.check_dashboard(),
            self.check_bot_status(),
            return_exceptions=True
        )
        
        # Print results
        all_healthy = True
        for service, result in self.results.items():
            status = result['status']
            details = result['details']
            
            if status == 'healthy':
                icon = "✅"
            elif status == 'warning':
                icon = "⚠️"
                all_healthy = False
            else:
                icon = "❌"
                all_healthy = False
            
            print(f"{icon} {service.replace('_', ' ').title()}: {status}")
            print(f"   {details}")
            print()
        
        print("=" * 60)
        if all_healthy:
            print("🎉 All services are healthy!")
            return 0
        else:
            print("⚠️  Some services have issues")
            return 1

async def main():
    """Main health check function"""
    checker = HealthChecker()
    return await checker.run_all_checks()

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
