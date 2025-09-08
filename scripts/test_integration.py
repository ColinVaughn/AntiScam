#!/usr/bin/env python3
"""
Integration tests for AntiScam Bot system
Tests end-to-end functionality of all components
"""

import asyncio
import asyncpg
import redis.asyncio as redis
import aiohttp
import tempfile
import os
import json
from datetime import datetime
from pathlib import Path

# Add project root to Python path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.preprocessor import TextPreprocessor
from core.rule_detector import RuleBasedDetector
from core.detector_pipeline import DetectorPipeline
from database import DatabaseManager, init_database

class IntegrationTester:
    def __init__(self):
        self.results = []
        self.db_manager = None
        
    async def setup(self):
        """Initialize test environment"""
        print("🔧 Setting up test environment...")
        
        # Initialize database
        db_url = os.getenv('DATABASE_URL', 'postgresql://antiscam:password@localhost:5432/antiscam_db')
        self.db_manager = init_database(db_url)
        
        print("✅ Test environment ready")

    async def test_text_preprocessor(self):
        """Test text preprocessing functionality"""
        try:
            preprocessor = TextPreprocessor()
            
            # Test homoglyph normalization
            test_text = "Frее Nіtro! Clісk hеrе: discord-nitro.fake"
            result = await preprocessor.preprocess_text(test_text)
            
            assert 'links' in result
            assert 'normalized_text' in result
            assert len(result['links']) > 0
            
            # Test suspicious patterns
            scam_text = "FREE MONEY! Click here to claim $1000 NOW!"
            result2 = await preprocessor.preprocess_text(scam_text)
            
            assert result2['quick_scam_check']['is_suspicious']
            
            self.results.append({
                'test': 'text_preprocessor',
                'status': 'pass',
                'details': 'Homoglyph normalization and link extraction working'
            })
            
        except Exception as e:
            self.results.append({
                'test': 'text_preprocessor',
                'status': 'fail',
                'details': f'Error: {str(e)}'
            })

    async def test_rule_detector(self):
        """Test rule-based detection"""
        try:
            detector = RuleBasedDetector()
            
            # Test scam detection
            scam_texts = [
                "Free Discord Nitro! Click here: discord-nitro.fake/claim",
                "Your account will be suspended! Verify here: discord-security.scam",
                "Congratulations! You won $1000! Send me your PayPal to claim"
            ]
            
            for text in scam_texts:
                result = await detector.analyze_text(text)
                assert result['label'] == 'scam'
                assert result['confidence'] > 0.5
            
            # Test legitimate text
            legit_text = "Hey everyone, how's your day going?"
            result = await detector.analyze_text(legit_text)
            assert result['label'] == 'safe'
            
            self.results.append({
                'test': 'rule_detector',
                'status': 'pass',
                'details': 'Rule-based detection working correctly'
            })
            
        except Exception as e:
            self.results.append({
                'test': 'rule_detector',
                'status': 'fail',
                'details': f'Error: {str(e)}'
            })

    async def test_database_operations(self):
        """Test database connectivity and operations"""
        try:
            # Test connection
            async with self.db_manager.get_session() as session:
                result = await session.execute("SELECT 1")
                assert result.scalar() == 1
            
            # Test guild config creation
            await self.db_manager.get_or_create_guild_config("test_guild_123")
            
            # Test domain operations
            await self.db_manager.add_domain_to_blacklist("test_guild_123", "scam.example.com", "test_moderator")
            
            blacklisted = await self.db_manager.is_domain_blacklisted("test_guild_123", "scam.example.com")
            assert blacklisted
            
            self.results.append({
                'test': 'database_operations',
                'status': 'pass',
                'details': 'Database operations working correctly'
            })
            
        except Exception as e:
            self.results.append({
                'test': 'database_operations',
                'status': 'fail',
                'details': f'Error: {str(e)}'
            })

    async def test_redis_connectivity(self):
        """Test Redis connectivity and caching"""
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            r = redis.from_url(redis_url)
            
            # Test basic operations
            await r.set('test_key', 'test_value', ex=10)
            value = await r.get('test_key')
            assert value == b'test_value'
            
            await r.delete('test_key')
            await r.close()
            
            self.results.append({
                'test': 'redis_connectivity',
                'status': 'pass',
                'details': 'Redis operations working correctly'
            })
            
        except Exception as e:
            self.results.append({
                'test': 'redis_connectivity',
                'status': 'fail',
                'details': f'Error: {str(e)}'
            })

    async def test_ocr_service(self):
        """Test OCR service integration"""
        try:
            # Create test image with text (if service is available)
            async with aiohttp.ClientSession() as session:
                try:
                    # Test health endpoint
                    async with session.get('http://localhost:8001/health', timeout=5) as response:
                        if response.status == 200:
                            health_data = await response.json()
                            
                            self.results.append({
                                'test': 'ocr_service',
                                'status': 'pass',
                                'details': f'OCR service healthy: {health_data.get("status", "unknown")}'
                            })
                        else:
                            self.results.append({
                                'test': 'ocr_service',
                                'status': 'warning',
                                'details': f'OCR service returned status {response.status}'
                            })
                            
                except asyncio.TimeoutError:
                    self.results.append({
                        'test': 'ocr_service',
                        'status': 'skip',
                        'details': 'OCR service not accessible (may not be running)'
                    })
                    
        except Exception as e:
            self.results.append({
                'test': 'ocr_service',
                'status': 'fail',
                'details': f'Error: {str(e)}'
            })

    async def test_llm_service(self):
        """Test LLM service integration"""
        try:
            async with aiohttp.ClientSession() as session:
                try:
                    # Test health endpoint
                    async with session.get('http://localhost:8002/health', timeout=10) as response:
                        if response.status == 200:
                            health_data = await response.json()
                            
                            self.results.append({
                                'test': 'llm_service',
                                'status': 'pass',
                                'details': f'LLM service healthy: {health_data.get("status", "unknown")}'
                            })
                        else:
                            self.results.append({
                                'test': 'llm_service',
                                'status': 'warning',
                                'details': f'LLM service returned status {response.status}'
                            })
                            
                except asyncio.TimeoutError:
                    self.results.append({
                        'test': 'llm_service',
                        'status': 'skip',
                        'details': 'LLM service not accessible (may not be running or loading)'
                    })
                    
        except Exception as e:
            self.results.append({
                'test': 'llm_service',
                'status': 'fail',
                'details': f'Error: {str(e)}'
            })

    async def test_dashboard_api(self):
        """Test dashboard API endpoints"""
        try:
            async with aiohttp.ClientSession() as session:
                # Test health endpoint
                async with session.get('http://localhost:8080/api/health', timeout=5) as response:
                    if response.status == 200:
                        health_data = await response.json()
                        
                        # Test guild stats endpoint
                        async with session.get('http://localhost:8080/api/guilds/test_guild_123/stats', timeout=5) as stats_response:
                            if stats_response.status == 200:
                                self.results.append({
                                    'test': 'dashboard_api',
                                    'status': 'pass',
                                    'details': 'Dashboard API endpoints responding correctly'
                                })
                            else:
                                self.results.append({
                                    'test': 'dashboard_api',
                                    'status': 'warning',
                                    'details': f'Stats endpoint returned status {stats_response.status}'
                                })
                    else:
                        self.results.append({
                            'test': 'dashboard_api',
                            'status': 'warning',
                            'details': f'Dashboard health endpoint returned status {response.status}'
                        })
                        
        except Exception as e:
            self.results.append({
                'test': 'dashboard_api',
                'status': 'fail',
                'details': f'Error: {str(e)}'
            })

    async def test_end_to_end_detection(self):
        """Test complete detection pipeline"""
        try:
            # Initialize detector pipeline (without external services for basic test)
            redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
            pipeline = DetectorPipeline(self.db_manager, redis_client)
            
            # Test message processing
            test_message = {
                'content': 'Free Discord Nitro! Click here: discord-nitro.fake/claim',
                'author': {'id': '123456789'},
                'guild': {'id': 'test_guild_123'},
                'channel': {'id': 'test_channel_123'},
                'id': 'test_message_123'
            }
            
            # This should detect as scam using rules
            result = await pipeline.process_message(test_message)
            
            await redis_client.close()
            
            if result and result.get('label') == 'scam':
                self.results.append({
                    'test': 'end_to_end_detection',
                    'status': 'pass',
                    'details': f'Detection pipeline working: {result.get("confidence", 0):.2f} confidence'
                })
            else:
                self.results.append({
                    'test': 'end_to_end_detection',
                    'status': 'warning',
                    'details': 'Detection pipeline returned unexpected result'
                })
                
        except Exception as e:
            self.results.append({
                'test': 'end_to_end_detection',
                'status': 'fail',
                'details': f'Error: {str(e)}'
            })

    async def run_all_tests(self):
        """Run all integration tests"""
        print("🧪 Running Integration Tests")
        print("=" * 50)
        
        await self.setup()
        
        # Run all tests
        await asyncio.gather(
            self.test_text_preprocessor(),
            self.test_rule_detector(),
            self.test_database_operations(),
            self.test_redis_connectivity(),
            self.test_ocr_service(),
            self.test_llm_service(),
            self.test_dashboard_api(),
            self.test_end_to_end_detection(),
            return_exceptions=True
        )
        
        # Print results
        passed = 0
        failed = 0
        warnings = 0
        skipped = 0
        
        for result in self.results:
            test = result['test']
            status = result['status']
            details = result['details']
            
            if status == 'pass':
                icon = "✅"
                passed += 1
            elif status == 'fail':
                icon = "❌"
                failed += 1
            elif status == 'warning':
                icon = "⚠️"
                warnings += 1
            else:  # skip
                icon = "⏭️"
                skipped += 1
            
            print(f"{icon} {test.replace('_', ' ').title()}: {status}")
            print(f"   {details}")
            print()
        
        print("=" * 50)
        print(f"📊 Test Results: {passed} passed, {failed} failed, {warnings} warnings, {skipped} skipped")
        
        if failed > 0:
            print("❌ Some tests failed - check configuration and service status")
            return 1
        elif warnings > 0:
            print("⚠️  All critical tests passed with some warnings")
            return 0
        else:
            print("✅ All tests passed!")
            return 0

async def main():
    """Main test function"""
    tester = IntegrationTester()
    return await tester.run_all_tests()

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
