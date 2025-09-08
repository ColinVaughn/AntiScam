import asyncio
import json
import logging
import os
import time
from typing import Dict, List, Optional, Any
import subprocess
import tempfile
from dataclasses import dataclass
from redis import Redis

logger = logging.getLogger(__name__)

@dataclass
class LLMRequest:
    """LLM inference request"""
    message_text: str
    ocr_text: str
    metadata: Dict[str, Any]
    request_id: str
    timestamp: float

@dataclass
class LLMResponse:
    """LLM inference response"""
    label: str  # scam, not_scam, suspicious
    confidence: float
    indicator_tags: List[str]
    short_reason: str
    evidence: List[str]
    processing_time_ms: int
    model_version: str

class LLMInferenceService:
    """Offline LLM inference service using llama.cpp or similar quantized models"""
    
    def __init__(self, redis_client: Redis, model_path: str, model_config: Dict = None):
        self.redis_client = redis_client
        self.model_path = model_path
        self.model_config = model_config or {}
        
        # Default configuration
        self.config = {
            'max_tokens': 256,
            'temperature': 0.0,  # Deterministic output
            'top_p': 0.9,
            'top_k': 40,
            'threads': int(os.getenv('LLM_THREADS', 4)),
            'context_length': int(os.getenv('LLM_CONTEXT_LENGTH', 2048)),
            'timeout': int(os.getenv('LLM_TIMEOUT', 60))
        }
        self.config.update(self.model_config)
        
        # Model information
        self.model_version = "quantized_llama_7b_v1.0"
        self.is_ready = False
        
        # Prompt template
        self.system_prompt = """You are a safety classifier for Discord that only answers with JSON.
TASK: Given the message_text, attached_ocr_text (if any), and metadata, decide if this message is a scam/attempted fraud.

You must respond with ONLY valid JSON in this exact format:
{
  "label": "scam"|"not_scam"|"suspicious",
  "confidence": 0.0-1.0,
  "indicator_tags": ["payment_request","impersonation","phishing_link","urgent","refund_trick"],
  "short_reason": "one-sentence explanation",
  "evidence": ["contains 'venmo' and asks to DM", "ocr contains 'send to...'"]
}

GUIDELINES:
- Use "scam" for clear fraudulent content (confidence > 0.7)
- Use "suspicious" for borderline cases (confidence 0.3-0.7)  
- Use "not_scam" for legitimate content (confidence < 0.3)
- Keep short_reason under 100 characters
- Include specific evidence from the text
- Focus on: payment requests, impersonation, phishing, urgency tactics, verification scams"""

    async def initialize(self) -> bool:
        """Initialize the LLM service"""
        try:
            # Check if model file exists
            if not os.path.exists(self.model_path):
                logger.error(f"Model file not found: {self.model_path}")
                return False
            
            # Test model loading
            test_result = await self._test_model()
            if test_result:
                self.is_ready = True
                logger.info(f"LLM service initialized successfully with model: {self.model_path}")
                return True
            else:
                logger.error("Model test failed during initialization")
                return False
                
        except Exception as e:
            logger.error(f"Failed to initialize LLM service: {str(e)}")
            return False

    async def process_request(self, request: LLMRequest) -> LLMResponse:
        """Process LLM inference request"""
        start_time = time.time()
        
        if not self.is_ready:
            return self._create_error_response("LLM service not ready", start_time)
        
        try:
            # Create prompt
            prompt = self._create_prompt(request.message_text, request.ocr_text, request.metadata)
            
            # Run inference
            raw_response = await self._run_inference(prompt)
            
            # Parse response
            parsed_response = self._parse_response(raw_response)
            
            # Calculate processing time
            processing_time = int((time.time() - start_time) * 1000)
            
            return LLMResponse(
                label=parsed_response.get('label', 'not_scam'),
                confidence=parsed_response.get('confidence', 0.0),
                indicator_tags=parsed_response.get('indicator_tags', []),
                short_reason=parsed_response.get('short_reason', 'No specific reason'),
                evidence=parsed_response.get('evidence', []),
                processing_time_ms=processing_time,
                model_version=self.model_version
            )
            
        except Exception as e:
            logger.error(f"LLM inference failed: {str(e)}")
            return self._create_error_response(f"Inference failed: {str(e)}", start_time)

    def _create_prompt(self, message_text: str, ocr_text: str, metadata: Dict) -> str:
        """Create formatted prompt for the model"""
        # Truncate long texts to fit context window
        max_text_length = 800
        if len(message_text) > max_text_length:
            message_text = message_text[:max_text_length] + "..."
        
        if len(ocr_text) > max_text_length:
            ocr_text = ocr_text[:max_text_length] + "..."
        
        # Extract relevant metadata
        author_age_days = metadata.get('author_age_days', 'unknown')
        has_links = metadata.get('has_links', False)
        links = metadata.get('links', [])
        link_domains = [link.get('domain', '') for link in links[:3]]  # Limit to 3 domains
        
        metadata_summary = {
            'author_age_days': author_age_days,
            'has_links': has_links,
            'link_domains': link_domains,
            'message_length': len(message_text)
        }
        
        user_prompt = f"""INPUT:
message_text: "{message_text}"
ocr_text: "{ocr_text}"
metadata: {json.dumps(metadata_summary)}

OUTPUT (json):"""
        
        return f"{self.system_prompt}\n\n{user_prompt}"

    async def _run_inference(self, prompt: str) -> str:
        """Run model inference using llama.cpp or similar"""
        try:
            # Create temporary file for prompt
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(prompt)
                prompt_file = temp_file.name
            
            try:
                # Build command for llama.cpp
                cmd = [
                    'llama-cpp-server',  # or path to llama.cpp executable
                    '--model', self.model_path,
                    '--prompt-file', prompt_file,
                    '--n-predict', str(self.config['max_tokens']),
                    '--temp', str(self.config['temperature']),
                    '--top-p', str(self.config['top_p']),
                    '--top-k', str(self.config['top_k']),
                    '--threads', str(self.config['threads']),
                    '--ctx-size', str(self.config['context_length']),
                    '--no-display-prompt'
                ]
                
                # Run inference
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config['timeout']
                )
                
                if process.returncode != 0:
                    logger.error(f"LLM process failed: {stderr.decode()}")
                    return ""
                
                return stdout.decode().strip()
                
            finally:
                # Clean up temp file
                if os.path.exists(prompt_file):
                    os.unlink(prompt_file)
                    
        except asyncio.TimeoutError:
            logger.error("LLM inference timed out")
            return ""
        except Exception as e:
            logger.error(f"LLM inference execution failed: {str(e)}")
            return ""

    def _parse_response(self, raw_response: str) -> Dict:
        """Parse LLM response and extract JSON"""
        if not raw_response:
            return self._get_default_response()
        
        try:
            # Try to find JSON in response
            json_start = raw_response.find('{')
            json_end = raw_response.rfind('}') + 1
            
            if json_start == -1 or json_end == 0:
                logger.warning("No JSON found in LLM response")
                return self._get_default_response()
            
            json_str = raw_response[json_start:json_end]
            parsed = json.loads(json_str)
            
            # Validate required fields
            required_fields = ['label', 'confidence', 'short_reason']
            for field in required_fields:
                if field not in parsed:
                    logger.warning(f"Missing required field in LLM response: {field}")
                    return self._get_default_response()
            
            # Validate label
            valid_labels = ['scam', 'not_scam', 'suspicious']
            if parsed['label'] not in valid_labels:
                logger.warning(f"Invalid label in LLM response: {parsed['label']}")
                parsed['label'] = 'not_scam'
            
            # Validate confidence
            confidence = float(parsed['confidence'])
            if not 0.0 <= confidence <= 1.0:
                logger.warning(f"Invalid confidence in LLM response: {confidence}")
                parsed['confidence'] = 0.0
            
            # Set defaults for optional fields
            parsed.setdefault('indicator_tags', [])
            parsed.setdefault('evidence', [])
            
            return parsed
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON response: {str(e)}")
            return self._get_default_response()
        except Exception as e:
            logger.error(f"Error processing LLM response: {str(e)}")
            return self._get_default_response()

    def _get_default_response(self) -> Dict:
        """Get default response when parsing fails"""
        return {
            'label': 'not_scam',
            'confidence': 0.0,
            'indicator_tags': [],
            'short_reason': 'Failed to analyze message',
            'evidence': []
        }

    async def _test_model(self) -> bool:
        """Test model with a simple prompt"""
        try:
            test_prompt = f"{self.system_prompt}\n\nINPUT:\nmessage_text: \"Hello world\"\nocr_text: \"\"\nmetadata: {{}}\n\nOUTPUT (json):"
            
            response = await self._run_inference(test_prompt)
            if response:
                parsed = self._parse_response(response)
                return 'label' in parsed
            return False
            
        except Exception as e:
            logger.error(f"Model test failed: {str(e)}")
            return False

    def _create_error_response(self, error_message: str, start_time: float) -> LLMResponse:
        """Create error response"""
        processing_time = int((time.time() - start_time) * 1000)
        return LLMResponse(
            label='not_scam',
            confidence=0.0,
            indicator_tags=[],
            short_reason=f'Error: {error_message}',
            evidence=[],
            processing_time_ms=processing_time,
            model_version=self.model_version
        )

    async def health_check(self) -> Dict:
        """Health check for LLM service"""
        try:
            if not self.is_ready:
                return {
                    'status': 'unhealthy',
                    'error': 'Service not initialized',
                    'model_path': self.model_path
                }
            
            # Test inference
            test_request = LLMRequest(
                message_text="Test message",
                ocr_text="",
                metadata={'author_age_days': 5, 'has_links': False},
                request_id="health_check",
                timestamp=time.time()
            )
            
            response = await self.process_request(test_request)
            
            return {
                'status': 'healthy' if response.label in ['scam', 'not_scam', 'suspicious'] else 'unhealthy',
                'model_version': self.model_version,
                'model_path': self.model_path,
                'test_processing_time_ms': response.processing_time_ms,
                'config': self.config
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'model_path': self.model_path
            }

    def update_config(self, new_config: Dict) -> None:
        """Update model configuration"""
        self.config.update(new_config)
        logger.info(f"Updated LLM config: {new_config}")

    def get_stats(self) -> Dict:
        """Get service statistics"""
        return {
            'model_version': self.model_version,
            'model_path': self.model_path,
            'is_ready': self.is_ready,
            'config': self.config
        }
