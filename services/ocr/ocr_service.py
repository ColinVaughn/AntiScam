import asyncio
import logging
import os
import tempfile
import time
from typing import Optional, Dict, List
from PIL import Image, ImageEnhance, ImageFilter
import pytesseract
import aiohttp
import hashlib
from redis import Redis
import json

logger = logging.getLogger(__name__)

class OCRService:
    """Tesseract-based OCR service for extracting text from images"""
    
    def __init__(self, redis_client: Redis, tesseract_cmd: str = None):
        self.redis_client = redis_client
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
        
        # OCR configuration
        self.config = {
            'lang': 'eng',
            'config': '--oem 3 --psm 6 -c tessedit_char_whitelist=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.,!?@#$%&*()+-=[]{}|;:"\'/\\<>~ '
        }
        
        # Image preprocessing settings
        self.preprocess_settings = {
            'min_width': 100,
            'min_height': 100,
            'max_width': 2000,
            'max_height': 2000,
            'upscale_factor': 2,
            'contrast_factor': 1.5,
            'sharpness_factor': 2.0
        }
        
        # Cache settings (Redis)
        self.cache_ttl = 3600  # 1 hour
        self.cache_prefix = "ocr_cache:"

    async def process_image_url(self, image_url: str, timeout: int = 30) -> Dict:
        """Process image from URL and extract text"""
        start_time = time.time()
        
        # Check cache first
        cache_key = self._get_cache_key(image_url)
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            logger.info(f"OCR cache hit for {image_url}")
            return cached_result
        
        try:
            # Download image
            image_data = await self._download_image(image_url, timeout)
            if not image_data:
                return self._create_error_result("Failed to download image", start_time)
            
            # Process image
            result = await self._process_image_data(image_data, image_url)
            
            # Cache result
            self._cache_result(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"OCR processing failed for {image_url}: {str(e)}")
            return self._create_error_result(f"OCR processing failed: {str(e)}", start_time)

    async def process_image_data(self, image_data: bytes, source_info: str = "direct") -> Dict:
        """Process image data directly and extract text"""
        start_time = time.time()
        
        try:
            result = await self._process_image_data(image_data, source_info)
            return result
        except Exception as e:
            logger.error(f"OCR processing failed for {source_info}: {str(e)}")
            return self._create_error_result(f"OCR processing failed: {str(e)}", start_time)

    async def _download_image(self, url: str, timeout: int) -> Optional[bytes]:
        """Download image from URL"""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content_type = response.headers.get('content-type', '')
                        if not content_type.startswith('image/'):
                            logger.warning(f"Non-image content type: {content_type}")
                            return None
                        
                        # Check file size (max 10MB)
                        content_length = response.headers.get('content-length')
                        if content_length and int(content_length) > 10 * 1024 * 1024:
                            logger.warning(f"Image too large: {content_length} bytes")
                            return None
                        
                        return await response.read()
                    else:
                        logger.error(f"Failed to download image: HTTP {response.status}")
                        return None
        except Exception as e:
            logger.error(f"Error downloading image from {url}: {str(e)}")
            return None

    async def _process_image_data(self, image_data: bytes, source_info: str) -> Dict:
        """Process image data and extract text"""
        start_time = time.time()
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
            temp_path = temp_file.name
            
        try:
            # Load and preprocess image
            image = Image.open(io.BytesIO(image_data))
            preprocessed_image = self._preprocess_image(image)
            
            # Save preprocessed image
            preprocessed_image.save(temp_path)
            
            # Run OCR in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            ocr_result = await loop.run_in_executor(
                None, self._run_tesseract, temp_path
            )
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Analyze extracted text
            analysis = self._analyze_extracted_text(ocr_result['text'])
            
            result = {
                'success': True,
                'text': ocr_result['text'],
                'confidence': ocr_result['confidence'],
                'word_count': len(ocr_result['text'].split()),
                'char_count': len(ocr_result['text']),
                'processing_time_ms': int(processing_time * 1000),
                'source': source_info,
                'analysis': analysis,
                'timestamp': time.time()
            }
            
            logger.info(f"OCR completed for {source_info}: {len(ocr_result['text'])} chars, {processing_time:.2f}s")
            return result
            
        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _preprocess_image(self, image: Image.Image) -> Image.Image:
        """Preprocess image for better OCR results"""
        # Convert to RGB if necessary
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Get image dimensions
        width, height = image.size
        
        # Upscale small images
        if width < self.preprocess_settings['min_width'] or height < self.preprocess_settings['min_height']:
            scale_factor = max(
                self.preprocess_settings['min_width'] / width,
                self.preprocess_settings['min_height'] / height,
                self.preprocess_settings['upscale_factor']
            )
            new_width = int(width * scale_factor)
            new_height = int(height * scale_factor)
            image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        # Downscale very large images
        elif width > self.preprocess_settings['max_width'] or height > self.preprocess_settings['max_height']:
            scale_factor = min(
                self.preprocess_settings['max_width'] / width,
                self.preprocess_settings['max_height'] / height
            )
            new_width = int(width * scale_factor)
            new_height = int(height * scale_factor)
            image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        # Enhance contrast
        enhancer = ImageEnhance.Contrast(image)
        image = enhancer.enhance(self.preprocess_settings['contrast_factor'])
        
        # Enhance sharpness
        enhancer = ImageEnhance.Sharpness(image)
        image = enhancer.enhance(self.preprocess_settings['sharpness_factor'])
        
        # Apply slight gaussian blur to smooth noise
        image = image.filter(ImageFilter.GaussianBlur(radius=0.5))
        
        return image

    def _run_tesseract(self, image_path: str) -> Dict:
        """Run Tesseract OCR on image"""
        try:
            # Extract text with confidence scores
            data = pytesseract.image_to_data(
                image_path, 
                lang=self.config['lang'],
                config=self.config['config'],
                output_type=pytesseract.Output.DICT
            )
            
            # Extract text
            text = pytesseract.image_to_string(
                image_path,
                lang=self.config['lang'],
                config=self.config['config']
            ).strip()
            
            # Calculate average confidence
            confidences = [int(conf) for conf in data['conf'] if int(conf) > 0]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            
            return {
                'text': text,
                'confidence': avg_confidence,
                'word_data': data
            }
            
        except Exception as e:
            logger.error(f"Tesseract OCR failed: {str(e)}")
            return {
                'text': '',
                'confidence': 0,
                'word_data': None
            }

    def _analyze_extracted_text(self, text: str) -> Dict:
        """Analyze extracted text for suspicious patterns"""
        analysis = {
            'has_urls': False,
            'has_emails': False,
            'has_phone_numbers': False,
            'has_payment_info': False,
            'has_suspicious_keywords': False,
            'language_confidence': 'high'
        }
        
        if not text:
            return analysis
        
        text_lower = text.lower()
        
        # Check for URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        if re.search(url_pattern, text):
            analysis['has_urls'] = True
        
        # Check for email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if re.search(email_pattern, text):
            analysis['has_emails'] = True
        
        # Check for phone numbers
        phone_pattern = r'(\+?\d{1,3}[\s-]?)?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}'
        if re.search(phone_pattern, text):
            analysis['has_phone_numbers'] = True
        
        # Check for payment information
        payment_keywords = ['venmo', 'cashapp', 'paypal', 'zelle', '$', 'payment', 'money', 'send']
        if any(keyword in text_lower for keyword in payment_keywords):
            analysis['has_payment_info'] = True
        
        # Check for suspicious keywords
        suspicious_keywords = ['urgent', 'verify', 'suspend', 'click here', 'claim now', 'limited time']
        if any(keyword in text_lower for keyword in suspicious_keywords):
            analysis['has_suspicious_keywords'] = True
        
        # Simple language confidence based on character distribution
        ascii_chars = sum(1 for c in text if ord(c) < 128)
        if text:
            ascii_ratio = ascii_chars / len(text)
            if ascii_ratio < 0.8:
                analysis['language_confidence'] = 'low'
            elif ascii_ratio < 0.9:
                analysis['language_confidence'] = 'medium'
        
        return analysis

    def _get_cache_key(self, image_url: str) -> str:
        """Generate cache key for image URL"""
        return f"{self.cache_prefix}{hashlib.md5(image_url.encode()).hexdigest()}"

    def _get_cached_result(self, cache_key: str) -> Optional[Dict]:
        """Get cached OCR result"""
        try:
            cached_data = self.redis_client.get(cache_key)
            if cached_data:
                return json.loads(cached_data)
        except Exception as e:
            logger.warning(f"Failed to get cached result: {str(e)}")
        return None

    def _cache_result(self, cache_key: str, result: Dict) -> None:
        """Cache OCR result"""
        try:
            self.redis_client.setex(
                cache_key, 
                self.cache_ttl, 
                json.dumps(result, default=str)
            )
        except Exception as e:
            logger.warning(f"Failed to cache result: {str(e)}")

    def _create_error_result(self, error_message: str, start_time: float) -> Dict:
        """Create error result dictionary"""
        return {
            'success': False,
            'error': error_message,
            'text': '',
            'confidence': 0,
            'word_count': 0,
            'char_count': 0,
            'processing_time_ms': int((time.time() - start_time) * 1000),
            'timestamp': time.time()
        }

    async def health_check(self) -> Dict:
        """Health check for OCR service"""
        try:
            # Test with a simple image
            test_image = Image.new('RGB', (200, 50), color='white')
            
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
                test_image.save(temp_file.name)
                temp_path = temp_file.name
            
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, self._run_tesseract, temp_path)
                
                return {
                    'status': 'healthy',
                    'tesseract_available': True,
                    'test_confidence': result['confidence']
                }
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                    
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'tesseract_available': False
            }

# Import needed for image processing
import io
import re
