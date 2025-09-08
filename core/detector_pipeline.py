import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from redis import Redis
import json

from .preprocessor import TextPreprocessor
from .rule_detector import RuleBasedDetector
from ..services.ocr.ocr_service import OCRService
from ..services.llm.llm_service import LLMInferenceService, LLMRequest
from ..database import DatabaseManager, FlaggedMessage, DomainBlacklist, DomainWhitelist

logger = logging.getLogger(__name__)

@dataclass
class DetectionRequest:
    """Detection pipeline request"""
    message_id: str
    guild_id: str
    channel_id: str
    author_id: str
    text: str
    attachments: List[str]  # URLs to images
    metadata: Dict[str, Any]
    timestamp: float

@dataclass
class DetectionResult:
    """Detection pipeline result"""
    message_id: str
    label: str  # scam, not_scam, suspicious
    confidence: float
    processing_time_ms: int
    rule_results: Dict
    ocr_results: List[Dict]
    llm_result: Optional[Dict]
    final_reason: str
    evidence: List[str]
    indicator_tags: List[str]
    recommended_action: str  # delete, flag, monitor, ignore

class DetectionPipeline:
    """Main detection pipeline coordinating all detection components"""
    
    def __init__(
        self,
        db_manager: DatabaseManager,
        redis_client: Redis,
        ocr_service: OCRService,
        llm_service: LLMInferenceService
    ):
        self.db_manager = db_manager
        self.redis_client = redis_client
        self.ocr_service = ocr_service
        self.llm_service = llm_service
        
        # Initialize components
        self.preprocessor = TextPreprocessor()
        self.rule_detector = RuleBasedDetector()
        
        # Pipeline configuration
        self.config = {
            'quick_rule_threshold': 0.7,  # Auto-action on high rule confidence
            'llm_threshold': 0.3,         # Use LLM if rule confidence is above this
            'final_scam_threshold': 0.7,  # Final decision threshold
            'suspicious_threshold': 0.3,   # Flag as suspicious above this
            'max_processing_time': 30,    # Max processing time in seconds
            'enable_domain_cache': True,
            'parallel_ocr': True
        }
        
        # Cache for domain lookups
        self.domain_cache = {}
        
        # Statistics
        self.stats = {
            'total_processed': 0,
            'scams_detected': 0,
            'false_positives': 0,
            'avg_processing_time': 0.0,
            'rule_only_decisions': 0,
            'llm_decisions': 0,
            'ocr_processed': 0
        }

    async def process_message(self, request: DetectionRequest) -> DetectionResult:
        """Process message through complete detection pipeline"""
        start_time = time.time()
        
        logger.info(f"Processing message {request.message_id} from guild {request.guild_id}")
        
        try:
            # Step 1: Preprocess text
            features = self.preprocessor.extract_features(request.text, request.metadata)
            
            # Step 2: Quick domain blacklist check
            domain_check = await self._check_domain_blacklist(features['links'], request.guild_id)
            if domain_check['is_blacklisted']:
                return self._create_blacklist_result(request, domain_check, start_time)
            
            # Step 3: Quick rule-based check
            rule_result = self.rule_detector.evaluate_rules(
                request.text, 
                request.metadata, 
                ""  # No OCR text yet
            )
            
            # Step 4: Check if we can make decision with rules alone
            if rule_result['total_confidence'] >= self.config['quick_rule_threshold']:
                self.stats['rule_only_decisions'] += 1
                return await self._create_rule_based_result(request, rule_result, [], start_time)
            
            # Step 5: Process attachments with OCR (if any)
            ocr_results = []
            combined_ocr_text = ""
            
            if request.attachments and self.config['parallel_ocr']:
                ocr_results = await self._process_attachments(request.attachments)
                combined_ocr_text = " ".join([result.get('text', '') for result in ocr_results if result.get('success')])
                self.stats['ocr_processed'] += len(request.attachments)
            
            # Step 6: Re-evaluate rules with OCR text
            if combined_ocr_text:
                rule_result = self.rule_detector.evaluate_rules(
                    request.text,
                    request.metadata,
                    combined_ocr_text
                )
                
                # Check again if rules are now confident enough
                if rule_result['total_confidence'] >= self.config['quick_rule_threshold']:
                    self.stats['rule_only_decisions'] += 1
                    return await self._create_rule_based_result(request, rule_result, ocr_results, start_time)
            
            # Step 7: Use LLM for complex analysis
            llm_result = None
            if (rule_result['total_confidence'] >= self.config['llm_threshold'] or 
                combined_ocr_text or 
                len(features['links']) > 0):
                
                llm_request = LLMRequest(
                    message_text=request.text,
                    ocr_text=combined_ocr_text,
                    metadata=request.metadata,
                    request_id=request.message_id,
                    timestamp=request.timestamp
                )
                
                llm_response = await self.llm_service.process_request(llm_request)
                llm_result = {
                    'label': llm_response.label,
                    'confidence': llm_response.confidence,
                    'indicator_tags': llm_response.indicator_tags,
                    'short_reason': llm_response.short_reason,
                    'evidence': llm_response.evidence
                }
                self.stats['llm_decisions'] += 1
            
            # Step 8: Combine results and make final decision
            final_result = await self._combine_results(
                request, rule_result, ocr_results, llm_result, start_time
            )
            
            # Step 9: Store result in database
            await self._store_detection_result(final_result)
            
            # Update statistics
            self._update_stats(final_result, start_time)
            
            return final_result
            
        except Exception as e:
            logger.error(f"Detection pipeline failed for message {request.message_id}: {str(e)}")
            return self._create_error_result(request, str(e), start_time)

    async def _check_domain_blacklist(self, links: List[Dict], guild_id: str) -> Dict:
        """Check if any links point to blacklisted domains"""
        if not links:
            return {'is_blacklisted': False, 'blacklisted_domains': []}
        
        blacklisted_domains = []
        
        # Get cached blacklist or fetch from database
        cache_key = f"blacklist:{guild_id}"
        blacklist = self.domain_cache.get(cache_key)
        
        if blacklist is None:
            async with self.db_manager.get_session() as session:
                result = await session.execute(
                    "SELECT domain FROM domains_blacklist WHERE guild_id = $1 AND is_active = true",
                    guild_id
                )
                blacklist = [row[0] for row in result.fetchall()]
                
                # Cache for 5 minutes
                self.domain_cache[cache_key] = blacklist
                if self.config['enable_domain_cache']:
                    self.redis_client.setex(cache_key, 300, json.dumps(blacklist))
        
        # Check each link
        for link in links:
            domain = link.get('domain', '').lower()
            if domain in blacklist:
                blacklisted_domains.append(domain)
        
        return {
            'is_blacklisted': len(blacklisted_domains) > 0,
            'blacklisted_domains': blacklisted_domains
        }

    async def _process_attachments(self, attachment_urls: List[str]) -> List[Dict]:
        """Process image attachments with OCR"""
        if not attachment_urls:
            return []
        
        ocr_tasks = []
        for url in attachment_urls:
            task = self.ocr_service.process_image_url(url)
            ocr_tasks.append(task)
        
        # Process all images in parallel
        ocr_results = await asyncio.gather(*ocr_tasks, return_exceptions=True)
        
        # Filter out exceptions and failed results
        valid_results = []
        for i, result in enumerate(ocr_results):
            if isinstance(result, Exception):
                logger.warning(f"OCR failed for attachment {attachment_urls[i]}: {str(result)}")
                continue
            if isinstance(result, dict):
                valid_results.append(result)
        
        return valid_results

    async def _combine_results(
        self, 
        request: DetectionRequest, 
        rule_result: Dict, 
        ocr_results: List[Dict], 
        llm_result: Optional[Dict],
        start_time: float
    ) -> DetectionResult:
        """Combine rule, OCR, and LLM results into final decision"""
        
        processing_time = int((time.time() - start_time) * 1000)
        
        # Initialize final result
        final_confidence = 0.0
        final_label = "not_scam"
        final_reason = "No scam indicators detected"
        all_evidence = []
        all_indicator_tags = []
        
        # Combine rule results
        rule_confidence = rule_result.get('total_confidence', 0.0)
        rule_evidence = rule_result.get('evidence', [])
        
        if rule_confidence > 0:
            final_confidence += rule_confidence * 0.4  # Rules weight 40%
            all_evidence.extend(rule_evidence)
        
        # Combine OCR results
        ocr_confidence = 0.0
        for ocr_result in ocr_results:
            if ocr_result.get('success') and ocr_result.get('analysis'):
                analysis = ocr_result['analysis']
                # Boost confidence if OCR contains suspicious content
                if analysis.get('has_payment_info') or analysis.get('has_suspicious_keywords'):
                    ocr_confidence += 0.2
                if analysis.get('has_urls'):
                    ocr_confidence += 0.1
        
        final_confidence += min(ocr_confidence, 0.3)  # OCR weight max 30%
        
        # Combine LLM results
        if llm_result:
            llm_confidence = llm_result.get('confidence', 0.0)
            llm_label = llm_result.get('label', 'not_scam')
            
            # LLM gets the highest weight for complex cases
            if llm_label == 'scam':
                final_confidence = max(final_confidence, llm_confidence * 0.8)
            elif llm_label == 'suspicious':
                final_confidence = max(final_confidence, llm_confidence * 0.6)
            
            all_evidence.extend(llm_result.get('evidence', []))
            all_indicator_tags.extend(llm_result.get('indicator_tags', []))
            
            if llm_result.get('short_reason'):
                final_reason = llm_result['short_reason']
        
        # Normalize final confidence
        final_confidence = min(final_confidence, 1.0)
        
        # Determine final label
        if final_confidence >= self.config['final_scam_threshold']:
            final_label = "scam"
        elif final_confidence >= self.config['suspicious_threshold']:
            final_label = "suspicious"
        else:
            final_label = "not_scam"
        
        # Determine recommended action
        recommended_action = self._determine_action(final_label, final_confidence, request.guild_id)
        
        return DetectionResult(
            message_id=request.message_id,
            label=final_label,
            confidence=final_confidence,
            processing_time_ms=processing_time,
            rule_results=rule_result,
            ocr_results=ocr_results,
            llm_result=llm_result,
            final_reason=final_reason,
            evidence=all_evidence,
            indicator_tags=all_indicator_tags,
            recommended_action=recommended_action
        )

    def _determine_action(self, label: str, confidence: float, guild_id: str) -> str:
        """Determine recommended action based on detection results"""
        if label == "scam" and confidence >= 0.9:
            return "delete"
        elif label == "scam" and confidence >= 0.7:
            return "flag"
        elif label == "suspicious":
            return "monitor"
        else:
            return "ignore"

    async def _store_detection_result(self, result: DetectionResult) -> None:
        """Store detection result in database"""
        try:
            async with self.db_manager.get_session() as session:
                flagged_message = FlaggedMessage(
                    guild_id=result.rule_results.get('metadata', {}).get('guild_id', ''),
                    channel_id=result.rule_results.get('metadata', {}).get('channel_id', ''),
                    message_id=result.message_id,
                    author_id=result.rule_results.get('metadata', {}).get('author_id', ''),
                    text=result.rule_results.get('original_text', ''),
                    ocr_text=" ".join([r.get('text', '') for r in result.ocr_results if r.get('success')]),
                    label=result.label,
                    confidence=result.confidence,
                    rules_triggered=json.dumps(result.rule_results.get('triggered_rules', [])),
                    indicator_tags=json.dumps(result.indicator_tags),
                    short_reason=result.final_reason,
                    evidence=json.dumps(result.evidence),
                    model_version=result.llm_result.get('model_version') if result.llm_result else None,
                    status='pending'
                )
                
                session.add(flagged_message)
                await session.commit()
                
        except Exception as e:
            logger.error(f"Failed to store detection result: {str(e)}")

    def _create_blacklist_result(self, request: DetectionRequest, domain_check: Dict, start_time: float) -> DetectionResult:
        """Create result for blacklisted domain"""
        processing_time = int((time.time() - start_time) * 1000)
        
        return DetectionResult(
            message_id=request.message_id,
            label="scam",
            confidence=1.0,
            processing_time_ms=processing_time,
            rule_results={'triggered_rules': ['domain_blacklist']},
            ocr_results=[],
            llm_result=None,
            final_reason=f"Contains blacklisted domain: {', '.join(domain_check['blacklisted_domains'])}",
            evidence=domain_check['blacklisted_domains'],
            indicator_tags=['blacklisted_domain'],
            recommended_action="delete"
        )

    async def _create_rule_based_result(self, request: DetectionRequest, rule_result: Dict, ocr_results: List[Dict], start_time: float) -> DetectionResult:
        """Create result based on rules only"""
        processing_time = int((time.time() - start_time) * 1000)
        confidence = rule_result['total_confidence']
        
        label = "scam" if confidence >= 0.7 else "suspicious" if confidence >= 0.3 else "not_scam"
        action = self._determine_action(label, confidence, request.guild_id)
        
        return DetectionResult(
            message_id=request.message_id,
            label=label,
            confidence=confidence,
            processing_time_ms=processing_time,
            rule_results=rule_result,
            ocr_results=ocr_results,
            llm_result=None,
            final_reason=f"Rule-based detection: {', '.join(rule_result.get('triggered_rules', []))}",
            evidence=rule_result.get('evidence', []),
            indicator_tags=[],
            recommended_action=action
        )

    def _create_error_result(self, request: DetectionRequest, error_msg: str, start_time: float) -> DetectionResult:
        """Create error result"""
        processing_time = int((time.time() - start_time) * 1000)
        
        return DetectionResult(
            message_id=request.message_id,
            label="not_scam",
            confidence=0.0,
            processing_time_ms=processing_time,
            rule_results={},
            ocr_results=[],
            llm_result=None,
            final_reason=f"Processing error: {error_msg}",
            evidence=[],
            indicator_tags=[],
            recommended_action="ignore"
        )

    def _update_stats(self, result: DetectionResult, start_time: float) -> None:
        """Update pipeline statistics"""
        self.stats['total_processed'] += 1
        
        if result.label == "scam":
            self.stats['scams_detected'] += 1
        
        processing_time = time.time() - start_time
        self.stats['avg_processing_time'] = (
            (self.stats['avg_processing_time'] * (self.stats['total_processed'] - 1) + processing_time) /
            self.stats['total_processed']
        )

    def get_stats(self) -> Dict:
        """Get pipeline statistics"""
        return self.stats.copy()

    def update_config(self, new_config: Dict) -> None:
        """Update pipeline configuration"""
        self.config.update(new_config)
        logger.info(f"Updated pipeline config: {new_config}")

    async def health_check(self) -> Dict:
        """Health check for detection pipeline"""
        try:
            # Check OCR service
            ocr_health = await self.ocr_service.health_check()
            
            # Check LLM service
            llm_health = await self.llm_service.health_check()
            
            # Check database
            db_healthy = True
            try:
                async with self.db_manager.get_session() as session:
                    await session.execute("SELECT 1")
            except Exception:
                db_healthy = False
            
            overall_status = (
                ocr_health['status'] == 'healthy' and
                llm_health['status'] == 'healthy' and
                db_healthy
            )
            
            return {
                'status': 'healthy' if overall_status else 'unhealthy',
                'components': {
                    'ocr': ocr_health['status'],
                    'llm': llm_health['status'],
                    'database': 'healthy' if db_healthy else 'unhealthy',
                    'preprocessor': 'healthy',
                    'rule_detector': 'healthy'
                },
                'config': self.config,
                'stats': self.stats
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
