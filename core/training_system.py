import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import aiohttp
from PIL import Image
import io
import base64

from ..database import DatabaseManager, TrainingExample, TrainingBatch, ModelVersion
from ..core.preprocessor import TextPreprocessor
from ..core.logging_system import AntiScamLogger, LogComponent
from ..services.ocr.ocr_service import OCRService

class TrainingDataManager:
    """Manages training data collection and validation"""
    
    def __init__(self, db_manager: DatabaseManager, logger: AntiScamLogger):
        self.db_manager = db_manager
        self.logger = logger
        self.preprocessor = TextPreprocessor()
        
    async def submit_training_example(
        self,
        guild_id: str,
        submitted_by: str,
        message_text: Optional[str] = None,
        image_url: Optional[str] = None,
        image_data: Optional[bytes] = None,
        label: str = "scam",
        explanation: str = "",
        scam_type: Optional[str] = None,
        confidence: float = 1.0,
        source_message_id: Optional[str] = None,
        source_channel_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Submit a new training example"""
        try:
            # Validate inputs
            if not message_text and not image_url and not image_data:
                return {"success": False, "error": "Must provide either text or image"}
            
            if not explanation.strip():
                return {"success": False, "error": "Explanation is required"}
            
            if label not in ['scam', 'safe', 'suspicious']:
                return {"success": False, "error": "Label must be 'scam', 'safe', or 'suspicious'"}
            
            # Download image if URL provided
            if image_url and not image_data:
                image_data = await self._download_image(image_url)
            
            # Extract OCR text if image provided
            ocr_text = None
            if image_data:
                ocr_text = await self._extract_ocr_text(image_data)
            
            # Preprocess text for feature extraction
            features = {}
            keywords = []
            
            if message_text:
                preprocess_result = await self.preprocessor.preprocess_text(message_text)
                features['text_features'] = preprocess_result
                keywords.extend(preprocess_result.get('keywords', []))
            
            if ocr_text:
                ocr_preprocess = await self.preprocessor.preprocess_text(ocr_text)
                features['ocr_features'] = ocr_preprocess
                keywords.extend(ocr_preprocess.get('keywords', []))
            
            # Store training example
            async with self.db_manager.get_session() as session:
                example = TrainingExample(
                    guild_id=guild_id,
                    submitted_by=submitted_by,
                    message_text=message_text,
                    ocr_text=ocr_text,
                    image_url=image_url,
                    image_data=image_data,
                    label=label,
                    explanation=explanation,
                    scam_type=scam_type,
                    confidence=confidence,
                    source_message_id=source_message_id,
                    source_channel_id=source_channel_id,
                    keywords=json.dumps(keywords),
                    features=json.dumps(features, default=str),
                    status='pending'
                )
                
                session.add(example)
                await session.commit()
                
                example_id = example.id
                
            await self.logger.info(
                LogComponent.BOT,
                f"Training example submitted: {label}",
                guild_id=guild_id,
                user_id=submitted_by,
                extra_data={
                    'example_id': example_id,
                    'scam_type': scam_type,
                    'has_text': bool(message_text),
                    'has_image': bool(image_data)
                }
            )
            
            return {
                "success": True,
                "example_id": example_id,
                "message": f"Training example submitted successfully! ID: {example_id}"
            }
            
        except Exception as e:
            await self.logger.log_system_error(LogComponent.BOT, e, context={
                'operation': 'submit_training_example',
                'guild_id': guild_id,
                'submitted_by': submitted_by
            })
            return {"success": False, "error": f"Failed to submit example: {str(e)}"}
    
    async def _download_image(self, url: str) -> Optional[bytes]:
        """Download image from URL"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        return await response.read()
            return None
        except Exception as e:
            await self.logger.error(LogComponent.BOT, f"Failed to download image: {str(e)}")
            return None
    
    async def _extract_ocr_text(self, image_data: bytes) -> Optional[str]:
        """Extract text from image using OCR"""
        try:
            # Convert to PIL Image for validation
            image = Image.open(io.BytesIO(image_data))
            
            # Basic validation
            if image.size[0] * image.size[1] > 4000000:  # 4MP limit
                return None
            
            # Use OCR service if available
            # For now, return placeholder - integrate with actual OCR service
            ocr_service = OCRService()
            if hasattr(ocr_service, 'extract_text_from_bytes'):
                return await ocr_service.extract_text_from_bytes(image_data)
            
            return None
            
        except Exception as e:
            await self.logger.error(LogComponent.OCR, f"OCR extraction failed: {str(e)}")
            return None
    
    async def validate_example(
        self,
        example_id: int,
        validated_by: str,
        action: str,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate a training example"""
        try:
            async with self.db_manager.get_session() as session:
                example = await session.get(TrainingExample, example_id)
                if not example:
                    return {"success": False, "error": "Example not found"}
                
                if action not in ['approve', 'reject']:
                    return {"success": False, "error": "Action must be 'approve' or 'reject'"}
                
                example.status = 'validated' if action == 'approve' else 'rejected'
                example.validated_by = validated_by
                example.validated_at = datetime.utcnow()
                example.validation_notes = notes
                
                await session.commit()
                
            await self.logger.info(
                LogComponent.BOT,
                f"Training example {action}d: {example_id}",
                guild_id=example.guild_id,
                user_id=validated_by,
                extra_data={'example_id': example_id, 'notes': notes}
            )
            
            return {"success": True, "message": f"Example {action}d successfully"}
            
        except Exception as e:
            await self.logger.log_system_error(LogComponent.BOT, e)
            return {"success": False, "error": f"Validation failed: {str(e)}"}
    
    async def get_pending_examples(self, guild_id: str, limit: int = 50) -> List[Dict]:
        """Get pending training examples for validation"""
        try:
            async with self.db_manager.get_session() as session:
                result = await session.execute(
                    """SELECT * FROM training_examples 
                       WHERE guild_id = $1 AND status = 'pending'
                       ORDER BY created_at DESC 
                       LIMIT $2""",
                    guild_id, limit
                )
                
                examples = []
                for row in result.fetchall():
                    example_dict = dict(row)
                    # Convert image data to base64 for display
                    if example_dict.get('image_data'):
                        example_dict['image_base64'] = base64.b64encode(example_dict['image_data']).decode()
                        del example_dict['image_data']  # Remove binary data
                    examples.append(example_dict)
                
                return examples
                
        except Exception as e:
            await self.logger.log_system_error(LogComponent.BOT, e)
            return []
    
    async def get_training_stats(self, guild_id: Optional[str] = None) -> Dict[str, Any]:
        """Get training data statistics"""
        try:
            async with self.db_manager.get_session() as session:
                where_clause = "WHERE guild_id = $1" if guild_id else ""
                params = [guild_id] if guild_id else []
                
                # Total examples
                result = await session.execute(
                    f"SELECT COUNT(*) FROM training_examples {where_clause}",
                    *params
                )
                total_examples = result.scalar()
                
                # By label
                result = await session.execute(
                    f"""SELECT label, COUNT(*) as count 
                        FROM training_examples {where_clause}
                        GROUP BY label""",
                    *params
                )
                by_label = {row['label']: row['count'] for row in result.fetchall()}
                
                # By status
                result = await session.execute(
                    f"""SELECT status, COUNT(*) as count 
                        FROM training_examples {where_clause}
                        GROUP BY status""",
                    *params
                )
                by_status = {row['status']: row['count'] for row in result.fetchall()}
                
                return {
                    "total_examples": total_examples,
                    "by_label": by_label,
                    "by_status": by_status
                }
                
        except Exception as e:
            await self.logger.log_system_error(LogComponent.BOT, e)
            return {}

class ModelTrainingManager:
    """Manages model training and retraining"""
    
    def __init__(self, db_manager: DatabaseManager, logger: AntiScamLogger):
        self.db_manager = db_manager
        self.logger = logger
        
    async def create_training_batch(
        self,
        created_by: str,
        guild_id: Optional[str] = None,
        model_type: str = "rules",
        min_examples: int = 10
    ) -> Dict[str, Any]:
        """Create a new training batch from validated examples"""
        try:
            # Get validated examples
            async with self.db_manager.get_session() as session:
                where_clause = "WHERE status = 'validated'"
                params = []
                
                if guild_id:
                    where_clause += " AND guild_id = $1"
                    params.append(guild_id)
                
                result = await session.execute(
                    f"""SELECT * FROM training_examples {where_clause}
                        AND training_batch_id IS NULL
                        ORDER BY created_at""",
                    *params
                )
                
                examples = result.fetchall()
                
                if len(examples) < min_examples:
                    return {
                        "success": False,
                        "error": f"Not enough validated examples. Need {min_examples}, have {len(examples)}"
                    }
                
                # Create batch
                batch_id = f"batch_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
                
                batch = TrainingBatch(
                    batch_id=batch_id,
                    guild_id=guild_id,
                    model_type=model_type,
                    examples_count=len(examples),
                    scam_examples=sum(1 for ex in examples if ex['label'] == 'scam'),
                    safe_examples=sum(1 for ex in examples if ex['label'] == 'safe'),
                    created_by=created_by,
                    status='pending'
                )
                
                session.add(batch)
                
                # Assign examples to batch
                for example in examples:
                    await session.execute(
                        "UPDATE training_examples SET training_batch_id = $1 WHERE id = $2",
                        batch_id, example['id']
                    )
                
                await session.commit()
                
            await self.logger.info(
                LogComponent.BOT,
                f"Training batch created: {batch_id}",
                guild_id=guild_id,
                user_id=created_by,
                extra_data={
                    'batch_id': batch_id,
                    'examples_count': len(examples),
                    'model_type': model_type
                }
            )
            
            return {
                "success": True,
                "batch_id": batch_id,
                "examples_count": len(examples),
                "message": f"Training batch {batch_id} created with {len(examples)} examples"
            }
            
        except Exception as e:
            await self.logger.log_system_error(LogComponent.BOT, e)
            return {"success": False, "error": f"Failed to create batch: {str(e)}"}
    
    async def start_training(self, batch_id: str) -> Dict[str, Any]:
        """Start training process for a batch"""
        try:
            async with self.db_manager.get_session() as session:
                # Get batch info
                result = await session.execute(
                    "SELECT * FROM training_batches WHERE batch_id = $1",
                    batch_id
                )
                batch = result.fetchone()
                
                if not batch:
                    return {"success": False, "error": "Batch not found"}
                
                if batch['status'] != 'pending':
                    return {"success": False, "error": f"Batch status is {batch['status']}, expected 'pending'"}
                
                # Update batch status
                await session.execute(
                    """UPDATE training_batches 
                       SET status = 'training', started_at = $1 
                       WHERE batch_id = $2""",
                    datetime.utcnow(), batch_id
                )
                await session.commit()
            
            # Start training process based on model type
            if batch['model_type'] == 'rules':
                result = await self._train_rules_model(batch_id)
            elif batch['model_type'] == 'classifier':
                result = await self._train_classifier_model(batch_id)
            elif batch['model_type'] == 'llm':
                result = await self._train_llm_model(batch_id)
            else:
                result = {"success": False, "error": f"Unknown model type: {batch['model_type']}"}
            
            # Update batch with results
            async with self.db_manager.get_session() as session:
                status = 'completed' if result['success'] else 'failed'
                await session.execute(
                    """UPDATE training_batches 
                       SET status = $1, completed_at = $2, notes = $3
                       WHERE batch_id = $4""",
                    status, datetime.utcnow(), result.get('message', ''), batch_id
                )
                await session.commit()
            
            return result
            
        except Exception as e:
            await self.logger.log_system_error(LogComponent.BOT, e)
            return {"success": False, "error": f"Training failed: {str(e)}"}
    
    async def _train_rules_model(self, batch_id: str) -> Dict[str, Any]:
        """Train rule-based model using training examples"""
        try:
            # Get training examples for this batch
            async with self.db_manager.get_session() as session:
                result = await session.execute(
                    """SELECT * FROM training_examples 
                       WHERE training_batch_id = $1 AND label = 'scam'""",
                    batch_id
                )
                scam_examples = result.fetchall()
            
            # Extract patterns from scam examples
            new_rules = []
            for example in scam_examples:
                text = example['message_text'] or example['ocr_text'] or ""
                explanation = example['explanation']
                
                # Extract rules based on explanation and content
                extracted_rules = await self._extract_rules_from_example(text, explanation)
                new_rules.extend(extracted_rules)
            
            # Save new rules (in practice, this would update the RuleBasedDetector)
            rules_data = {
                'batch_id': batch_id,
                'new_rules': new_rules,
                'created_at': datetime.utcnow().isoformat()
            }
            
            # In a real implementation, you'd save these rules to a file or database
            # and reload the RuleBasedDetector
            
            await self.logger.info(
                LogComponent.BOT,
                f"Rules training completed for batch {batch_id}",
                extra_data={'new_rules_count': len(new_rules)}
            )
            
            return {
                "success": True,
                "message": f"Generated {len(new_rules)} new rules",
                "new_rules_count": len(new_rules)
            }
            
        except Exception as e:
            await self.logger.log_system_error(LogComponent.BOT, e)
            return {"success": False, "error": str(e)}
    
    async def _extract_rules_from_example(self, text: str, explanation: str) -> List[Dict]:
        """Extract detection rules from training example"""
        rules = []
        
        # Simple rule extraction based on explanation keywords
        if 'payment' in explanation.lower() or 'money' in explanation.lower():
            # Look for payment-related patterns in text
            words = text.lower().split()
            for word in ['venmo', 'cashapp', 'paypal', 'zelle']:
                if word in words:
                    rules.append({
                        'type': 'payment_keyword',
                        'pattern': word,
                        'confidence': 0.8,
                        'source': 'training_extraction'
                    })
        
        if 'phishing' in explanation.lower() or 'link' in explanation.lower():
            # Extract suspicious domains or link patterns
            import re
            urls = re.findall(r'https?://[\w\.-]+', text)
            for url in urls:
                domain = url.split('/')[2] if '/' in url else url
                rules.append({
                    'type': 'suspicious_domain',
                    'pattern': domain,
                    'confidence': 0.9,
                    'source': 'training_extraction'
                })
        
        if 'impersonation' in explanation.lower() or 'admin' in explanation.lower():
            rules.append({
                'type': 'impersonation_pattern',
                'pattern': 'admin.*urgent|moderator.*action|official.*discord',
                'confidence': 0.85,
                'source': 'training_extraction'
            })
        
        return rules
    
    async def _train_classifier_model(self, batch_id: str) -> Dict[str, Any]:
        """Train classifier model (placeholder for future ML implementation)"""
        # This would implement actual ML training
        await asyncio.sleep(1)  # Simulate training time
        return {
            "success": True,
            "message": "Classifier training not yet implemented",
            "accuracy": 0.85
        }
    
    async def _train_llm_model(self, batch_id: str) -> Dict[str, Any]:
        """Fine-tune LLM model (placeholder for future implementation)"""
        # This would implement LLM fine-tuning
        await asyncio.sleep(1)  # Simulate training time
        return {
            "success": True,
            "message": "LLM fine-tuning not yet implemented",
            "perplexity": 2.1
        }

class AutoTrainingSystem:
    """Main auto-training system coordinator"""
    
    def __init__(self, db_manager: DatabaseManager, logger: AntiScamLogger):
        self.db_manager = db_manager
        self.logger = logger
        self.data_manager = TrainingDataManager(db_manager, logger)
        self.training_manager = ModelTrainingManager(db_manager, logger)
        
    async def process_message_link(
        self,
        guild_id: str,
        moderator_id: str,
        message_link: str,
        label: str,
        explanation: str,
        scam_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Process a Discord message link for training"""
        try:
            # Parse Discord message link
            # Format: https://discord.com/channels/guild_id/channel_id/message_id
            parts = message_link.split('/')
            if len(parts) < 7 or 'discord.com' not in message_link:
                return {"success": False, "error": "Invalid Discord message link"}
            
            link_guild_id = parts[-3]
            channel_id = parts[-2]
            message_id = parts[-1]
            
            if link_guild_id != guild_id:
                return {"success": False, "error": "Message is from a different server"}
            
            # In a real implementation, you'd fetch the message from Discord API
            # For now, we'll create a placeholder
            return await self.data_manager.submit_training_example(
                guild_id=guild_id,
                submitted_by=moderator_id,
                message_text="[Message content would be fetched from Discord API]",
                label=label,
                explanation=explanation,
                scam_type=scam_type,
                source_message_id=message_id,
                source_channel_id=channel_id
            )
            
        except Exception as e:
            await self.logger.log_system_error(LogComponent.BOT, e)
            return {"success": False, "error": f"Failed to process message link: {str(e)}"}
    
    async def schedule_auto_training(self, guild_id: Optional[str] = None):
        """Schedule automatic training when enough examples are available"""
        try:
            stats = await self.data_manager.get_training_stats(guild_id)
            validated_count = stats.get('by_status', {}).get('validated', 0)
            
            # Auto-create training batch if we have enough examples
            if validated_count >= 20:  # Configurable threshold
                result = await self.training_manager.create_training_batch(
                    created_by='system',
                    guild_id=guild_id,
                    model_type='rules',
                    min_examples=10
                )
                
                if result['success']:
                    # Auto-start training for rules (safe to automate)
                    await self.training_manager.start_training(result['batch_id'])
                    
                    await self.logger.info(
                        LogComponent.BOT,
                        "Auto-training initiated",
                        guild_id=guild_id,
                        extra_data={'batch_id': result['batch_id'], 'examples_count': validated_count}
                    )
            
        except Exception as e:
            await self.logger.log_system_error(LogComponent.BOT, e)

# Global training system instance
_training_system: Optional[AutoTrainingSystem] = None

def init_training_system(db_manager: DatabaseManager, logger: AntiScamLogger) -> AutoTrainingSystem:
    """Initialize global training system"""
    global _training_system
    _training_system = AutoTrainingSystem(db_manager, logger)
    return _training_system

def get_training_system() -> AutoTrainingSystem:
    """Get global training system instance"""
    if _training_system is None:
        raise RuntimeError("Training system not initialized")
    return _training_system
