from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()

class FlaggedMessage(Base):
    __tablename__ = 'flagged_messages'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    guild_id = Column(String(20), nullable=False, index=True)
    channel_id = Column(String(20), nullable=False, index=True)
    message_id = Column(String(20), nullable=False, unique=True, index=True)
    author_id = Column(String(20), nullable=False, index=True)
    text = Column(Text, nullable=False)
    ocr_text = Column(Text, nullable=True)
    label = Column(String(20), nullable=False)  # scam, not_scam, suspicious
    confidence = Column(Float, nullable=False)
    rules_triggered = Column(Text, nullable=True)  # JSON array of triggered rules
    model_version = Column(String(50), nullable=True)
    indicator_tags = Column(Text, nullable=True)  # JSON array of indicator tags
    short_reason = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)  # JSON array of evidence
    status = Column(String(20), default='pending')  # pending, reviewed, approved, deleted
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    moderator_actions = relationship("ModeratorAction", back_populates="flagged_message")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_guild_created', 'guild_id', 'created_at'),
        Index('idx_status_confidence', 'status', 'confidence'),
        Index('idx_label_created', 'label', 'created_at'),
    )

class ModeratorAction(Base):
    __tablename__ = 'moderator_actions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    flagged_message_id = Column(Integer, ForeignKey('flagged_messages.id'), nullable=False)
    moderator_id = Column(String(20), nullable=False, index=True)
    action = Column(String(20), nullable=False)  # approve, delete_ban, warn, ignore, appeal
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    
    # Relationships
    flagged_message = relationship("FlaggedMessage", back_populates="moderator_actions")
    
    # Indexes
    __table_args__ = (
        Index('idx_moderator_created', 'moderator_id', 'created_at'),
        Index('idx_action_created', 'action', 'created_at'),
    )

class DomainBlacklist(Base):
    __tablename__ = 'domains_blacklist'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    added_by = Column(String(20), nullable=False)  # Discord user ID
    guild_id = Column(String(20), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('idx_guild_active', 'guild_id', 'is_active'),
        Index('idx_domain_active', 'domain', 'is_active'),
    )

class DomainWhitelist(Base):
    __tablename__ = 'domains_whitelist'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    added_by = Column(String(20), nullable=False)
    guild_id = Column(String(20), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_guild_active_wl', 'guild_id', 'is_active'),
        Index('idx_domain_active_wl', 'domain', 'is_active'),
    )

class GuildConfig(Base):
    __tablename__ = 'guild_configs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    guild_id = Column(String(20), nullable=False, unique=True, index=True)
    auto_delete_confidence = Column(Float, default=0.9, nullable=False)
    flag_threshold = Column(Float, default=0.5, nullable=False)
    mod_channel_id = Column(String(20), nullable=True)
    log_channel_id = Column(String(20), nullable=True)
    enable_ocr = Column(Boolean, default=True, nullable=False)
    enable_llm = Column(Boolean, default=True, nullable=False)
    enable_rules = Column(Boolean, default=True, nullable=False)
    retention_days = Column(Integer, default=30, nullable=False)
    whitelist_roles = Column(Text, nullable=True)  # JSON array of role IDs
    admin_roles = Column(Text, nullable=True)  # JSON array of role IDs with config access
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

class SystemLog(Base):
    __tablename__ = 'system_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    level = Column(String(10), nullable=False, index=True)  # INFO, WARNING, ERROR, CRITICAL
    component = Column(String(50), nullable=False, index=True)  # bot, ocr, llm, detector, etc.
    message = Column(Text, nullable=False)
    guild_id = Column(String(20), nullable=True, index=True)
    user_id = Column(String(20), nullable=True, index=True)
    message_id = Column(String(20), nullable=True, index=True)
    extra_data = Column(Text, nullable=True)  # JSON for additional context
    created_at = Column(DateTime, default=func.now(), nullable=False, index=True)
    
    __table_args__ = (
        Index('idx_level_created', 'level', 'created_at'),
        Index('idx_component_created', 'component', 'created_at'),
    )

class DetectionStats(Base):
    __tablename__ = 'detection_stats'
    
    id = Column(Integer, primary_key=True)
    guild_id = Column(String(20), nullable=False, index=True)
    date = Column(Date, nullable=False, index=True)
    messages_processed = Column(Integer, default=0)
    scams_detected = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    moderator_actions = Column(Integer, default=0)
    avg_confidence = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (UniqueConstraint('guild_id', 'date', name='unique_guild_date_stats'),)

class TrainingExample(Base):
    __tablename__ = 'training_examples'
    
    id = Column(Integer, primary_key=True)
    guild_id = Column(String(20), nullable=False, index=True)
    submitted_by = Column(String(20), nullable=False)  # Moderator user ID
    
    # Content information
    message_text = Column(Text)
    ocr_text = Column(Text)
    image_url = Column(String(500))
    image_data = Column(LargeBinary)  # Store image for training
    
    # Labels and explanations
    label = Column(String(50), nullable=False)  # 'scam', 'safe', 'suspicious'
    explanation = Column(Text, nullable=False)  # Moderator's explanation
    scam_type = Column(String(100))  # e.g., 'phishing', 'payment_fraud', 'impersonation'
    confidence = Column(Float, default=1.0)  # Moderator confidence in label
    
    # Metadata
    source_message_id = Column(String(20))  # Original message ID if applicable
    source_channel_id = Column(String(20))
    keywords = Column(Text)  # Extracted keywords for training
    features = Column(Text)  # JSON string of extracted features
    
    # Processing status
    status = Column(String(20), default='pending')  # 'pending', 'validated', 'rejected', 'used'
    validation_notes = Column(Text)
    validated_by = Column(String(20))  # Admin who validated
    validated_at = Column(DateTime)
    
    # Training metadata
    model_version_used = Column(String(50))  # Model version when used for training
    training_batch_id = Column(String(100))  # Batch identifier for retraining
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class TrainingBatch(Base):
    __tablename__ = 'training_batches'
    
    id = Column(Integer, primary_key=True)
    batch_id = Column(String(100), unique=True, nullable=False)
    guild_id = Column(String(20), index=True)  # Null for global batches
    
    # Batch information
    examples_count = Column(Integer, default=0)
    scam_examples = Column(Integer, default=0)
    safe_examples = Column(Integer, default=0)
    
    # Training configuration
    model_type = Column(String(50))  # 'rules', 'classifier', 'llm'
    training_config = Column(Text)  # JSON training parameters
    
    # Status and results
    status = Column(String(20), default='pending')  # 'pending', 'training', 'completed', 'failed'
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Results
    accuracy_improvement = Column(Float)
    model_path = Column(String(500))  # Path to trained model
    performance_metrics = Column(Text)  # JSON metrics
    notes = Column(Text)
    
    created_by = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class ModelVersion(Base):
    __tablename__ = 'model_versions'
    
    id = Column(Integer, primary_key=True)
    version = Column(String(50), unique=True, nullable=False)
    model_type = Column(String(50), nullable=False)  # 'rules', 'classifier', 'llm'
    
    # Model information
    model_path = Column(String(500))
    config_path = Column(String(500))
    description = Column(Text)
    
    # Training information
    training_batch_id = Column(String(100))
    training_examples_count = Column(Integer, default=0)
    base_model = Column(String(200))  # Base model used for training
    
    # Performance metrics
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    validation_metrics = Column(Text)  # JSON metrics
    
    # Deployment status
    status = Column(String(20), default='training')  # 'training', 'ready', 'deployed', 'deprecated'
    deployed_at = Column(DateTime)
    deprecated_at = Column(DateTime)
    
    created_by = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
