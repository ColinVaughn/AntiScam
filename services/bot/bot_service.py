import asyncio
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json

import discord
from discord.ext import commands, tasks
from redis import Redis

from ...core.detector_pipeline import DetectorPipeline
from ...core.actioner import Actioner
from ...core.logging_system import AntiScamLogger, LogComponent, init_logger
from ...core.training_system import AutoTrainingSystem, init_training_system
from ...database import DatabaseManager, init_database, create_default_guild_config, GuildConfig, DomainBlacklist, DomainWhitelist

logger = logging.getLogger(__name__)

class AntiScamBot(commands.Bot):
    """Main Discord Anti-Scam Bot class"""
    
    def __init__(self):
        # Bot configuration
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.reactions = True
        
        super().__init__(
            command_prefix='!scam',
            intents=intents,
            description="Offline-first Discord Anti-Scam Bot"
        )
        
        # Initialize components
        self.db_manager = None
        self.redis_client = None
        self.ocr_service = None
        self.llm_service = None
        self.detector_pipeline = None
        self.actioner = None
        self.logger = None
        self.training_system = None
        
        # Statistics tracking
        self.stats = {
            'messages_processed': 0,
            'scams_detected': 0,
            'actions_taken': 0,
            'start_time': datetime.utcnow()
        }
        
        # Rate limiting
        self.rate_limits = {}
        self.max_messages_per_minute = 60

    async def setup_hook(self):
        """Initialize bot services and components"""
        logger.info("Setting up Anti-Scam Bot...")
        
        # Initialize database
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            raise ValueError("DATABASE_URL environment variable not set")
        
        self.db_manager = init_database(database_url)
        await self.db_manager.create_tables()
        
        # Initialize Redis
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        self.redis_client = Redis.from_url(redis_url, decode_responses=True)
        
        # Initialize OCR service
        tesseract_cmd = os.getenv('TESSERACT_CMD')
        self.ocr_service = OCRService(self.redis_client, tesseract_cmd)
        
        # Initialize LLM service
        model_path = os.getenv('LLM_MODEL_PATH', './models/quantized_model.gguf')
        self.llm_service = LLMInferenceService(self.redis_client, model_path)
        
        # Initialize LLM service
        llm_initialized = await self.llm_service.initialize()
        if not llm_initialized:
            logger.warning("LLM service failed to initialize - continuing without LLM")
        
        # Initialize logging
        self.logger = init_logger(self.db_manager)
        
        # Initialize training system
        self.training_system = init_training_system(self.db_manager, self.logger)
        
        # Initialize detector pipeline
        self.detector_pipeline = DetectorPipeline(
            db_manager=self.db_manager,
            redis_client=self.redis_client
        )
        
        # Initialize actioner
        self.actioner = Actioner(
            bot=self,
            db_manager=self.db_manager,
            logger=self.logger
        )
        
        # Load training commands cog
        try:
            from .training_commands import TrainingCommands
            await self.add_cog(TrainingCommands(self))
            logger.info("Training commands loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load training commands: {str(e)}")
        
        # Start background tasks
        self.cleanup_task.start()
        self.stats_update_task.start()
        
        logger.info("Anti-Scam Bot setup completed successfully")

    async def on_ready(self):
        """Called when bot is ready"""
        logger.info(f'{self.user.name} has connected to Discord!')
        logger.info(f'Bot is in {len(self.guilds)} guilds')
        
        # Update guild count
        self.stats['guilds_served'] = len(self.guilds)
        
        # Create default configs for all guilds
        for guild in self.guilds:
            await create_default_guild_config(str(guild.id))

    async def on_guild_join(self, guild):
        """Called when bot joins a new guild"""
        logger.info(f"Joined guild: {guild.name} ({guild.id})")
        
        # Create default configuration
        await create_default_guild_config(str(guild.id))
        
        # Update stats
        self.stats['guilds_served'] = len(self.guilds)
        
        # Send welcome message to system channel
        if guild.system_channel:
            embed = discord.Embed(
                title="🛡️ Anti-Scam Bot Activated",
                description="Thank you for adding the Anti-Scam Bot to your server!",
                color=0x00ff00
            )
            embed.add_field(
                name="Features",
                value="• Automatic scam detection\n• OCR text analysis\n• Offline LLM inference\n• Configurable policies\n• Moderator dashboard",
                inline=False
            )
            embed.add_field(
                name="Setup",
                value="Use `!scamconfig` to configure settings and `!scamhelp` for commands.",
                inline=False
            )
            
            try:
                await guild.system_channel.send(embed=embed)
            except discord.Forbidden:
                pass

    async def on_message(self, message):
        """Process incoming messages"""
        # Skip bot messages
        if message.author.bot:
            return
        
        # Skip DMs
        if not message.guild:
            return
        
        # Rate limiting check
        if not self._check_rate_limit(message.author.id):
            return
        
        # Process commands first
        await self.process_commands(message)
        
        # Skip if message is a command
        if message.content.startswith(self.command_prefix):
            return
        
        # Process message for scam detection
        await self._process_message_for_scams(message)

    async def _process_message_for_scams(self, message):
        """Process message through scam detection pipeline"""
        try:
            # Get guild configuration
            guild_config = await self._get_guild_config(str(message.guild.id))
            
            # Skip if detection is disabled
            if not any([guild_config.enable_rules, guild_config.enable_ocr, guild_config.enable_llm]):
                return
            
            # Prepare metadata
            author_created = message.author.created_at
            account_age = (datetime.utcnow() - author_created).days
            
            metadata = {
                'author_id': str(message.author.id),
                'guild_id': str(message.guild.id),
                'channel_id': str(message.channel.id),
                'author_age_days': account_age,
                'has_links': 'http' in message.content.lower(),
                'message_length': len(message.content),
                'has_attachments': len(message.attachments) > 0
            }
            
            # Extract attachment URLs
            attachment_urls = []
            for attachment in message.attachments:
                if attachment.content_type and attachment.content_type.startswith('image/'):
                    attachment_urls.append(attachment.url)
            
            # Create detection request
            detection_request = DetectionRequest(
                message_id=str(message.id),
                guild_id=str(message.guild.id),
                channel_id=str(message.channel.id),
                author_id=str(message.author.id),
                text=message.content,
                attachments=attachment_urls,
                metadata=metadata,
                timestamp=message.created_at.timestamp()
            )
            
            # Process through detection pipeline
            result = await self.detection_pipeline.process_message(detection_request)
            
            # Take action based on result
            await self.actioner.process_detection_result(result, message)
            
            # Update statistics
            self.stats['messages_processed'] += 1
            if result.label == 'scam':
                self.stats['scams_detected'] += 1
            
        except Exception as e:
            logger.error(f"Error processing message {message.id}: {str(e)}")

    async def on_raw_reaction_add(self, payload):
        """Handle reaction additions for moderator actions"""
        # Skip bot reactions
        if payload.user_id == self.user.id:
            return
        
        await self.actioner.handle_moderator_reaction(payload)

    def _check_rate_limit(self, user_id: int) -> bool:
        """Check if user is within rate limits"""
        now = datetime.utcnow()
        minute_ago = now - timedelta(minutes=1)
        
        if user_id not in self.rate_limits:
            self.rate_limits[user_id] = []
        
        # Remove old timestamps
        self.rate_limits[user_id] = [
            timestamp for timestamp in self.rate_limits[user_id] 
            if timestamp > minute_ago
        ]
        
        # Check limit
        if len(self.rate_limits[user_id]) >= self.max_messages_per_minute:
            return False
        
        # Add current timestamp
        self.rate_limits[user_id].append(now)
        return True

    async def _get_guild_config(self, guild_id: str) -> GuildConfig:
        """Get guild configuration"""
        async with self.db_manager.get_session() as session:
            result = await session.execute(
                "SELECT * FROM guild_configs WHERE guild_id = $1",
                guild_id
            )
            config_data = result.fetchone()
            
            if config_data:
                return GuildConfig(**dict(config_data))
            else:
                # Create and return default config
                await create_default_guild_config(guild_id)
                return GuildConfig(guild_id=guild_id)

    @tasks.loop(hours=24)
    async def cleanup_task(self):
        """Daily cleanup task"""
        try:
            logger.info("Running daily cleanup task...")
            
            # Clean up old records based on retention policies
            for guild in self.guilds:
                guild_config = await self._get_guild_config(str(guild.id))
                # Cleanup implementation would go here
                
            logger.info("Daily cleanup completed")
            
        except Exception as e:
            logger.error(f"Error in cleanup task: {str(e)}")

    @tasks.loop(minutes=5)
    async def stats_update_task(self):
        """Update statistics periodically"""
        try:
            # Update guild count
            self.stats['guilds_served'] = len(self.guilds)
            
            # Store stats in Redis for dashboard
            stats_json = json.dumps(self.stats, default=str)
            self.redis_client.setex('bot_stats', 300, stats_json)
            
        except Exception as e:
            logger.error(f"Error updating stats: {str(e)}")

    async def close(self):
        """Cleanup when bot shuts down"""
        logger.info("Shutting down Anti-Scam Bot...")
        
        # Stop background tasks
        self.cleanup_task.cancel()
        self.stats_update_task.cancel()
        
        # Close database connections
        if self.db_manager:
            await self.db_manager.close()
        
        # Close Redis connection
        if self.redis_client:
            self.redis_client.close()
        
        await super().close()

    def get_stats(self) -> Dict:
        """Get bot statistics"""
        uptime = datetime.utcnow() - self.stats['uptime_start']
        
        return {
            **self.stats,
            'uptime_hours': uptime.total_seconds() / 3600,
            'detection_pipeline_stats': self.detection_pipeline.get_stats() if self.detection_pipeline else {},
            'actioner_stats': self.actioner.get_stats() if self.actioner else {}
        }

# Bot commands will be defined in separate cogs
class ConfigCommands(commands.Cog):
    """Configuration commands for the Anti-Scam Bot"""
    
    def __init__(self, bot: AntiScamBot):
        self.bot = bot

    @commands.group(name='config', aliases=['cfg'])
    @commands.has_permissions(administrator=True)
    async def config(self, ctx):
        """Anti-scam bot configuration commands"""
        if ctx.invoked_subcommand is None:
            await ctx.send("Use `!scamconfig help` for configuration options.")

    @config.command(name='set')
    @commands.has_permissions(administrator=True)
    async def set_config(self, ctx, setting: str, value: str):
        """Set a configuration value"""
        try:
            guild_id = str(ctx.guild.id)
            
            # Validate settings
            valid_settings = {
                'auto_delete_confidence': float,
                'flag_threshold': float,
                'mod_channel': str,
                'log_channel': str,
                'enable_ocr': bool,
                'enable_llm': bool,
                'enable_rules': bool,
                'retention_days': int
            }
            
            if setting not in valid_settings:
                await ctx.send(f"Invalid setting. Valid options: {', '.join(valid_settings.keys())}")
                return
            
            # Parse value
            if valid_settings[setting] == bool:
                parsed_value = value.lower() in ['true', '1', 'yes', 'on']
            elif valid_settings[setting] == float:
                parsed_value = float(value)
                if setting.endswith('confidence') or setting.endswith('threshold'):
                    if not 0.0 <= parsed_value <= 1.0:
                        await ctx.send("Confidence values must be between 0.0 and 1.0")
                        return
            elif valid_settings[setting] == int:
                parsed_value = int(value)
            else:
                # Handle channel mentions
                if setting.endswith('channel'):
                    if value.startswith('<#') and value.endswith('>'):
                        channel_id = value[2:-1]
                        channel = ctx.guild.get_channel(int(channel_id))
                        if not channel:
                            await ctx.send("Channel not found")
                            return
                        parsed_value = channel_id
                    else:
                        parsed_value = value
                else:
                    parsed_value = value
            
            # Update database
            async with self.bot.db_manager.get_session() as session:
                # Check if config exists
                result = await session.execute(
                    "SELECT id FROM guild_configs WHERE guild_id = $1",
                    guild_id
                )
                config_exists = result.fetchone()
                
                if config_exists:
                    # Update existing config
                    column_name = f"{setting}_id" if setting.endswith('channel') else setting
                    await session.execute(
                        f"UPDATE guild_configs SET {column_name} = $1 WHERE guild_id = $2",
                        parsed_value, guild_id
                    )
                else:
                    # Create new config
                    await create_default_guild_config(guild_id)
                    column_name = f"{setting}_id" if setting.endswith('channel') else setting
                    await session.execute(
                        f"UPDATE guild_configs SET {column_name} = $1 WHERE guild_id = $2",
                        parsed_value, guild_id
                    )
                
                await session.commit()
            
            await ctx.send(f"✅ Set `{setting}` to `{value}`")
            
        except ValueError as e:
            await ctx.send(f"Invalid value for `{setting}`: {str(e)}")
        except Exception as e:
            logger.error(f"Error setting config: {str(e)}")
            await ctx.send("An error occurred while updating the configuration.")

    @config.command(name='show')
    @commands.has_permissions(manage_messages=True)
    async def show_config(self, ctx):
        """Show current configuration"""
        try:
            guild_config = await self.bot._get_guild_config(str(ctx.guild.id))
            
            embed = discord.Embed(
                title="Anti-Scam Bot Configuration",
                color=0x0099ff
            )
            
            embed.add_field(
                name="Detection Settings",
                value=f"Auto-delete confidence: {guild_config.auto_delete_confidence}\n"
                      f"Flag threshold: {guild_config.flag_threshold}\n"
                      f"Enable OCR: {guild_config.enable_ocr}\n"
                      f"Enable LLM: {guild_config.enable_llm}\n"
                      f"Enable Rules: {guild_config.enable_rules}",
                inline=False
            )
            
            mod_channel = f"<#{guild_config.mod_channel_id}>" if guild_config.mod_channel_id else "Not set"
            log_channel = f"<#{guild_config.log_channel_id}>" if guild_config.log_channel_id else "Not set"
            
            embed.add_field(
                name="Channels",
                value=f"Moderator channel: {mod_channel}\n"
                      f"Log channel: {log_channel}",
                inline=False
            )
            
            embed.add_field(
                name="Other Settings",
                value=f"Retention days: {guild_config.retention_days}",
                inline=False
            )
            
            await ctx.send(embed=embed)
            
        except Exception as e:
            logger.error(f"Error showing config: {str(e)}")
            await ctx.send("An error occurred while fetching the configuration.")

    @commands.command(name='stats')
    @commands.has_permissions(manage_messages=True)
    async def stats(self, ctx):
        """Show bot statistics"""
        try:
            stats = self.bot.get_stats()
            
            embed = discord.Embed(
                title="Anti-Scam Bot Statistics",
                color=0x0099ff
            )
            
            embed.add_field(
                name="Messages",
                value=f"Processed: {stats['messages_processed']}\n"
                      f"Scams detected: {stats['scams_detected']}\n"
                      f"False positives: {stats['false_positives']}",
                inline=True
            )
            
            embed.add_field(
                name="System",
                value=f"Uptime: {stats['uptime_hours']:.1f} hours\n"
                      f"Guilds served: {stats['guilds_served']}",
                inline=True
            )
            
            if 'detection_pipeline_stats' in stats:
                pipeline_stats = stats['detection_pipeline_stats']
                embed.add_field(
                    name="Detection Pipeline",
                    value=f"Avg processing time: {pipeline_stats.get('avg_processing_time', 0):.2f}s\n"
                          f"Rule decisions: {pipeline_stats.get('rule_only_decisions', 0)}\n"
                          f"LLM decisions: {pipeline_stats.get('llm_decisions', 0)}",
                    inline=False
                )
            
            await ctx.send(embed=embed)
            
        except Exception as e:
            logger.error(f"Error showing stats: {str(e)}")
            await ctx.send("An error occurred while fetching statistics.")

async def main():
    """Main function to run the bot"""
    # Load environment variables
    token = os.getenv('DISCORD_TOKEN')
    if not token:
        raise ValueError("DISCORD_TOKEN environment variable not set")
    
    # Create and run bot
    bot = AntiScamBot()
    
    # Add cogs
    await bot.add_cog(ConfigCommands(bot))
    
    try:
        await bot.start(token)
    except Exception as e:
        logger.error(f"Bot failed to start: {str(e)}")
        raise
    finally:
        await bot.close()

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    asyncio.run(main())
