import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import discord
from discord.ext import commands

from .detector_pipeline import DetectionResult
from ..database import DatabaseManager, GuildConfig, ModeratorAction, SystemLog

logger = logging.getLogger(__name__)

@dataclass
class ActionResult:
    """Result of an enforcement action"""
    action_taken: str
    success: bool
    error_message: Optional[str]
    moderator_notified: bool
    user_notified: bool

class MessageActioner:
    """Handles enforcement actions based on detection results"""
    
    def __init__(self, bot: commands.Bot, db_manager: DatabaseManager):
        self.bot = bot
        self.db_manager = db_manager
        
        # Action templates
        self.user_dm_templates = {
            'warning': """⚠️ **Anti-Scam Warning**

Your recent message in **{guild_name}** was flagged as potentially suspicious content.

**Reason:** {reason}
**Confidence:** {confidence:.0%}

If you believe this was a mistake, please contact the server moderators.

This is an automated message from the Anti-Scam system.""",
            
            'deletion': """🚫 **Message Removed**

Your message in **{guild_name}** was automatically removed for violating our scam prevention policies.

**Reason:** {reason}
**Evidence:** {evidence}

If you believe this was an error, please contact the server moderators to appeal this action.

This is an automated message from the Anti-Scam system."""
        }
        
        self.mod_notification_templates = {
            'high_confidence': """🚨 **HIGH CONFIDENCE SCAM DETECTED**

**Server:** {guild_name}
**Channel:** <#{channel_id}>
**User:** <@{author_id}> ({author_id})
**Confidence:** {confidence:.0%}

**Message Content:**
```
{message_content}
```

**Detection Reason:** {reason}
**Evidence:** {evidence}
**Action Taken:** {action}

**OCR Text (if any):**
```
{ocr_text}
```

*Message ID: {message_id}*""",
            
            'review_needed': """⚠️ **SCAM DETECTION - REVIEW NEEDED**

**Server:** {guild_name}
**Channel:** <#{channel_id}>
**User:** <@{author_id}> ({author_id})
**Confidence:** {confidence:.0%}

**Message Content:**
```
{message_content}
```

**Detection Reason:** {reason}
**Evidence:** {evidence}

This message has been flagged for moderator review. React with:
✅ to approve (not a scam)
❌ to delete and ban user
⚠️ to warn user only

*Message ID: {message_id}*"""
        }

    async def process_detection_result(self, result: DetectionResult, message: discord.Message) -> ActionResult:
        """Process detection result and take appropriate action"""
        try:
            # Get guild configuration
            guild_config = await self._get_guild_config(str(message.guild.id))
            
            # Determine action based on result and configuration
            action = self._determine_action(result, guild_config)
            
            # Execute action
            action_result = await self._execute_action(action, result, message, guild_config)
            
            # Log action
            await self._log_action(result, message, action, action_result)
            
            return action_result
            
        except Exception as e:
            logger.error(f"Failed to process detection result for message {result.message_id}: {str(e)}")
            return ActionResult(
                action_taken="error",
                success=False,
                error_message=str(e),
                moderator_notified=False,
                user_notified=False
            )

    def _determine_action(self, result: DetectionResult, guild_config: GuildConfig) -> str:
        """Determine appropriate action based on detection result and guild config"""
        confidence = result.confidence
        label = result.label
        
        # High confidence scam - auto delete if configured
        if (label == "scam" and 
            confidence >= guild_config.auto_delete_confidence):
            return "delete"
        
        # Medium confidence - flag for review
        elif (label == "scam" and 
              confidence >= guild_config.flag_threshold):
            return "flag"
        
        # Suspicious content - monitor/warn
        elif label == "suspicious":
            return "warn"
        
        # Low confidence or not scam - just monitor
        else:
            return "monitor"

    async def _execute_action(
        self, 
        action: str, 
        result: DetectionResult, 
        message: discord.Message, 
        guild_config: GuildConfig
    ) -> ActionResult:
        """Execute the determined action"""
        
        if action == "delete":
            return await self._delete_message_action(result, message, guild_config)
        elif action == "flag":
            return await self._flag_message_action(result, message, guild_config)
        elif action == "warn":
            return await self._warn_user_action(result, message, guild_config)
        elif action == "monitor":
            return await self._monitor_action(result, message, guild_config)
        else:
            return ActionResult(
                action_taken="unknown",
                success=False,
                error_message=f"Unknown action: {action}",
                moderator_notified=False,
                user_notified=False
            )

    async def _delete_message_action(
        self, 
        result: DetectionResult, 
        message: discord.Message, 
        guild_config: GuildConfig
    ) -> ActionResult:
        """Delete message and notify relevant parties"""
        try:
            # Delete the message
            await message.delete()
            
            # Send DM to user
            user_notified = await self._send_user_dm(
                message.author, 
                'deletion', 
                result, 
                message.guild.name
            )
            
            # Notify moderators
            mod_notified = await self._notify_moderators(
                'high_confidence', 
                result, 
                message, 
                guild_config, 
                "Message deleted automatically"
            )
            
            return ActionResult(
                action_taken="delete",
                success=True,
                error_message=None,
                moderator_notified=mod_notified,
                user_notified=user_notified
            )
            
        except discord.NotFound:
            # Message was already deleted
            return ActionResult(
                action_taken="delete",
                success=True,
                error_message="Message already deleted",
                moderator_notified=False,
                user_notified=False
            )
        except discord.Forbidden:
            # No permission to delete
            logger.warning(f"No permission to delete message {result.message_id}")
            return ActionResult(
                action_taken="delete",
                success=False,
                error_message="No permission to delete message",
                moderator_notified=False,
                user_notified=False
            )

    async def _flag_message_action(
        self, 
        result: DetectionResult, 
        message: discord.Message, 
        guild_config: GuildConfig
    ) -> ActionResult:
        """Flag message for moderator review"""
        try:
            # Add reaction to message for quick identification
            try:
                await message.add_reaction("🚨")
            except (discord.NotFound, discord.Forbidden):
                pass  # Message deleted or no permission
            
            # Notify moderators for review
            mod_notified = await self._notify_moderators(
                'review_needed', 
                result, 
                message, 
                guild_config, 
                "Flagged for review"
            )
            
            return ActionResult(
                action_taken="flag",
                success=True,
                error_message=None,
                moderator_notified=mod_notified,
                user_notified=False
            )
            
        except Exception as e:
            logger.error(f"Failed to flag message {result.message_id}: {str(e)}")
            return ActionResult(
                action_taken="flag",
                success=False,
                error_message=str(e),
                moderator_notified=False,
                user_notified=False
            )

    async def _warn_user_action(
        self, 
        result: DetectionResult, 
        message: discord.Message, 
        guild_config: GuildConfig
    ) -> ActionResult:
        """Warn user about suspicious content"""
        try:
            # Send warning DM to user
            user_notified = await self._send_user_dm(
                message.author, 
                'warning', 
                result, 
                message.guild.name
            )
            
            # Add warning reaction
            try:
                await message.add_reaction("⚠️")
            except (discord.NotFound, discord.Forbidden):
                pass
            
            return ActionResult(
                action_taken="warn",
                success=True,
                error_message=None,
                moderator_notified=False,
                user_notified=user_notified
            )
            
        except Exception as e:
            logger.error(f"Failed to warn user for message {result.message_id}: {str(e)}")
            return ActionResult(
                action_taken="warn",
                success=False,
                error_message=str(e),
                moderator_notified=False,
                user_notified=False
            )

    async def _monitor_action(
        self, 
        result: DetectionResult, 
        message: discord.Message, 
        guild_config: GuildConfig
    ) -> ActionResult:
        """Monitor message (log only, no user-facing action)"""
        # Just log the detection for monitoring
        return ActionResult(
            action_taken="monitor",
            success=True,
            error_message=None,
            moderator_notified=False,
            user_notified=False
        )

    async def _send_user_dm(
        self, 
        user: discord.User, 
        template_type: str, 
        result: DetectionResult, 
        guild_name: str
    ) -> bool:
        """Send DM notification to user"""
        try:
            template = self.user_dm_templates.get(template_type)
            if not template:
                return False
            
            evidence_str = ", ".join(result.evidence[:3]) if result.evidence else "Automated detection"
            
            message_content = template.format(
                guild_name=guild_name,
                reason=result.final_reason,
                confidence=result.confidence,
                evidence=evidence_str
            )
            
            await user.send(message_content)
            return True
            
        except discord.Forbidden:
            # User has DMs disabled
            logger.info(f"Could not DM user {user.id} - DMs disabled")
            return False
        except Exception as e:
            logger.error(f"Failed to send DM to user {user.id}: {str(e)}")
            return False

    async def _notify_moderators(
        self, 
        template_type: str, 
        result: DetectionResult, 
        message: discord.Message, 
        guild_config: GuildConfig, 
        action_taken: str
    ) -> bool:
        """Send notification to moderator channel"""
        try:
            if not guild_config.mod_channel_id:
                return False
            
            mod_channel = self.bot.get_channel(int(guild_config.mod_channel_id))
            if not mod_channel:
                return False
            
            template = self.mod_notification_templates.get(template_type)
            if not template:
                return False
            
            # Prepare message data
            evidence_str = "\n".join([f"• {ev}" for ev in result.evidence[:5]]) if result.evidence else "None"
            ocr_text = ""
            
            if result.ocr_results:
                ocr_texts = [r.get('text', '') for r in result.ocr_results if r.get('success')]
                ocr_text = "\n".join(ocr_texts)[:500]  # Limit length
            
            message_content = template.format(
                guild_name=message.guild.name,
                channel_id=message.channel.id,
                author_id=message.author.id,
                confidence=result.confidence,
                message_content=message.content[:500],  # Limit length
                reason=result.final_reason,
                evidence=evidence_str,
                action=action_taken,
                ocr_text=ocr_text or "None",
                message_id=result.message_id
            )
            
            # Send notification
            notification_msg = await mod_channel.send(message_content)
            
            # Add reaction buttons for review_needed template
            if template_type == 'review_needed':
                await notification_msg.add_reaction("✅")
                await notification_msg.add_reaction("❌")
                await notification_msg.add_reaction("⚠️")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to notify moderators: {str(e)}")
            return False

    async def handle_moderator_reaction(
        self, 
        payload: discord.RawReactionActionEvent
    ) -> None:
        """Handle moderator reactions to flagged messages"""
        try:
            # Get the message
            channel = self.bot.get_channel(payload.channel_id)
            if not channel:
                return
            
            message = await channel.fetch_message(payload.message_id)
            if not message or message.author != self.bot.user:
                return
            
            # Check if this is a moderator notification
            if "SCAM DETECTION - REVIEW NEEDED" not in message.content:
                return
            
            # Get user who reacted
            guild = self.bot.get_guild(payload.guild_id)
            if not guild:
                return
            
            member = guild.get_member(payload.user_id)
            if not member or member.bot:
                return
            
            # Check if user has moderator permissions
            if not member.guild_permissions.manage_messages:
                return
            
            # Extract message ID from notification
            message_id = self._extract_message_id_from_notification(message.content)
            if not message_id:
                return
            
            # Handle reaction
            action = None
            if str(payload.emoji) == "✅":
                action = "approve"
            elif str(payload.emoji) == "❌":
                action = "delete_ban"
            elif str(payload.emoji) == "⚠️":
                action = "warn"
            
            if action:
                await self._execute_moderator_action(
                    message_id, 
                    action, 
                    member.id, 
                    guild.id
                )
                
                # Update the notification message
                await self._update_notification_message(message, action, member)
            
        except Exception as e:
            logger.error(f"Failed to handle moderator reaction: {str(e)}")

    async def _execute_moderator_action(
        self, 
        message_id: str, 
        action: str, 
        moderator_id: int, 
        guild_id: int
    ) -> None:
        """Execute moderator's decision on flagged message"""
        try:
            async with self.db_manager.get_session() as session:
                # Find the flagged message
                result = await session.execute(
                    "SELECT * FROM flagged_messages WHERE message_id = $1",
                    message_id
                )
                flagged_msg = result.fetchone()
                
                if not flagged_msg:
                    return
                
                # Record moderator action
                mod_action = ModeratorAction(
                    flagged_message_id=flagged_msg['id'],
                    moderator_id=str(moderator_id),
                    action=action,
                    reason=f"Moderator decision via reaction"
                )
                session.add(mod_action)
                
                # Update flagged message status
                await session.execute(
                    "UPDATE flagged_messages SET status = $1 WHERE id = $2",
                    'reviewed' if action == 'approve' else 'deleted',
                    flagged_msg['id']
                )
                
                await session.commit()
                
                # Execute the actual action if needed
                if action == "delete_ban":
                    await self._execute_delete_ban_action(flagged_msg, guild_id)
                elif action == "warn":
                    await self._execute_warn_action(flagged_msg, guild_id)
            
        except Exception as e:
            logger.error(f"Failed to execute moderator action: {str(e)}")

    async def _execute_delete_ban_action(self, flagged_msg: Dict, guild_id: int) -> None:
        """Execute delete and ban action"""
        try:
            guild = self.bot.get_guild(guild_id)
            if not guild:
                return
            
            # Try to delete message if it still exists
            try:
                channel = guild.get_channel(int(flagged_msg['channel_id']))
                if channel:
                    message = await channel.fetch_message(int(flagged_msg['message_id']))
                    await message.delete()
            except (discord.NotFound, discord.Forbidden):
                pass
            
            # Ban user
            try:
                user = await self.bot.fetch_user(int(flagged_msg['author_id']))
                await guild.ban(user, reason="Scam content confirmed by moderator", delete_message_days=1)
            except (discord.NotFound, discord.Forbidden):
                pass
            
        except Exception as e:
            logger.error(f"Failed to execute delete/ban action: {str(e)}")

    async def _execute_warn_action(self, flagged_msg: Dict, guild_id: int) -> None:
        """Execute warn action"""
        try:
            # Send DM warning to user
            user = await self.bot.fetch_user(int(flagged_msg['author_id']))
            guild = self.bot.get_guild(guild_id)
            
            warning_msg = f"""⚠️ **Moderator Warning**

Your message in **{guild.name}** was reviewed by a moderator and flagged as suspicious.

**Reason:** {flagged_msg['short_reason']}

Please review our community guidelines and avoid posting suspicious content in the future.

This is a warning from the moderation team."""
            
            await user.send(warning_msg)
            
        except Exception as e:
            logger.error(f"Failed to execute warn action: {str(e)}")

    def _extract_message_id_from_notification(self, content: str) -> Optional[str]:
        """Extract message ID from notification content"""
        try:
            lines = content.split('\n')
            for line in lines:
                if line.startswith('*Message ID:'):
                    return line.split(': ')[1].rstrip('*')
        except:
            pass
        return None

    async def _update_notification_message(
        self, 
        message: discord.Message, 
        action: str, 
        moderator: discord.Member
    ) -> None:
        """Update notification message with moderator action"""
        try:
            action_text = {
                'approve': '✅ Approved (Not a scam)',
                'delete_ban': '❌ Deleted and banned user',
                'warn': '⚠️ User warned'
            }.get(action, action)
            
            updated_content = f"{message.content}\n\n**RESOLVED:** {action_text} by {moderator.mention}"
            await message.edit(content=updated_content)
            
            # Remove reactions
            await message.clear_reactions()
            
        except Exception as e:
            logger.error(f"Failed to update notification message: {str(e)}")

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
                # Return default config
                return GuildConfig(
                    guild_id=guild_id,
                    auto_delete_confidence=0.9,
                    flag_threshold=0.5,
                    enable_ocr=True,
                    enable_llm=True,
                    enable_rules=True,
                    retention_days=30
                )

    async def _log_action(
        self, 
        result: DetectionResult, 
        message: discord.Message, 
        action: str, 
        action_result: ActionResult
    ) -> None:
        """Log enforcement action"""
        try:
            async with self.db_manager.get_session() as session:
                log_entry = SystemLog(
                    level='INFO' if action_result.success else 'ERROR',
                    component='actioner',
                    message=f"Action '{action}' {'completed' if action_result.success else 'failed'} for message {result.message_id}",
                    guild_id=str(message.guild.id),
                    user_id=str(message.author.id),
                    message_id=result.message_id,
                    extra_data=f"{{'confidence': {result.confidence}, 'label': '{result.label}', 'action': '{action}'}}"
                )
                session.add(log_entry)
                await session.commit()
                
        except Exception as e:
            logger.error(f"Failed to log action: {str(e)}")

    def get_stats(self) -> Dict:
        """Get actioner statistics"""
        # This would typically pull from database
        return {
            'actions_processed': 0,
            'messages_deleted': 0,
            'users_warned': 0,
            'moderator_notifications': 0
        }
