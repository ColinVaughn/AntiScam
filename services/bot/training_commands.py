import discord
from discord.ext import commands
from datetime import datetime
from typing import Optional
import logging

from ...core.training_system import get_training_system
from ...core.logging_system import LogComponent

logger = logging.getLogger(__name__)

class TrainingCommands(commands.Cog):
    """Training system commands for the Anti-Scam Bot"""
    
    def __init__(self, bot):
        self.bot = bot

    @commands.group(name='train')
    @commands.has_permissions(manage_messages=True)
    async def training_group(self, ctx):
        """Training system commands"""
        if ctx.invoked_subcommand is None:
            embed = discord.Embed(
                title="🎓 Training System Commands",
                description="Help improve scam detection by providing training examples",
                color=0x3498db
            )
            
            embed.add_field(
                name="Commands",
                value="""
                `!scamtrain submit <message_link> <label> <explanation>` - Submit message for training
                `!scamtrain image <label> <explanation>` - Submit image (attach to message)  
                `!scamtrain text "text here" <label> <explanation>` - Submit text example
                `!scamtrain stats` - Show training statistics
                `!scamtrain pending` - List pending examples for validation
                `!scamtrain validate <id> <approve|reject> [reason]` - Validate training example
                `!scamtrain batch create` - Create training batch from validated examples
                """,
                inline=False
            )
            
            embed.add_field(
                name="Labels",
                value="`scam`, `safe`, `suspicious`",
                inline=False
            )
            
            embed.add_field(
                name="Example",
                value="`!scamtrain submit https://discord.com/channels/.../... scam This is asking for payment via Venmo which is a common scam pattern`",
                inline=False
            )
            
            await ctx.send(embed=embed)

    @training_group.command(name='submit')
    async def train_submit_link(self, ctx, message_link: str, label: str, *, explanation: str):
        """Submit a Discord message link for training"""
        try:
            guild_id = str(ctx.guild.id)
            moderator_id = str(ctx.author.id)
            
            # Extract scam type from explanation (optional)
            scam_type = None
            explanation_lower = explanation.lower()
            if 'phishing' in explanation_lower:
                scam_type = 'phishing'
            elif 'payment' in explanation_lower or 'money' in explanation_lower:
                scam_type = 'payment_fraud'
            elif 'impersonation' in explanation_lower or 'admin' in explanation_lower:
                scam_type = 'impersonation'
            elif 'investment' in explanation_lower or 'crypto' in explanation_lower:
                scam_type = 'investment'
            
            training_system = get_training_system()
            result = await training_system.process_message_link(
                guild_id=guild_id,
                moderator_id=moderator_id,
                message_link=message_link,
                label=label,
                explanation=explanation,
                scam_type=scam_type
            )
            
            if result['success']:
                embed = discord.Embed(
                    title="✅ Training Example Submitted",
                    description=result['message'],
                    color=0x00ff00
                )
                embed.add_field(name="Label", value=label, inline=True)
                embed.add_field(name="Type", value=scam_type or "General", inline=True)
                embed.add_field(name="Explanation", value=explanation[:500] + ("..." if len(explanation) > 500 else ""), inline=False)
            else:
                embed = discord.Embed(
                    title="❌ Submission Failed",
                    description=result['error'],
                    color=0xff0000
                )
            
            await ctx.send(embed=embed)
            
        except Exception as e:
            await ctx.send(f"❌ Error submitting training example: {str(e)}")
            if hasattr(self.bot, 'logger'):
                await self.bot.logger.error(LogComponent.BOT, f"Training submit error: {str(e)}")

    @training_group.command(name='image')
    async def train_submit_image(self, ctx, label: str, *, explanation: str):
        """Submit an image for training (attach image to message)"""
        try:
            if not ctx.message.attachments:
                await ctx.send("❌ Please attach an image to your message")
                return
            
            attachment = ctx.message.attachments[0]
            if not attachment.content_type.startswith('image/'):
                await ctx.send("❌ Attachment must be an image")
                return
            
            guild_id = str(ctx.guild.id)
            moderator_id = str(ctx.author.id)
            
            # Download image
            image_data = await attachment.read()
            
            # Extract scam type
            scam_type = None
            explanation_lower = explanation.lower()
            if 'phishing' in explanation_lower:
                scam_type = 'phishing'
            elif 'payment' in explanation_lower:
                scam_type = 'payment_fraud'
            elif 'impersonation' in explanation_lower:
                scam_type = 'impersonation'
            
            training_system = get_training_system()
            result = await training_system.data_manager.submit_training_example(
                guild_id=guild_id,
                submitted_by=moderator_id,
                image_url=attachment.url,
                image_data=image_data,
                label=label,
                explanation=explanation,
                scam_type=scam_type
            )
            
            if result['success']:
                embed = discord.Embed(
                    title="✅ Image Training Example Submitted",
                    description=result['message'],
                    color=0x00ff00
                )
                embed.add_field(name="Label", value=label, inline=True)
                embed.add_field(name="Type", value=scam_type or "General", inline=True)
                embed.add_field(name="Explanation", value=explanation[:500] + ("..." if len(explanation) > 500 else ""), inline=False)
                embed.set_thumbnail(url=attachment.url)
            else:
                embed = discord.Embed(
                    title="❌ Submission Failed",
                    description=result['error'],
                    color=0xff0000
                )
            
            await ctx.send(embed=embed)
            
        except Exception as e:
            await ctx.send(f"❌ Error submitting image example: {str(e)}")
            if hasattr(self.bot, 'logger'):
                await self.bot.logger.error(LogComponent.BOT, f"Training image error: {str(e)}")

    @training_group.command(name='text')
    async def train_submit_text(self, ctx, text: str, label: str, *, explanation: str):
        """Submit text for training"""
        try:
            guild_id = str(ctx.guild.id)
            moderator_id = str(ctx.author.id)
            
            # Extract scam type
            scam_type = None
            explanation_lower = explanation.lower()
            if 'phishing' in explanation_lower:
                scam_type = 'phishing'
            elif 'payment' in explanation_lower:
                scam_type = 'payment_fraud'
            elif 'impersonation' in explanation_lower:
                scam_type = 'impersonation'
            
            training_system = get_training_system()
            result = await training_system.data_manager.submit_training_example(
                guild_id=guild_id,
                submitted_by=moderator_id,
                message_text=text,
                label=label,
                explanation=explanation,
                scam_type=scam_type
            )
            
            if result['success']:
                embed = discord.Embed(
                    title="✅ Text Training Example Submitted",
                    description=result['message'],
                    color=0x00ff00
                )
                embed.add_field(name="Label", value=label, inline=True)
                embed.add_field(name="Type", value=scam_type or "General", inline=True)
                embed.add_field(name="Text", value=text[:500] + ("..." if len(text) > 500 else ""), inline=False)
                embed.add_field(name="Explanation", value=explanation[:500] + ("..." if len(explanation) > 500 else ""), inline=False)
            else:
                embed = discord.Embed(
                    title="❌ Submission Failed",
                    description=result['error'],
                    color=0xff0000
                )
            
            await ctx.send(embed=embed)
            
        except Exception as e:
            await ctx.send(f"❌ Error submitting text example: {str(e)}")
            if hasattr(self.bot, 'logger'):
                await self.bot.logger.error(LogComponent.BOT, f"Training text error: {str(e)}")

    @training_group.command(name='stats')
    async def train_stats(self, ctx):
        """Show training statistics"""
        try:
            guild_id = str(ctx.guild.id)
            training_system = get_training_system()
            stats = await training_system.data_manager.get_training_stats(guild_id)
            
            embed = discord.Embed(
                title="🎓 Training Statistics",
                color=0x3498db,
                timestamp=datetime.utcnow()
            )
            
            embed.add_field(
                name="📊 Total Examples",
                value=str(stats.get('total_examples', 0)),
                inline=True
            )
            
            by_label = stats.get('by_label', {})
            embed.add_field(
                name="🏷️ By Label",
                value=f"""
                Scam: {by_label.get('scam', 0)}
                Safe: {by_label.get('safe', 0)}
                Suspicious: {by_label.get('suspicious', 0)}
                """,
                inline=True
            )
            
            by_status = stats.get('by_status', {})
            embed.add_field(
                name="📋 By Status",
                value=f"""
                Pending: {by_status.get('pending', 0)}
                Validated: {by_status.get('validated', 0)}
                Rejected: {by_status.get('rejected', 0)}
                Used: {by_status.get('used', 0)}
                """,
                inline=True
            )
            
            await ctx.send(embed=embed)
            
        except Exception as e:
            await ctx.send(f"❌ Error retrieving training statistics: {str(e)}")
            if hasattr(self.bot, 'logger'):
                await self.bot.logger.error(LogComponent.BOT, f"Training stats error: {str(e)}")

    @training_group.command(name='pending')
    async def train_pending(self, ctx, limit: int = 10):
        """List pending training examples"""
        try:
            guild_id = str(ctx.guild.id)
            training_system = get_training_system()
            examples = await training_system.data_manager.get_pending_examples(guild_id, limit)
            
            if not examples:
                await ctx.send("✅ No pending training examples")
                return
            
            embed = discord.Embed(
                title="📋 Pending Training Examples",
                description=f"Showing {len(examples)} examples (use `!scamtrain validate <id> approve/reject`)",
                color=0xffa500
            )
            
            for example in examples[:5]:  # Show max 5 in embed
                content = example.get('message_text', 'Image only')
                if content and len(content) > 100:
                    content = content[:100] + "..."
                
                embed.add_field(
                    name=f"ID: {example['id']} | Label: {example['label']}",
                    value=f"**Content:** {content or 'Image only'}\n**Explanation:** {example['explanation'][:150]}...\n**Submitted:** <t:{int(example['created_at'].timestamp())}:R>",
                    inline=False
                )
            
            await ctx.send(embed=embed)
            
        except Exception as e:
            await ctx.send(f"❌ Error retrieving pending examples: {str(e)}")
            if hasattr(self.bot, 'logger'):
                await self.bot.logger.error(LogComponent.BOT, f"Training pending error: {str(e)}")

    @training_group.command(name='validate')
    async def train_validate(self, ctx, example_id: int, action: str, *, reason: str = None):
        """Validate a training example"""
        try:
            moderator_id = str(ctx.author.id)
            
            training_system = get_training_system()
            result = await training_system.data_manager.validate_example(
                example_id=example_id,
                validated_by=moderator_id,
                action=action,
                notes=reason
            )
            
            if result['success']:
                embed = discord.Embed(
                    title=f"✅ Example {action.title()}d",
                    description=result['message'],
                    color=0x00ff00 if action == 'approve' else 0xffa500
                )
                if reason:
                    embed.add_field(name="Reason", value=reason, inline=False)
            else:
                embed = discord.Embed(
                    title="❌ Validation Failed",
                    description=result['error'],
                    color=0xff0000
                )
            
            await ctx.send(embed=embed)
            
            # Check if we should trigger auto-training
            await training_system.schedule_auto_training(str(ctx.guild.id))
            
        except Exception as e:
            await ctx.send(f"❌ Error validating example: {str(e)}")
            if hasattr(self.bot, 'logger'):
                await self.bot.logger.error(LogComponent.BOT, f"Training validate error: {str(e)}")

    @training_group.command(name='batch')
    @commands.has_permissions(administrator=True)
    async def train_batch(self, ctx, action: str = "create"):
        """Training batch management"""
        try:
            guild_id = str(ctx.guild.id)
            moderator_id = str(ctx.author.id)
            
            training_system = get_training_system()
            
            if action == "create":
                result = await training_system.training_manager.create_training_batch(
                    created_by=moderator_id,
                    guild_id=guild_id,
                    model_type="rules"
                )
                
                if result['success']:
                    embed = discord.Embed(
                        title="✅ Training Batch Created",
                        description=f"Batch ID: `{result['batch_id']}`",
                        color=0x00ff00
                    )
                    embed.add_field(name="Examples", value=str(result['examples_count']), inline=True)
                    
                    # Auto-start training
                    train_result = await training_system.training_manager.start_training(result['batch_id'])
                    if train_result['success']:
                        embed.add_field(name="Training", value="Started automatically", inline=True)
                        embed.add_field(name="Result", value=train_result.get('message', 'Training completed'), inline=False)
                    else:
                        embed.add_field(name="Training", value=f"Failed: {train_result['error']}", inline=True)
                else:
                    embed = discord.Embed(
                        title="❌ Batch Creation Failed",
                        description=result['error'],
                        color=0xff0000
                    )
            else:
                embed = discord.Embed(
                    title="❌ Invalid Action",
                    description="Use `create` to create a new training batch",
                    color=0xff0000
                )
            
            await ctx.send(embed=embed)
            
        except Exception as e:
            await ctx.send(f"❌ Error managing training batch: {str(e)}")
            if hasattr(self.bot, 'logger'):
                await self.bot.logger.error(LogComponent.BOT, f"Training batch error: {str(e)}")

async def setup(bot):
    """Setup function for the cog"""
    await bot.add_cog(TrainingCommands(bot))
