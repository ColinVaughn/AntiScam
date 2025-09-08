import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncpg

from ...database import DatabaseManager, get_db_session, FlaggedMessage, ModeratorAction, GuildConfig, SystemLog

logger = logging.getLogger(__name__)

# Pydantic models for API
class FlaggedMessageResponse(BaseModel):
    id: int
    guild_id: str
    channel_id: str
    message_id: str
    author_id: str
    text: str
    ocr_text: Optional[str]
    label: str
    confidence: float
    rules_triggered: List[str]
    indicator_tags: List[str]
    short_reason: str
    evidence: List[str]
    status: str
    created_at: datetime
    moderator_actions: List[Dict]

class ModeratorActionRequest(BaseModel):
    action: str  # approve, delete_ban, warn, ignore
    reason: Optional[str] = None

class GuildConfigUpdate(BaseModel):
    auto_delete_confidence: Optional[float] = None
    flag_threshold: Optional[float] = None
    mod_channel_id: Optional[str] = None
    log_channel_id: Optional[str] = None
    enable_ocr: Optional[bool] = None
    enable_llm: Optional[bool] = None
    enable_rules: Optional[bool] = None
    retention_days: Optional[int] = None

class DashboardAPI:
    """FastAPI-based moderator dashboard API"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.app = FastAPI(
            title="Anti-Scam Bot Dashboard",
            description="Moderator dashboard for Discord Anti-Scam Bot",
            version="1.0.0"
        )
        
        # Configure CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Mount static files
        self.app.mount("/static", StaticFiles(directory="services/dashboard/static"), name="static")
        
        # Register routes
        self._register_routes()

    def _register_routes(self):
        """Register API routes"""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard_home():
            """Serve main dashboard page"""
            with open("services/dashboard/templates/index.html", "r") as f:
                return HTMLResponse(f.read())

        @self.app.get("/api/guilds/{guild_id}/flagged-messages")
        async def get_flagged_messages(
            guild_id: str,
            status: Optional[str] = Query(None),
            limit: int = Query(50, le=200),
            offset: int = Query(0, ge=0)
        ):
            """Get flagged messages for a guild"""
            try:
                async with self.db_manager.get_session() as session:
                    # Build query
                    query = """
                        SELECT fm.*, 
                               json_agg(
                                   json_build_object(
                                       'id', ma.id,
                                       'moderator_id', ma.moderator_id,
                                       'action', ma.action,
                                       'reason', ma.reason,
                                       'created_at', ma.created_at
                                   )
                               ) FILTER (WHERE ma.id IS NOT NULL) as moderator_actions
                        FROM flagged_messages fm
                        LEFT JOIN moderator_actions ma ON fm.id = ma.flagged_message_id
                        WHERE fm.guild_id = $1
                    """
                    params = [guild_id]
                    param_count = 1
                    
                    if status:
                        param_count += 1
                        query += f" AND fm.status = ${param_count}"
                        params.append(status)
                    
                    query += f"""
                        GROUP BY fm.id
                        ORDER BY fm.created_at DESC
                        LIMIT ${param_count + 1} OFFSET ${param_count + 2}
                    """
                    params.extend([limit, offset])
                    
                    result = await session.execute(query, *params)
                    rows = result.fetchall()
                    
                    messages = []
                    for row in rows:
                        message_data = dict(row)
                        
                        # Parse JSON fields
                        message_data['rules_triggered'] = json.loads(message_data['rules_triggered'] or '[]')
                        message_data['indicator_tags'] = json.loads(message_data['indicator_tags'] or '[]')
                        message_data['evidence'] = json.loads(message_data['evidence'] or '[]')
                        message_data['moderator_actions'] = message_data['moderator_actions'] or []
                        
                        messages.append(message_data)
                    
                    return {"messages": messages, "total": len(messages)}
                    
            except Exception as e:
                logger.error(f"Error fetching flagged messages: {str(e)}")
                raise HTTPException(status_code=500, detail="Internal server error")

        @self.app.post("/api/flagged-messages/{message_id}/action")
        async def moderate_message(
            message_id: int,
            action_request: ModeratorActionRequest,
            moderator_id: str = Query(..., description="Moderator Discord user ID")
        ):
            """Take moderator action on a flagged message"""
            try:
                async with self.db_manager.get_session() as session:
                    # Verify message exists
                    result = await session.execute(
                        "SELECT * FROM flagged_messages WHERE id = $1",
                        message_id
                    )
                    flagged_message = result.fetchone()
                    
                    if not flagged_message:
                        raise HTTPException(status_code=404, detail="Message not found")
                    
                    # Create moderator action record
                    moderator_action = ModeratorAction(
                        flagged_message_id=message_id,
                        moderator_id=moderator_id,
                        action=action_request.action,
                        reason=action_request.reason
                    )
                    session.add(moderator_action)
                    
                    # Update message status
                    new_status = "reviewed"
                    if action_request.action in ["delete_ban"]:
                        new_status = "deleted"
                    elif action_request.action == "approve":
                        new_status = "approved"
                    
                    await session.execute(
                        "UPDATE flagged_messages SET status = $1 WHERE id = $2",
                        new_status, message_id
                    )
                    
                    await session.commit()
                    
                    return {"success": True, "action": action_request.action, "status": new_status}
                    
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error processing moderator action: {str(e)}")
                raise HTTPException(status_code=500, detail="Internal server error")

        @self.app.get("/api/guilds/{guild_id}/config")
        async def get_guild_config(guild_id: str):
            """Get guild configuration"""
            try:
                async with self.db_manager.get_session() as session:
                    result = await session.execute(
                        "SELECT * FROM guild_configs WHERE guild_id = $1",
                        guild_id
                    )
                    config_data = result.fetchone()
                    
                    if not config_data:
                        raise HTTPException(status_code=404, detail="Guild configuration not found")
                    
                    return dict(config_data)
                    
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error fetching guild config: {str(e)}")
                raise HTTPException(status_code=500, detail="Internal server error")

        @self.app.put("/api/guilds/{guild_id}/config")
        async def update_guild_config(
            guild_id: str,
            config_update: GuildConfigUpdate,
            moderator_id: str = Query(..., description="Moderator Discord user ID")
        ):
            """Update guild configuration"""
            try:
                async with self.db_manager.get_session() as session:
                    # Get current config
                    result = await session.execute(
                        "SELECT * FROM guild_configs WHERE guild_id = $1",
                        guild_id
                    )
                    current_config = result.fetchone()
                    
                    if not current_config:
                        raise HTTPException(status_code=404, detail="Guild configuration not found")
                    
                    # Build update query
                    updates = []
                    params = []
                    param_count = 0
                    
                    for field, value in config_update.dict(exclude_unset=True).items():
                        if value is not None:
                            param_count += 1
                            updates.append(f"{field} = ${param_count}")
                            params.append(value)
                    
                    if updates:
                        param_count += 1
                        query = f"UPDATE guild_configs SET {', '.join(updates)} WHERE guild_id = ${param_count}"
                        params.append(guild_id)
                        
                        await session.execute(query, *params)
                        await session.commit()
                    
                    # Log the configuration change
                    log_entry = SystemLog(
                        level='INFO',
                        component='dashboard',
                        message=f"Guild configuration updated by moderator {moderator_id}",
                        guild_id=guild_id,
                        user_id=moderator_id,
                        extra_data=json.dumps(config_update.dict(exclude_unset=True))
                    )
                    session.add(log_entry)
                    await session.commit()
                    
                    return {"success": True, "updated_fields": list(config_update.dict(exclude_unset=True).keys())}
                    
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error updating guild config: {str(e)}")
                raise HTTPException(status_code=500, detail="Internal server error")

        @self.app.get("/api/guilds/{guild_id}/stats")
        async def get_guild_stats(
            guild_id: str,
            days: int = Query(30, ge=1, le=365)
        ):
            """Get guild detection statistics"""
            try:
                async with self.db_manager.get_session() as session:
                    cutoff_date = datetime.utcnow() - timedelta(days=days)
                    
                    # Get basic stats
                    stats_query = """
                        SELECT 
                            COUNT(*) as total_flagged,
                            SUM(CASE WHEN label = 'scam' THEN 1 ELSE 0 END) as scam_count,
                            SUM(CASE WHEN label = 'suspicious' THEN 1 ELSE 0 END) as suspicious_count,
                            AVG(confidence) as avg_confidence,
                            COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_review
                        FROM flagged_messages 
                        WHERE guild_id = $1 AND created_at >= $2
                    """
                    
                    result = await session.execute(stats_query, guild_id, cutoff_date)
                    stats = dict(result.fetchone())
                    
                    # Get moderator actions
                    actions_query = """
                        SELECT ma.action, COUNT(*) as count
                        FROM moderator_actions ma
                        JOIN flagged_messages fm ON ma.flagged_message_id = fm.id
                        WHERE fm.guild_id = $1 AND ma.created_at >= $2
                        GROUP BY ma.action
                    """
                    
                    result = await session.execute(actions_query, guild_id, cutoff_date)
                    actions = {row['action']: row['count'] for row in result.fetchall()}
                    
                    # Get daily breakdown
                    daily_query = """
                        SELECT 
                            DATE(created_at) as date,
                            COUNT(*) as total,
                            SUM(CASE WHEN label = 'scam' THEN 1 ELSE 0 END) as scams
                        FROM flagged_messages 
                        WHERE guild_id = $1 AND created_at >= $2
                        GROUP BY DATE(created_at)
                        ORDER BY date DESC
                        LIMIT 30
                    """
                    
                    result = await session.execute(daily_query, guild_id, cutoff_date)
                    daily_stats = [dict(row) for row in result.fetchall()]
                    
                    return {
                        "period_days": days,
                        "summary": stats,
                        "moderator_actions": actions,
                        "daily_breakdown": daily_stats
                    }
                    
            except Exception as e:
                logger.error(f"Error fetching guild stats: {str(e)}")
                raise HTTPException(status_code=500, detail="Internal server error")

        @self.app.get("/api/guilds/{guild_id}/logs")
        async def get_system_logs(
            guild_id: str,
            level: Optional[str] = Query(None),
            component: Optional[str] = Query(None),
            limit: int = Query(100, le=500),
            offset: int = Query(0, ge=0)
        ):
            """Get system logs for a guild"""
            try:
                async with self.db_manager.get_session() as session:
                    # Build query
                    query = "SELECT * FROM system_logs WHERE guild_id = $1"
                    params = [guild_id]
                    param_count = 1
                    
                    if level:
                        param_count += 1
                        query += f" AND level = ${param_count}"
                        params.append(level)
                    
                    if component:
                        param_count += 1
                        query += f" AND component = ${param_count}"
                        params.append(component)
                    
                    query += f"""
                        ORDER BY created_at DESC
                        LIMIT ${param_count + 1} OFFSET ${param_count + 2}
                    """
                    params.extend([limit, offset])
                    
                    result = await session.execute(query, *params)
                    logs = [dict(row) for row in result.fetchall()]
                    
                    return {"logs": logs, "total": len(logs)}
                    
            except Exception as e:
                logger.error(f"Error fetching system logs: {str(e)}")
                raise HTTPException(status_code=500, detail="Internal server error")

        @self.app.get("/api/health")
        async def health_check():
            """API health check"""
            try:
                # Test database connection
                async with self.db_manager.get_session() as session:
                    await session.execute("SELECT 1")
                
                return {
                    "status": "healthy",
                    "timestamp": datetime.utcnow(),
                    "database": "connected"
                }
            except Exception as e:
                return {
                    "status": "unhealthy",
                    "timestamp": datetime.utcnow(),
                    "error": str(e)
                }

    def get_app(self) -> FastAPI:
        """Get FastAPI application instance"""
        return self.app
