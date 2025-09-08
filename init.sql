-- Initialize database with default settings
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_flagged_messages_composite ON flagged_messages(guild_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_moderator_actions_composite ON moderator_actions(flagged_message_id, created_at);
CREATE INDEX IF NOT EXISTS idx_system_logs_composite ON system_logs(component, level, created_at);

-- Insert default domain blacklist entries (common scam domains)
INSERT INTO domains_blacklist (domain, added_by, guild_id, reason, created_at) VALUES 
    ('bit.ly', '0', '0', 'Common shortener used in scams', NOW()),
    ('tinyurl.com', '0', '0', 'Common shortener used in scams', NOW()),
    ('t.co', '0', '0', 'Common shortener used in scams', NOW())
ON CONFLICT (domain) DO NOTHING;
