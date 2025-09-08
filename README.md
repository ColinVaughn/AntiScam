# Discord Anti-Scam Bot

An offline-first Discord moderation bot that detects and blocks scams in text and images using on-premises LLMs and OCR.

## Features

- **Offline Detection**: Uses self-hosted LLMs and OCR for complete privacy
- **Multi-layered Analysis**: Rule-based, OCR, and LLM inference pipeline
- **Smart Actions**: Auto-delete, flag for review, or monitor based on confidence
- **Moderator Dashboard**: Web-based interface for reviewing flagged content
- **Configurable Policies**: Per-guild settings and thresholds
- **Comprehensive Logging**: Full audit trail with performance metrics

## Architecture

```
Discord Gateway ← Bot Service → Detection Pipeline → Actioner → Moderator Dashboard
                              ↓
                          [Rules, OCR, LLM] → Database & Logs
```

### Components

1. **Discord Bot Service** - Message event handling and Discord integration
2. **Detection Pipeline** - Coordinates rule-based, OCR, and LLM analysis
3. **OCR Service** - Tesseract-based text extraction from images
4. **LLM Service** - Offline quantized model inference with structured prompts
5. **Actioner** - Policy enforcement and moderator notifications
6. **Dashboard** - FastAPI-based web interface for moderators
7. **Database** - PostgreSQL for flagged messages, actions, and configuration

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Discord Bot Token
- Quantized LLM model (GGUF format)

### Setup

1. **Clone and configure**:
```bash
git clone <repository>
cd AntiScam
cp .env.example .env
# Edit .env with your Discord token and settings
```

2. **Download a quantized model**:
```bash
# Example: Download a quantized Llama model
mkdir -p models
wget https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF/resolve/main/llama-2-7b-chat.q4_0.gguf -O models/quantized_model.gguf
```

3. **Start services**:
```bash
docker-compose up -d
```

4. **Invite bot to Discord**:
   - Go to Discord Developer Portal
   - Create application and bot
   - Generate invite link with permissions: `Manage Messages`, `Read Message History`, `Send Messages`, `Add Reactions`

### Configuration

Access the dashboard at `http://localhost:8080` to configure:

- **Detection thresholds**: Auto-delete and flag confidence levels
- **Feature toggles**: Enable/disable OCR, LLM, or rule-based detection
- **Channels**: Set moderator notification and log channels
- **Retention**: Configure data retention policies

### Discord Commands

```
!scamconfig set auto_delete_confidence 0.9
!scamconfig set flag_threshold 0.5
!scamconfig set mod_channel #moderators
!scamconfig show
!scamstats
```

## Development

### Project Structure

```
AntiScam/
├── core/                    # Core detection logic
│   ├── preprocessor.py      # Text normalization and feature extraction
│   ├── rule_detector.py     # Rule-based scam detection
│   ├── detector_pipeline.py # Main detection coordinator
│   ├── actioner.py         # Policy enforcement
│   └── logging_system.py   # Comprehensive logging
├── database/               # Database models and management
│   ├── models.py          # SQLAlchemy models
│   ├── database.py        # Database management
│   └── __init__.py
├── services/              # Microservices
│   ├── bot/              # Discord bot service
│   ├── ocr/              # OCR processing service
│   ├── llm/              # LLM inference service
│   └── dashboard/        # Web dashboard
├── docker-compose.yml     # Service orchestration
├── requirements.txt       # Python dependencies
└── init.sql              # Database initialization
```

### Local Development

1. **Install dependencies**:
```bash
pip install -r requirements.txt
```

2. **Setup database**:
```bash
# Start PostgreSQL and Redis
docker-compose up postgres redis -d

# Initialize database
python -c "
from database import init_database
import asyncio
async def init():
    db = init_database('postgresql://antiscam:password@localhost/antiscam_db')
    await db.create_tables()
asyncio.run(init())
"
```

3. **Run services individually**:
```bash
# Bot service
python -m services.bot.main

# OCR service
python -m services.ocr.main

# LLM service
python -m services.llm.main

# Dashboard
python -m services.dashboard.main
```

### Testing

```bash
# Run basic tests
python -m pytest tests/

# Test specific components
python -m pytest tests/test_detector.py
python -m pytest tests/test_ocr.py
```

## Configuration Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DISCORD_TOKEN` | Discord bot token | Required |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://antiscam:password@localhost/antiscam_db` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `LLM_MODEL_PATH` | Path to GGUF model file | `./models/quantized_model.gguf` |
| `LLM_THREADS` | CPU threads for LLM inference | `4` |
| `TESSERACT_CMD` | Tesseract executable path | `/usr/bin/tesseract` |
| `LOG_LEVEL` | Logging level | `INFO` |

### Detection Rules

The system includes built-in rules for:

- **Payment scams**: Venmo, CashApp, PayPal requests
- **Impersonation**: Fake admin/moderator messages  
- **Phishing**: Account suspension/verification scams
- **Giveaways**: Fake contests and crypto airdrops
- **Social engineering**: Remote access and urgency tactics

Custom rules can be added via the dashboard or API.

### Performance Tuning

- **Rule-based detection**: <50ms average
- **OCR processing**: 200-1000ms per image
- **LLM inference**: 300-800ms for classification
- **Memory usage**: ~2GB with 7B quantized model

Scale by:
- Adding more LLM worker replicas
- Using GPU acceleration for LLM inference
- Implementing Redis caching for domain lookups
- Horizontal scaling of OCR workers

## API Reference

### Dashboard API

Base URL: `http://localhost:8080/api`

#### Get Flagged Messages
```
GET /guilds/{guild_id}/flagged-messages?status=pending&limit=50
```

#### Take Moderator Action
```
POST /flagged-messages/{message_id}/action?moderator_id={user_id}
Content-Type: application/json

{
  "action": "approve|delete_ban|warn",
  "reason": "Optional reason"
}
```

#### Update Guild Configuration
```
PUT /guilds/{guild_id}/config?moderator_id={user_id}
Content-Type: application/json

{
  "auto_delete_confidence": 0.9,
  "flag_threshold": 0.5,
  "enable_ocr": true,
  "enable_llm": true
}
```

#### Get Statistics
```
GET /guilds/{guild_id}/stats?days=30
```

## Security Considerations

- **Data Privacy**: All processing happens on-premises
- **Access Control**: Dashboard requires Discord role verification
- **Rate Limiting**: Built-in protection against spam/abuse
- **Data Retention**: Configurable cleanup of old records
- **Audit Trail**: Complete logging of all actions

## Troubleshooting

### Common Issues

1. **Bot not responding**:
   - Check Discord token in `.env`
   - Verify bot permissions in Discord server
   - Check bot service logs: `docker-compose logs bot`

2. **LLM inference failing**:
   - Ensure model file exists and is valid GGUF format
   - Check available system memory (>4GB recommended)
   - Review LLM service logs: `docker-compose logs llm-service`

3. **OCR not working**:
   - Verify Tesseract installation in container
   - Check image format support (PNG, JPG, GIF)
   - Review OCR service logs: `docker-compose logs ocr-service`

4. **Dashboard not accessible**:
   - Verify port 8080 is not blocked
   - Check database connectivity
   - Review dashboard logs: `docker-compose logs dashboard`

### Monitoring

Access service health at:
- Dashboard: `http://localhost:8080/api/health`
- Bot statistics: `!scamstats` command in Discord
- System logs: Dashboard → System Logs tab

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- GitHub Issues: Report bugs and feature requests
- Documentation: Check this README and code comments
- Discord: Join our support server [invite link]
