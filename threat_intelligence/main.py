"""
TraceMail AI — Threat Intelligence Service Entrypoint
Runs Uvicorn server on configured host and port.
"""

import uvicorn
from shared.config.settings import get_settings

if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "threat_intelligence.service:app",
        host="0.0.0.0",
        port=settings.THREAT_INTEL_PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
