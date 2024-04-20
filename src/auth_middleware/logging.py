import sys

from loguru import logger

from auth_middleware.settings import settings

# Configurar el logger
logger.remove()
logger.add(
    sink=sys.stderr,
    level=settings.AUTH_MIDDLEWARE_LOG_LEVEL,
    format=settings.AUTH_MIDDLEWARE_LOG_FORMAT,
    colorize=True,
)
