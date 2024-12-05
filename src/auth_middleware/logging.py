import sys

from loguru import logger
from typing import Optional

from auth_middleware.settings import settings

logger.remove()


def configure_logger(
    level: Optional[str] = None,
    format: Optional[str] = None,
    colorize: Optional[bool] = True,
):
    """Configure logger.

    Args:
        level (Optional[str]): Log level (default from settings).
        format (Optional[str]): Log format (default from settings).
        colorize (Optional[bool]): Colorize logger (default True).
    """
    logger.remove()
    logger.add(
        sink=sys.stderr,
        level=level or settings.AUTH_MIDDLEWARE_LOG_LEVEL,
        format=format or settings.AUTH_MIDDLEWARE_LOG_FORMAT,
        colorize=colorize,
    )


# Configure logger with the default settings
configure_logger()
