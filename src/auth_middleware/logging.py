import logging

import colorlog

from auth_middleware.settings import settings

logger = logging.getLogger(
    __name__ if settings.AUTH_MIDDLEWARE_LOGGER_NAME == "" else settings.AUTH_MIDDLEWARE_LOGGER_NAME
)
logger.setLevel(settings.AUTH_MIDDLEWARE_LOG_LEVEL)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(settings.AUTH_MIDDLEWARE_LOG_LEVEL)

# create formatter
formatter = colorlog.ColoredFormatter(
    settings.AUTH_MIDDLEWARE_LOG_FORMAT,
    reset=True,
    log_colors={
        "DEBUG": "cyan",
        "INFO": "green",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "red,bg_white",
    },
)

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)
