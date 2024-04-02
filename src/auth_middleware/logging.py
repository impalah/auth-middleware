import logging

import colorlog

from auth_middleware.settings import settings

logger = logging.getLogger(
    __name__ if settings.LOGGER_NAME == "" else settings.LOGGER_NAME
)
logger.setLevel(settings.LOG_LEVEL)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(settings.LOG_LEVEL)

# create formatter
formatter = colorlog.ColoredFormatter(
    settings.LOG_FORMAT,
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
