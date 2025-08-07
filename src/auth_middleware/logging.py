import contextvars
import sys
from typing import Any

from loguru import logger

# Create a context variable to store the trace_id
trace_id_context = contextvars.ContextVar("trace_id", default=None)


def add_trace_id(record: dict[str, Any]) -> bool:
    """Add the trace_id to the log record

    Args:
        record: The log record to be modified

    Returns:
        bool: Always returns True to indicate the filter passed
    """
    trace_id = trace_id_context.get()
    record["extra"]["trace_id"] = trace_id if trace_id else "N/A"
    return True  # Return True to indicate the filter passed


def configure_logger(settings: dict[str, Any]) -> None:
    """Configure the logger"""

    logger.remove()  # Remove the default logger
    print("Configuring logger with settings:", settings)

    logger.add(
        sink=sys.stderr,
        level=settings["LOG_LEVEL"] if "LOG_LEVEL" in settings else "INFO",
        format=(
            settings["LOG_FORMAT"]
            if "LOG_FORMAT" in settings
            else (
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> "
                "| <level>{level: <8}</level> | trace_id={extra[trace_id]} "
                "| <cyan>{name}</cyan>:<cyan>{function}</cyan>:"
                "<cyan>{line}</cyan> - <level>{message}</level>"
            )
        ),
        filter=add_trace_id,
        colorize=settings["LOG_COLORIZE"] if "LOG_COLORIZE" in settings else False,
        serialize=False,
        backtrace=True,
        diagnose=True,
        enqueue=(
            settings["LOG_ENQUEUE"] if "LOG_ENQUEUE" in settings else False
        ),  # Do not uses multiprocesing for the logs (aws lambda)
    )


__all__ = [
    "logger",
    "trace_id_context",
    "configure_logger",
]  # Add  to __all__ to be able to import them from the package
