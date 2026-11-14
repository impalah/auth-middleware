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
        level=settings.get("LOG_LEVEL", "INFO"),
        format=settings.get(
            "LOG_FORMAT",
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> "
            "| <level>{level: <8}</level> | trace_id={extra[trace_id]} "
            "| <cyan>{name}</cyan>:<cyan>{function}</cyan>:"
            "<cyan>{line}</cyan> - <level>{message}</level>",
        ),
        filter=add_trace_id,  # type: ignore[arg-type]
        colorize=settings.get("LOG_COLORIZE", False),
        serialize=False,
        backtrace=True,
        # diagnose=True prints the values of local variables in tracebacks, which
        # can leak tokens and passwords into the logs: opt in explicitly.
        diagnose=settings.get("LOG_DIAGNOSE", False),
        # Do not use multiprocessing for the logs (AWS Lambda)
        enqueue=settings.get("LOG_ENQUEUE", False),
    )


__all__ = [
    "logger",
    "trace_id_context",
    "configure_logger",
]  # Add  to __all__ to be able to import them from the package
