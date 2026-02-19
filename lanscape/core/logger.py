"""
Logging configuration module for the lanscape application.

This module provides utilities to configure logging for both console and file output,
with options to control log levels.
"""
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional


def configure_logging(loglevel: str, logfile: Optional[str] = None) -> None:
    """
    Configure the application's logging system.

    Sets up logging with the specified log level and optionally directs output to a file.
    When a logfile is specified, rotating file handlers are configured to manage log size.

    Args:
        loglevel (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        logfile (Optional[str]): Path to log file, or None for console-only logging

    Raises:
        ValueError: If an invalid log level is specified
    """
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {loglevel}')

    logging.basicConfig(level=numeric_level,
                        format='[%(name)s] %(levelname)s - %(message)s')

    if logfile:
        handler = RotatingFileHandler(
            logfile, maxBytes=100000, backupCount=3)
        handler.setLevel(numeric_level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
