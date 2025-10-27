"""
Logging configuration module for the lanscape application.

This module provides utilities to configure logging for both console and file output,
with options to control log levels and disable Flask's verbose logging output.
"""
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional

import click


def configure_logging(loglevel: str, logfile: Optional[str], flask_logging: bool = False) -> None:
    """
    Configure the application's logging system.

    Sets up logging with the specified log level and optionally directs output to a file.
    When a logfile is specified, rotating file handlers are configured to manage log size.

    Args:
        loglevel (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        logfile (Optional[str]): Path to log file, or None for console-only logging
        flask_logging (bool): Whether to allow Flask's default logging (defaults to False)

    Raises:
        ValueError: If an invalid log level is specified
    """
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {loglevel}')

    logging.basicConfig(level=numeric_level,
                        format='[%(name)s] %(levelname)s - %(message)s')

    # flask spams too much on info
    if not flask_logging:
        disable_flask_logging()

    if logfile:
        handler = RotatingFileHandler(
            logfile, maxBytes=100000, backupCount=3)
        handler.setLevel(numeric_level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
    else:
        # For console, it defaults to basicConfig
        pass


def disable_flask_logging() -> None:
    """
    Disable Flask and Werkzeug logging output.

    Overrides click's echo and secho functions to suppress output and
    sets Werkzeug's logger level to ERROR to reduce log verbosity.
    """
    def override_click_logging():
        # pylint: disable=unused-argument
        def secho(text, file=None, nl=None, err=None, color=None, **styles):
            pass
        # pylint: disable=unused-argument

        def echo(text, file=None, nl=None, err=None, color=None, **styles):
            pass

        click.echo = echo
        click.secho = secho
    werkzeug_log = logging.getLogger('werkzeug')
    werkzeug_log.setLevel(logging.ERROR)

    override_click_logging()
