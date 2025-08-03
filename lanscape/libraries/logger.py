import logging
from logging.handlers import RotatingFileHandler
import click
from typing import Optional


def configure_logging(loglevel: str, logfile: Optional[str], flask_logging: bool = False) -> None:
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

    def override_click_logging():
        def secho(text, file=None, nl=None, err=None, color=None, **styles):
            pass

        def echo(text, file=None, nl=None, err=None, color=None, **styles):
            pass

        click.echo = echo
        click.secho = secho
    werkzeug_log = logging.getLogger('werkzeug')
    werkzeug_log.setLevel(logging.ERROR)

    override_click_logging()
