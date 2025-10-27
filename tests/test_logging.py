"""
Unit tests for the logging configuration and functionality of the LANscape application.
Tests include log file creation, CLI logging settings, and runtime arguments for logging.
"""

import logging
import os
import tempfile
import pytest
from logging.handlers import RotatingFileHandler
from unittest.mock import patch

# Third-party imports - ensure 'click' is installed with 'pip install click'
import click

from lanscape.core.logger import configure_logging
from lanscape.core.runtime_args import parse_args


@pytest.fixture
def logging_cleanup():
    """Clean up logging after test (manual use)."""
    yield
    
    # Cleanup after test
    root = logging.getLogger()
    for handler in root.handlers[:]:
        handler.close()
    root.handlers.clear()
    logging.shutdown()


# Logging Configuration Tests
############################

def test_configure_logging_writes_file():
    """Test that logs are properly written to the specified log file."""
    # Save existing handlers and clear them to avoid pytest interference
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers[:]
    root_logger.handlers.clear()
    
    tmpdir = tempfile.mkdtemp()
    try:
        logfile = os.path.join(tmpdir, 'test.log')
        configure_logging('INFO', logfile, flask_logging=True)
        logging.getLogger('test').info('hello file')
        
        # Flush all handlers to ensure content is written
        for handler in logging.getLogger().handlers:
            handler.flush()
        
        # Read the file contents
        with open(logfile, 'r', encoding='utf-8') as fh:
            contents = fh.read()
        
        # Clean up handlers to release file locks
        for handler in logging.getLogger().handlers[:]:
            if hasattr(handler, 'close'):
                handler.close()
        logging.getLogger().handlers.clear()
        
        assert 'hello file' in contents
        
    finally:
        # Restore original handlers
        root_logger.handlers = original_handlers
        
        # Clean up the temp directory
        import shutil
        try:
            shutil.rmtree(tmpdir)
        except PermissionError:
            # On Windows, sometimes files are still locked, ignore cleanup errors
            pass
def test_configure_logging_without_file(logging_cleanup):
    """Test that no file handlers are created when no log file is specified."""
    configure_logging('INFO', None, flask_logging=True)
    root_handlers = logging.getLogger().handlers
    assert all(not isinstance(h, RotatingFileHandler) for h in root_handlers)


def test_disable_flask_logging_overrides_click(logging_cleanup):
    """Test that disabling Flask logging properly overrides click echo functions."""
    original_click_echo = click.echo
    original_click_secho = click.secho
    
    configure_logging('INFO', None, flask_logging=False)
    assert click.echo != original_click_echo
    assert click.secho != original_click_secho
    assert logging.getLogger('werkzeug').level == logging.ERROR


# Runtime Arguments Tests
#########################

def test_parse_args_logfile_path():
    """Test that the logfile argument is correctly parsed from command-line arguments."""
    with patch('sys.argv', ['prog', '--logfile', '/tmp/custom.log']):
        args = parse_args()
    assert args.logfile == '/tmp/custom.log'
