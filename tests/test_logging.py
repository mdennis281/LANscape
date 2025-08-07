"""
Unit tests for the logging configuration and functionality of the LANscape application.
Tests include log file creation, CLI logging settings, and runtime arguments for logging.
"""

import logging
import os
import tempfile
import unittest
from logging.handlers import RotatingFileHandler
from unittest.mock import patch

# Third-party imports - ensure 'click' is installed with 'pip install click'
import click

from lanscape.libraries.logger import configure_logging
from lanscape.libraries.runtime_args import parse_args


class LoggingConfigTests(unittest.TestCase):
    """
    Test cases for the logging configuration functionality.
    Verifies that log handlers are properly configured based on settings.
    """

    def setUp(self):
        """Prepare the test environment by clearing existing log handlers."""
        self.root = logging.getLogger()
        self.root.handlers.clear()
        self.original_click_echo = click.echo
        self.original_click_secho = click.secho

    def tearDown(self):
        """Clean up after tests by resetting logging and click functionality."""
        self.root.handlers.clear()
        logging.shutdown()
        click.echo = self.original_click_echo
        click.secho = self.original_click_secho

    def test_configure_logging_writes_file(self):
        """Test that logs are properly written to the specified log file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logfile = os.path.join(tmpdir, 'test.log')
            configure_logging('INFO', logfile, flask_logging=True)
            logging.getLogger('test').info('hello file')
            for handler in logging.getLogger().handlers:
                handler.flush()
            with open(logfile, 'r', encoding='utf-8') as fh:
                contents = fh.read()
            self.assertIn('hello file', contents)
            self.tearDown()

    def test_configure_logging_without_file(self):
        """Test that no file handlers are created when no log file is specified."""
        configure_logging('INFO', None, flask_logging=True)
        root_handlers = logging.getLogger().handlers
        self.assertTrue(all(not isinstance(h, RotatingFileHandler)
                        for h in root_handlers))

    def test_disable_flask_logging_overrides_click(self):
        """Test that disabling Flask logging properly overrides click echo functions."""
        configure_logging('INFO', None, flask_logging=False)
        self.assertNotEqual(click.echo, self.original_click_echo)
        self.assertNotEqual(click.secho, self.original_click_secho)
        self.assertEqual(logging.getLogger('werkzeug').level, logging.ERROR)


class RuntimeArgsLoggingTests(unittest.TestCase):
    """
    Test cases for runtime argument parsing related to logging configuration.
    Verifies command-line arguments are correctly handled.
    """

    def test_parse_args_logfile_path(self):
        """Test that the logfile argument is correctly parsed from command-line arguments."""
        with patch('sys.argv', ['prog', '--logfile', '/tmp/custom.log']):
            args = parse_args()
        self.assertEqual(args.logfile, '/tmp/custom.log')
