import unittest
import logging
import os
import tempfile
from unittest.mock import patch

import click
from logging.handlers import RotatingFileHandler

from lanscape.libraries.logger import configure_logging
from lanscape.libraries.runtime_args import parse_args


class LoggingConfigTests(unittest.TestCase):
    def setUp(self):
        self.root = logging.getLogger()
        self.root.handlers.clear()
        self.original_click_echo = click.echo
        self.original_click_secho = click.secho

    def tearDown(self):
        self.root.handlers.clear()
        logging.shutdown()
        click.echo = self.original_click_echo
        click.secho = self.original_click_secho

    def test_configure_logging_writes_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logfile = os.path.join(tmpdir, 'test.log')
            configure_logging('INFO', logfile, flask_logging=True)
            logging.getLogger('test').info('hello file')
            for handler in logging.getLogger().handlers:
                handler.flush()
            with open(logfile, 'r') as fh:
                contents = fh.read()
            self.assertIn('hello file', contents)
            self.tearDown()

    def test_configure_logging_without_file(self):
        configure_logging('INFO', None, flask_logging=True)
        root_handlers = logging.getLogger().handlers
        self.assertTrue(all(not isinstance(h, RotatingFileHandler) for h in root_handlers))

    def test_disable_flask_logging_overrides_click(self):
        configure_logging('INFO', None, flask_logging=False)
        self.assertNotEqual(click.echo, self.original_click_echo)
        self.assertNotEqual(click.secho, self.original_click_secho)
        self.assertEqual(logging.getLogger('werkzeug').level, logging.ERROR)


class RuntimeArgsLoggingTests(unittest.TestCase):
    def test_parse_args_logfile_path(self):
        with patch('sys.argv', ['prog', '--logfile', '/tmp/custom.log']):
            args = parse_args()
        self.assertEqual(args.logfile, '/tmp/custom.log')
