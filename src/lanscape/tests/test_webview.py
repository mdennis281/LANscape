import webview
from ._helpers import webview_client
import unittest
import warnings

# Suppress ResourceWarning
warnings.simplefilter("ignore", ResourceWarning)

class WebViewTestCase(unittest.TestCase):
    
    @webview_client('Test Window','https://google.com')
    def test_webview_launch(self, client: webview.Window):
        # This test checks that the window has been created successfully
        self.assertIsNotNone(client,msg="WebView window failed to create.")
        self.assertEqual(client.title,'Test Window',msg='WebView window title did not match.')
        self.assertIn('google.com',client.real_url,msg=f'URL mismatch')
