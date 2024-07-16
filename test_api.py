import unittest
import json
from app import app
from libraries.net_tools import get_primary_network_subnet


class AppTestCase(unittest.TestCase):
    app = app.test_client()

    def test_port_lifecycle(self):
        response = self.app.delete('/api/port/list/test_port_list')

        # Get the list of port lists
        response = self.app.get('/api/port/list')
        self.assertEqual(response.status_code, 200)
        port_list_start = json.loads(response.data)

        # Create a new port list
        new_port_list = {'80': 'http', '443': 'https'}
        response = self.app.post('/api/port/list/test_port_list', json=new_port_list)
        self.assertEqual(response.status_code, 200)


        # Get the list of port lists again
        response = self.app.get('/api/port/list')
        self.assertEqual(response.status_code, 200)
        port_list_new = json.loads(response.data)
        # Verify that the new port list is in the list of port lists
        self.assertEqual(len(port_list_new), len(port_list_start) + 1)

        # Get the new port list
        response = self.app.get('/api/port/list/test_port_list')
        self.assertEqual(response.status_code, 200)
        port_list = json.loads(response.data)
        self.assertEqual(port_list, new_port_list)

        # Update the new port list
        updated_port_list = {'22': 'ssh', '8080': 'http-alt'}
        response = self.app.put('/api/port/list/test_port_list', json=updated_port_list)
        self.assertEqual(response.status_code, 200)

        # Get the new port list again
        response = self.app.get('/api/port/list/test_port_list')
        self.assertEqual(response.status_code, 200)
        port_list = json.loads(response.data)

        # Verify that the new port list has been updated
        self.assertEqual(port_list, updated_port_list)

        # Delete the new port list
        response = self.app.delete('/api/port/list/test_port_list')
        self.assertEqual(response.status_code, 200)

    def test_scan(self):
        # Create a new port list
        new_port_list = {'80': 'http', '443': 'https'}
        response = self.app.post('/api/port/list/test_port_list', json=new_port_list)
        self.assertEqual(response.status_code, 200)

        # Create a new scan
        new_scan = {'subnet': get_primary_network_subnet(), 'port_list': 'test_port_list'}
        response = self.app.post('/api/scan/async', json=new_scan)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.data)['status'], 'complete')

        # Delete the new port list
        response = self.app.delete('/api/port/list/test_port_list')
        self.assertEqual(response.status_code, 200)
        





if __name__ == '__main__':
    unittest.main()