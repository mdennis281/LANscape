import unittest
import json
from ..app import app
from ..libraries.net_tools import get_network_subnet
from ..libraries.subnet_scan import cleanup_old_jobs
from ._helpers import right_size_subnet



class ApiTestCase(unittest.TestCase):
    app = app.test_client()

    def test_port_lifecycle(self):
        # Delete the new port list if it exists
        self.app.delete('/api/port/list/test_port_list_lifecycle')

        # Get the list of port lists
        response = self.app.get('/api/port/list')
        self.assertEqual(response.status_code, 200)
        port_list_start = json.loads(response.data)

        # Create a new port list
        new_port_list = {'80': 'http', '443': 'https'}
        response = self.app.post('/api/port/list/test_port_list_lifecycle', json=new_port_list)
        self.assertEqual(response.status_code, 200)


        # Get the list of port lists again
        response = self.app.get('/api/port/list')
        self.assertEqual(response.status_code, 200)
        port_list_new = json.loads(response.data)
        # Verify that the new port list is in the list of port lists
        self.assertEqual(len(port_list_new), len(port_list_start) + 1)

        # Get the new port list
        response = self.app.get('/api/port/list/test_port_list_lifecycle')
        self.assertEqual(response.status_code, 200)
        port_list = json.loads(response.data)
        self.assertEqual(port_list, new_port_list)

        # Update the new port list
        updated_port_list = {'22': 'ssh', '8080': 'http-alt'}
        response = self.app.put('/api/port/list/test_port_list_lifecycle', json=updated_port_list)
        self.assertEqual(response.status_code, 200)

        # Get the new port list again
        response = self.app.get('/api/port/list/test_port_list_lifecycle')
        self.assertEqual(response.status_code, 200)
        port_list = json.loads(response.data)

        # Verify that the new port list has been updated
        self.assertEqual(port_list, updated_port_list)

        # Delete the new port list
        response = self.app.delete('/api/port/list/test_port_list_lifecycle')
        self.assertEqual(response.status_code, 200)

    def test_scan(self):
        # Delete the new port list if it exists
        self.app.delete('/api/port/list/test_port_list_scan')

        # Create a new port list
        new_port_list = {'80': 'http', '443': 'https'}
        response = self.app.post('/api/port/list/test_port_list_scan', json=new_port_list)
        self.assertEqual(response.status_code, 200)

        # Create a new scan, wait for completion
        new_scan = {'subnet': right_size_subnet(get_network_subnet()), 'port_list': 'test_port_list_scan'}
        response = self.app.post('/api/scan/async', json=new_scan)
        self.assertEqual(response.status_code, 200)
        scan_info = json.loads(response.data)
        self.assertEqual(scan_info['status'], 'complete')
        scanid = scan_info['scan_id']
        self.assertIsNotNone(scanid)

        # Validate the scan worked without error
        response = self.app.get(f"/api/scan/{scanid}")
        self.assertEqual(response.status_code, 200)
        scan_data = json.loads(response.data)
        self.assertEqual(scan_data['errors'], [])
        self.assertEqual(scan_data['stage'],'complete')

        # Render UI
        uris = [
            f'/?scan_id={scanid}',
            f'/scan/{scanid}/overview',
            f'/scan/{scanid}/table'
        ]
        for uri in uris:
            response = self.app.get(uri)
            self.assertEqual(response.status_code,200)


        # Delete the new port list
        response = self.app.delete('/api/port/list/test_port_list_scan')
        self.assertEqual(response.status_code, 200)

        cleanup_old_jobs()
    
    def test_subnet_ports(self):
        """
        Test to ensure multi-subnet dectection is working
        """

        response = self.app.get('/api/tools/subnet/list')
        self.assertEqual(response.status_code, 200)

        subnets = json.loads(response.data)
        self.assertIsNot(len(subnets), 0)
        self.assertIsInstance(subnets[0],dict)
        subnet:dict = subnets[0]
        self.assertIsNotNone(subnet.get('address_cnt'))

    def test_subnet_validation(self):
        """
        test subnet validation and parsing is working as expected
        """
        subnet_tests = {
            # subnet : count (-1 == invalid)
            '10.0.0.0/24': 254,
            '10.0.0.2/24': 254,
            '10.0.0.1-100': 100,
            '192.168.1.1/25': 126,
            '10.0.0.1/24, 192.168.1.1-100': 354,
            '10.0.0.1/20': 4094,
            '10.0.0.1/19': 8190,
            '': -1, # blank
            '10.0.1/24': -1, # invalid
            '10.0.0.1/2': -1, # too big
            '10.0.0.1/19, 192.168.1.1/20': -1 # too big
        }

        for subnet, count in subnet_tests.items():
            uri = f'/api/tools/subnet/test?subnet={subnet}'
            response = self.app.get(uri)
            self.assertEqual(response.status_code, 200)

            data:dict = json.loads(response.data)
            self.assertEqual(data.get('count'),count)
            self.assertIsNotNone(data.get('msg'))
            if count == -1:
                self.assertFalse(data.get('valid'))
            




        
if __name__ == '__main__':
    unittest.main()