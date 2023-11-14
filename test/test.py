import unittest
from worker.tool_scan import *
from db.dao import *


class MyTestCase(unittest.TestCase):
    def test_nmap_ping(self):
        host = '180.169.95.0/24'
        result = nmap_ping(host)
        print(result)

    def test_create_ip_record(self):
        result_id = create_ip_record(
            ['180.169.95.99', '180.169.95.100', '180.169.95.104', '180.169.95.106', '180.169.95.107', '180.169.95.108',
             '180.169.95.129', '180.169.95.130', '180.169.95.133', '180.169.95.135', '180.169.95.137', '180.169.95.190',
             '180.169.95.250'])
        print(result_id)

    def test_find_ip_record(self):
        result = find_ip_record('469dd780-5516-4b0a-b1a6-9013f61ec57f')
        print(result)

    def test_one_for_all(self):
        target = 'erp.chinaums.com'
        oneforall_scan(target)


if __name__ == '__main__':
    unittest.main()
