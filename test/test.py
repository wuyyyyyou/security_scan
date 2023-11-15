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

    def test1(self):
        s = get_oneforall_result_filename('erp.chinaums.com')
        print(s)

    def test2(self):
        file_name = f'{get_oneforall_result_filename("erp.chinaums.com")}.csv'
        l = get_oneforall_result(f'/Users/leyouming/company_program/scan_tool/OneForAll/results/{file_name}')
        create_domain_record('erp.chinaums.com', l)

    def test3(self):
        ports = port_scan('180.169.95.99')
        print(ports)

    def test4(self):
        update_ip_record_by_port(
            '469dd780-5516-4b0a-b1a6-9013f61ec57f',
            '180.169.95.99',
            ['80', '443', '8888']
        )

    def test5(self):
        a = web_info_scan([
            'http://ad.chinaums.com',
            'https://ad.chinaums.com',
            'https://adm.ielc.chinaums.com',
            'http://adm.ielc.chinaums.com',
            'https://ads.chinaums.com',
            'http://ads.chinaums.com'
             ])
        print(a)

    def test6(self):
        a = get_json_path('/Users/leyouming/company_program/scan_tool/Finger/output')
        for f in a:
            os.remove(f)

    def test7(self):
        a = get_certificate('www.baidu.com')
        print(a)

    def test8(self):
        urls = ["http://example.com", "https://example.com", "ftp://example.com", "example.com"]
        for url in urls:
            print(remove_http(url))

    def test9(self):
        subdomain_dict = delete_empty_domain('1916d244-1dcc-4fc1-a3b4-588c7dfd719d')
        subdomain_dict = get_domains_certificate(subdomain_dict)
        update_domain_record_by_subdomains('1916d244-1dcc-4fc1-a3b4-588c7dfd719d', subdomain_dict)

    def test10(self):
        a = nmap_server('180.169.95.99', '80,443,8888,25025,49154'.split(','))
        print(a)


if __name__ == '__main__':
    unittest.main()
