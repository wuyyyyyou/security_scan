import pandas as pd
from db.dao import *
from worker.tool_scan import *
import json


def gen_domain_excel(uid: str, out_file_name: str):
    result = get_record_result('domain_record', uid)
    domains = result['subdomains']

    df = pd.DataFrame(columns=[
        'url', 'cms', 'title', 'status', 'Server', 'size', 'iscdn', 'ip', 'address', 'isp',
        'subject', 'issuer', 'version', 'serialNumber', 'notBefore', 'notAfter', 'subjectAltName', 'OCSP',
        'caIssuers', 'crlDistributionPoints'
    ])

    for key, value in domains.items():
        new_row = {}

        web_info = value.get('web_info', {})
        if web_info == {}:
            new_row['url'] = key
        else:
            new_row['url'] = web_info.get('url', '')
            new_row['cms'] = web_info.get('cms', '')
            new_row['title'] = web_info.get('title', '')
            new_row['status'] = web_info.get('status', '')
            new_row['Server'] = web_info.get('Server', '')
            new_row['size'] = web_info.get('size', '')
            new_row['iscdn'] = web_info.get('iscdn', '')
            new_row['ip'] = web_info.get('ip', '')
            new_row['address'] = web_info.get('address', '')
            new_row['isp'] = web_info.get('isp', '')

        cert = value.get('cert', {})
        if cert != {}:
            new_row['subject'] = cert.get('subject', '')
            new_row['issuer'] = cert.get('issuer', '')
            new_row['version'] = cert.get('version', '')
            new_row['serialNumber'] = cert.get('serialNumber', '')
            new_row['notBefore'] = cert.get('notBefore', '')
            new_row['notAfter'] = cert.get('notAfter', '')
            new_row['subjectAltName'] = cert.get('subjectAltName', '')
            new_row['OCSP'] = cert.get('OCSP', '')
            new_row['caIssuers'] = cert.get('caIssuers', '')
            new_row['crlDistributionPoints'] = cert.get('crlDistributionPoints', '')

        del_strigula(new_row)
        df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)

    df.to_excel(out_file_name, index=False, sheet_name='Sheet1')


def del_strigula(dic: dict):
    for key, value in dic.items():
        if value == '-':
            dic[key] = ''


def count_domain(uid: str):
    result = get_record_result('domain_record', uid)
    subdomains = result['subdomains']

    subdomain_set = set()
    for subdomain in subdomains.keys():
        subdomain = remove_http(subdomain)
        subdomain_set.add(subdomain)

    print(len(subdomain_set))
