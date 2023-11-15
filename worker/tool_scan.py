import json
import os
import glob
import re
import socket
import ssl
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import xmltodict
import tempfile
from app_logger.app_log import logger
import pandas as pd
from worker import current_dir

# 根据环境配置
oneforall_dir = '/Users/leyouming/company_program/scan_tool/OneForAll'
masscan_dir = '/Users/leyouming/company_program/scan_tool/masscan/bin'
finger_dir = '/Users/leyouming/company_program/scan_tool/Finger'


def nmap_ping(host: str) -> list:
    """
    调用nmap，通过ping的方式探测主机是否存活
    :param host:
    :return:
    """
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        output_file = temp.name

    cmd = ['nmap', '-sP', '-oX', output_file, host]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)
        if result.returncode == 0:

            logger.debug(f'{host}检测成功')

            with open(output_file, 'r') as file:
                xml_data = file.read()
            result_json = xmltodict.parse(xml_data)
            os.remove(output_file)

            logger.debug(f'检测全部结果是:{result_json}')

            if 'host' not in result_json['nmaprun']:
                logger.debug(f'{host}没有存活IP')
                return []
            elif result_json['nmaprun']['host'] is None:
                logger.debug(f'{host}没有存活IP')
                return []
            elif isinstance(result_json['nmaprun']['host'], dict):
                logger.debug(f'{host}只有一个存活IP')
                ip_list = [result_json['nmaprun']['host']['address']['@addr']]
                logger.debug(f'存活IP:{ip_list}')
                return ip_list
            else:
                logger.debug(f'{host}有多个存活IP')
                ip_list = [h['address']['@addr'] for h in result_json['nmaprun']['host']]
                logger.debug(f'存活IP:{ip_list}')
                return ip_list

        else:
            logger.debug(f'{host}检测失败')
            logger.debug(f'报错:{result.stderr}')
            return []
    except Exception as e:
        logger.error(f'nmapIP扫描失败，错误:{e}')
        return []


def nmap_server(host: str, port: list) -> dict:
    """
    通过nmap扫描端口的服务
    :param host:
    :param port:
    :return:
    """

    # port为空的情况
    if len(port) == 0:
        return {}

    with tempfile.NamedTemporaryFile(delete=False) as temp:
        output_file = temp.name

    cmd = ['nmap', '-p', ','.join(port), '-oX', output_file, host]
    logger.debug(f'扫描命令:{cmd}')

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)
        if result.returncode == 0:

            with open(output_file, 'r') as file:
                xml_data = file.read()
            result_json = xmltodict.parse(xml_data)

            result_dict = {}

            # 只扫描一个port的情况
            if len(port) == 1:
                port = result_json['nmaprun']['host']['ports']['port']
                if 'service' in port:
                    result_dict[port['@portid']] = {
                        'protocol': port['@protocol'],
                        'service': port['service']['@name'],
                    }
                else:
                    result_dict[port['@portid']] = {
                        'protocol': port['@protocol'],
                        'service': '',
                    }


            # 多个port的情况
            else:
                for port in result_json['nmaprun']['host']['ports']['port']:
                    if 'service' in port:
                        result_dict[port['@portid']] = {
                            'protocol': port['@protocol'],
                            'service': port['service']['@name'],
                        }
                    else:
                        result_dict[port['@portid']] = {
                            'protocol': port['@protocol'],
                            'service': '',
                        }

            return result_dict

        else:
            logger.debug(f'{host}检测失败')
            logger.debug(f'报错:{result.stderr}')
            return {}
    except Exception as e:
        logger.error(f'nmapIP扫描失败，错误:{e}')
        return {}


def oneforall_scan(target: str) -> list:
    """
    调用oneforall进行子域名扫描
    :param target:
    :return:
    """
    oneforall_path = f'{oneforall_dir}/oneforall.py'
    oneforall_result_path = f'{oneforall_dir}/results/{get_oneforall_result_filename(target)}.csv'

    cmd = ['python', oneforall_path, '--target', target, '--brute', 'True', 'run']
    try:
        logger.debug(f'OneForAll开始检测')
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)
        logger.debug(result.stdout)
        logger.debug(f'OneForAll检测完毕')
        # 处理数据
        return get_oneforall_result(oneforall_result_path)

    except Exception as e:
        logger.error(f'OneForAll调用失败:{e}')
        return []


def get_oneforall_result_filename(s: str) -> str:
    parts = s.split('.')
    if len(parts) > 2:
        return '.'.join(parts[-2:])
    else:
        return s


def get_oneforall_result(result_path: str) -> list:
    df = pd.read_csv(result_path)
    subdomains = df['url'].unique()
    subdomain_list = subdomains.tolist()
    os.remove(result_path)
    return subdomain_list


def port_scan(ip: str) -> list:
    """
    调用masscan，进行端口扫描
    :param ip:
    :return:
    """

    masscan_path = f'{masscan_dir}/masscan'

    with tempfile.NamedTemporaryFile(delete=False) as temp:
        output_file = temp.name

    cmd = [masscan_path, '-p0-65535', '-oJ', output_file, ip, '--max-rate', '100']
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)
        if result.returncode == 0:

            logger.debug(f'{ip}检测成功')
            logger.debug(f'{result.stdout}')

            with open(output_file, 'r') as file:
                json_data = file.read()

            if json_data == '':
                logger.debug(f'{ip}没有端口')
                return []

            else:
                result_json = json.loads(json_data)
                os.remove(output_file)
                logger.debug(f'检测全部结果是:{result_json}')
                ports = []
                for ip in result_json:
                    ports.extend([str(port['port']) for port in ip['ports']])

            return ports

        else:
            logger.debug(f'{ip}检测失败')
            logger.debug(f'报错:{result.stderr}')
            return []
    except Exception as e:
        logger.error(f'masscan扫描失败，错误:{e}')
        return []


def web_info_scan(domains: list) -> list:
    tmp_txt_path = os.path.join(current_dir, 'tmp.txt')

    finger_path = f'{finger_dir}/Finger.py'
    json_dir = f'{finger_dir}/output'

    with open(tmp_txt_path, 'w') as file:
        file.write('\n'.join(domains))

    try:
        cmd = ['python', finger_path, '-f', tmp_txt_path, '-o', 'json']
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1200)
        if result.returncode == 0:
            logger.debug(f'web指纹检测成功')
            logger.debug(f'{result.stdout}')

            # 处理数据
            jsons = get_json_path(json_dir)
            json_path = jsons[0]

            with open(json_path, 'r') as f:
                json_data = json.load(f)

            # 删除多的json
            for j_path in jsons:
                os.remove(j_path)

            return json_data

        else:
            logger.debug(f'web指纹检测失败')
            logger.debug(f'报错:{result.stderr}')
    except Exception as e:
        logger.error(f'web指纹检测失败，错误:{e}')
        return []


def get_json_path(dir: str) -> list:
    return glob.glob(os.path.join(dir, '*.json'))


def get_certificate(host: str):
    """
    获取网站的https证书信息
    :param host:
    :return:
    """
    host = remove_http(host)
    context = ssl.create_default_context()
    conn = socket.create_connection((host, 443), timeout=3)
    sock = context.wrap_socket(conn, server_hostname=host)
    cert = sock.getpeercert()
    sock.close()
    return cert


def remove_http(url):
    if re.match(r'http[s]?://', url):
        return re.sub(r'http[s]?://', '', url)
    return url


def get_domains_certificate(subdomains: dict) -> dict:
    """
    获取子域名的证书信息
    :param subdomains:
    :return:
    """
    all_count = len(subdomains)
    complete_count = 0
    for subdomain in subdomains.keys():
        try:
            logger.debug(f'获取子域名"{subdomain}"的证书，进度{complete_count}/{all_count}')
            cert = get_certificate(subdomain)
            subdomains[subdomain]['cert'] = cert
        except Exception as e:
            logger.error(f'获取子域名"{subdomain}"的证书失败，错误:{e}')
        finally:
            complete_count += 1

    return subdomains
