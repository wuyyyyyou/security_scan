import json
import os
import subprocess

import xmltodict
import tempfile
from app_logger.app_log import logger
import pandas as pd


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


def oneforall_scan(target: str) -> list:
    """
    调用oneforall进行子域名扫描
    :param target:
    :return:
    """
    oneforall_dir = '/Users/leyouming/company_program/scan_tool/OneForAll'
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
    subdomains = df['subdomain'].unique()
    subdomain_list = subdomains.tolist()
    return subdomain_list


def port_scan(ip: str):
    """
    调用masscan，进行端口扫描
    :param ip:
    :return:
    """
    masscan_dir = '/Users/leyouming/company_program/scan_tool/masscan/bin'
    masscan_path = f'{masscan_dir}/masscan'

    with tempfile.NamedTemporaryFile(delete=False) as temp:
        output_file = temp.name

    cmd = [masscan_path, '-p0-65535', '-oJ', output_file, ip, '--max-rate', '500']
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
