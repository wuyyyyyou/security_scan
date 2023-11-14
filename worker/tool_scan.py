import json
import os
import subprocess
from collections import OrderedDict
from typing import Any

import xmltodict
import tempfile
from app_logger.app_log import logger


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
