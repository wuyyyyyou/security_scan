import traceback

from worker.tool_scan import *
from db.dao import *
from app_logger.app_log import logger

# 先暂时写死
host = '180.169.95.0/24'
domain = 'erp.chinaums.com'


def domain_process():
    try:

        # 1. oneforall扫描子域名
        subdomain_list = oneforall_scan(domain)
        domain_record_id = create_domain_record(domain, subdomain_list)

        # 2. web信息扫描
        web_infos = web_info_scan(subdomain_list)
        update_domain_record_by_web_info(domain_record_id, web_infos)

        # 3. 去掉不存活的域名
        subdomain_dict = delete_empty_domain(domain_record_id)

        # 4. 获取网页证书
        subdomain_dict = get_domains_certificate(subdomain_dict)
        update_domain_record_by_subdomains(domain_record_id, subdomain_dict)

    except Exception as e:
        logger.error(f'报错:{e}')
        traceback.print_exc()


def port_process():
    try:
        # 1. nmap扫描存活IP
        ip_list = nmap_ping(host)
        ip_record_id = create_ip_record(ip_list)

        ip_count = len(ip_list)
        complete_ip_count = 0
        for ip in ip_list:
            try:
                # 2. masscan扫描存活IP的端口，耗时巨大
                logger.debug(f'开始扫描{ip}端口，进度{complete_ip_count}/{ip_count}')
                ports = port_scan(ip)
                update_ip_record_by_port(ip_record_id, ip, ports)

                # 3. 对于扫描到的端口使用nmap进行服务扫描
                ports_info = nmap_server(ip, ports)
                update_ip_ports_info(ip_record_id, ip, ports_info)

            except Exception as e:
                logger.error(f'扫描报错:{e}')

            finally:
                complete_ip_count += 1

    except Exception as e:
        logger.error(f'报错:{e}')
        traceback.print_exc()


if __name__ == '__main__':
    # port_process()
    domain_process()
