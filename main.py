from worker.tool_scan import *
from db.dao import *
from app_logger.app_log import logger


def process():
    # 先暂时写死
    host = '180.169.95.0/24'
    domain = 'erp.chinaums.com'

    try:
        # 1. nmap扫描存活IP
        ip_list = nmap_ping(host)
        ip_record_id = create_ip_record(ip_list)
        # 2. masscan扫描存活IP的端口，耗时巨大暂时不开
        for ip in ip_list:
            ports = port_scan(ip)
            update_ip_record_by_port(ip_record_id, ip, ports)

        # 3. oneforall扫描子域名
        subdomain_list = oneforall_scan(domain)
        domain_record_id = create_domain_record(domain, subdomain_list)

        # 4. web信息扫描
        web_infos = web_info_scan(subdomain_list)
        update_domain_record_by_web_info(domain_record_id, web_infos)

        # 去掉不存活的域名
        subdomain_dict = delete_empty_domain(domain_record_id)

        # 6. 获取网页证书
        subdomain_dict = get_domains_certificate(subdomain_dict)
        update_domain_record_by_subdomains(domain_record_id, subdomain_dict)


    except Exception as e:
        logger.error(f'报错:{e}')


if __name__ == '__main__':
    process()
