import time
import uuid
from db.settings import db


def create_ip_record(ips_list: list) -> str:
    ips_list.sort()
    ips_dict = {key: {} for key in ips_list}

    collection = db['ip_record']
    random_uuid = str(uuid.uuid4())
    document = {
        '_id': random_uuid,
        "time": int(time.time()),
        "ips": ips_dict
    }

    insert_result = collection.insert_one(document)
    return insert_result.inserted_id


def find_ip_record(uid: str) -> dict:
    collection = db['ip_record']
    result = collection.find_one({"_id": uid})
    return result


def create_domain_record(domain: str, domain_list: list) -> str:
    domain_list.sort()
    domain_list_dict = {key: {} for key in domain_list}

    collection = db['domain_record']
    random_uuid = str(uuid.uuid4())
    document = {
        '_id': random_uuid,
        'domain': domain,
        "time": int(time.time()),
        "subdomains": domain_list_dict
    }

    insert_result = collection.insert_one(document)
    return insert_result.inserted_id


def update_ip_record_by_port(uid: str, ip: str, ports: list) -> int:
    result = get_record_result('ip_record', uid)
    ports.sort()
    port_list_dict = {key: {} for key in ports}

    result['ips'][ip] = {'ports': port_list_dict}
    update_count = update_record('ip_record', uid, result)
    return update_count


def update_domain_record_by_web_info(uid: str, web_infos: list) -> int:
    result = get_record_result('domain_record', uid)
    for web_info in web_infos:
        result['subdomains'][web_info['url']] = {'web_info': web_info}
    update_count = update_record('domain_record', uid, result)
    return update_count


def update_domain_record_by_subdomains(uid: str, subdomains: dict) -> int:
    result = get_record_result('domain_record', uid)
    result['subdomains'] = subdomains
    update_count = update_record('domain_record', uid, result)
    return update_count


def delete_empty_domain(uid: str) -> dict:
    result = get_record_result('domain_record', uid)
    subdomains = result['subdomains']
    new_subdomains = {}
    for subdomain, web_info in subdomains.items():
        if web_info != {}:
            new_subdomains[subdomain] = web_info
    result['subdomains'] = new_subdomains
    update_count = update_record('domain_record', uid, result)
    return new_subdomains


def get_record_result(col_name: str, uid: str) -> dict:
    collection = db[col_name]
    return collection.find_one({"_id": uid})


def update_record(col_name: str, uid: str, result: dict) -> int:
    collection = db[col_name]
    return collection.update_one({'_id': uid}, {'$set': result}).modified_count
