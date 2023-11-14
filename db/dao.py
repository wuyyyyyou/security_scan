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


