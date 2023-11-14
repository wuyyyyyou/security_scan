from pymongo import MongoClient

client = MongoClient('mongodb://root:root@127.0.0.1:27017/?authSource=admin')
db = client['scan_result']