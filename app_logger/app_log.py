import os
import sys
from loguru import logger
# from app_log import current_dir

logger_level = "DEBUG"
# path_debug_log = os.path.join(current_dir, '..', 'logs', 'debug.log')

# 设置控制台日志输出等级
logger.remove()
logger.add(sys.stderr, level=logger_level)
# 日志输出文件
# logger.add(path_debug_log, rotation="90 MB", enqueue=True, serialize=False, encoding="utf-8", retention="10 days")
