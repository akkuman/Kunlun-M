from celery import shared_task
from django.conf import settings
from tempfile import NamedTemporaryFile
import shutil
import os
import uuid
import logging
from utils.log import logger
from utils import utils
from utils.file import get_line
from minio.error import S3Error
from web.index.models import ScanTask
from core import cli
from core.engine import Running
import random
import string
import json


logger.setLevel(logging.INFO)


@shared_task(name='kunlun_M.code_audit')
def kunlun_M_code_audit(source_oss_path: str):
    """kunlun_M 代码审计
    
    Args:
      - source_oss_path: 源代码路径
    """
    target_path = get_source_localpath(source_oss_path)
    if len(os.listdir(target_path)) <= 0:
        return '{"error": "This archive appears to be unsafe or has no files. Please repackage!"}'
    res = ''

    # 开启扫描任务
    task_name = utils.get_mainstr_from_filename(target_path)
    s = ScanTask(task_name=task_name, target_path=target_path, parameter_config=[])
    s.save()

    data = {
        'status': 'running',
        'report': ''
    }
    Running(s.id).status(data)

    temp_jsonfilepath = os.path.join(settings.SOURCE_TMP_ROOTPATH, f"kunlun_res{''.join(random.sample(string.ascii_letters + string.digits, 8))}.json")
    cli.start(target_path, 'json', temp_jsonfilepath, None, s.id, is_unconfirm=True)
    if os.path.exists(temp_jsonfilepath):
        with open(temp_jsonfilepath, 'r') as ft:
            res = finalize_result(ft.read())
    s.is_finished = True
    s.save()

    # 获取结果
    return res


def finalize_result(result):
    """把得到的结果最后规整统一化
    {
        "s1289eq9t685": {
            "extension": 96,
            "file": 640,
            "framework": "Unknown Framework",
            "language": "html,javascript,php",
            "push_rules": 32,
            "target_directory": "/tmp/sources_e354ea0b-5590-4a1e-a60e-39b69cc56a32/",
            "trigger_rules": 11,
            "target": "/tmp/sources_e354ea0b-5590-4a1e-a60e-39b69cc56a32",
            "vulnerabilities": [
                {
                "analysis": "Unconfirmed Function-param-controllable",
                "chain": "",
                "code_content": "echo ($output);",
                "commit_author": "LoRexxar",
                "file_path": "/tmp/sources_e354ea0b-5590-4a1e-a60e-39b69cc56a32/catfish/library/think/Debug.php",
                "id": 10002,
                "language": "php",
                "line_number": "181",
                "rule_name": "Reflected XSS"
                }
            ]
        }
    }
    """
    if not result:
        return ''
    data = {}
    res = {'data': {}, 'vuls': []}
    if isinstance(result, str):
        data = json.loads(result)
    elif isinstance(result, dict):
        data = result
    else:
        return ''
    for _, proj_info in data.items():
        target_directory = proj_info.get('target_directory')
        # 项目概要信息
        for proj_k in proj_info:
            if proj_k in ('extension', 'file', 'framework', 'language', 'push_rules', 'trigger_rules'):
                res['data'][proj_k] = proj_info.get(proj_k)
        for vul in proj_info.get('vulnerabilities', []):
            # 漏洞信息
            vul_res = {'data': {}}
            for vul_k, vul_info in vul.items():
                if vul_k in ('analysis', 'chain', 'language'):
                    vul_res['data'][vul_k] = vul_info
                elif vul_k == 'file_path':
                    vul_res['file_path'] = vul_info.strip(target_directory)
                elif vul_k in ('code_content', 'line_number', 'rule_name'):
                    vul_res[vul_k] = vul_info
            vul_res['code_context'] = get_code_context(vul.get('file_path'), vul.get('line_number'))
            res['vuls'].append(vul_res)
    
    return json.dumps(res)


def get_code_context(filename, line_number, show_line=3):
    """获取代码文件指定行数的上下文"""
    if not (filename and os.path.exists(filename)):
        return []
    line_start = int(line_number) - show_line
    line_start = line_start if line_start else 1
    line_end = int(line_number) + show_line

    lines = get_line(filename, "{},{}".format(line_start, line_end))
    lines = [l.strip() for l in lines]

    return lines


def get_source_localpath(source_oss_path: str) -> str:
    """从oss中获取源码压缩包，解压到本地后返回解压路径"""
    try:
        client = settings.MINIO_CLIENT
        object_suffix = os.path.splitext(source_oss_path)[-1]
        bucket_name, object_name = source_oss_path.split('/', 1)
        with NamedTemporaryFile(prefix=bucket_name, dir='/tmp', suffix=object_suffix) as f:
            client.fget_object(bucket_name, object_name, f.name)
            source_path = os.path.join(settings.SOURCE_TMP_ROOTPATH, f'sources_{str(uuid.uuid4())}')
            if not os.path.exists(source_path):
                os.makedirs(source_path, 0o755)
            shutil.unpack_archive(f.name, source_path)
            return source_path
    except S3Error as e:
        logger.error("minio occur error: %s", e)
