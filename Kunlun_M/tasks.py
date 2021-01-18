from celery import shared_task
from django.conf import settings
from tempfile import NamedTemporaryFile
import shutil
import os
import uuid
from utils.log import logger
from utils import utils
from minio.error import S3Error
from web.index.models import ScanTask
from core import cli
from core.engine import Running
import random
import string
from core import rule
from core import pretreatment


is_load_plugin = False


@shared_task(name='kunlun_M_code_audit')
def kunlun_M_code_audit(source_oss_path: str):
    """kunlun_M 代码审计
    
    Args:
      - source_oss_path: 源代码路径
    """
    global is_load_plugin
    # 插件未加载先加载插件
    if not is_load_plugin:
        rule.RuleCheck().load()
        rule.TamperCheck().load()
        is_load_plugin = True
    
    # 重置全局ast_object
    setattr(pretreatment, 'ast_object', pretreatment.Pretreatment())
    os.chdir(settings.PROJECT_DIRECTORY)

    # target_path = get_source_localpath(source_oss_path)
    target_path = source_oss_path
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
    cli.start(target_path, 'json', temp_jsonfilepath, None, s.id)
    with open(temp_jsonfilepath, 'a+') as ft:
        res = ft.read()
    s.is_finished = True
    s.save()

    # 获取结果
    return res
    

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
