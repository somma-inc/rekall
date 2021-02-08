#
# @author       JeongPil, Lee(jeongpil@somma.kr)
# @date         2021/01/05 10:00 created.
# @copyright    (C)Somma,Inc. All rights reserved.
#
import os
import unittest
import pywintypes
import win32security
import psutil
import hashlib
import csv
import datetime
import json
import time
import ntpath

import win32api
import win32con
import windows

from rekall.plugins.tools.exporter import Exporter
from rekall.plugins.windows import common
from rekall.plugins.windows.filescan import PoolScanProcess


def sha256sum(file_path: str, block_size=8192):
    """sha-1 해시함수 사용
    """
    if os.path.exists(file_path) is False:
        return ''
    hash_func = hashlib.sha256()
    with open(file_path, 'rb') as file_object:
        for block in iter(lambda: file_object.read(block_size), b""):
            hash_func.update(block)
    return hash_func.hexdigest()


def get_elevated_n_elevation_type(pid):
    try:
        proc_handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
            False,
            pid
        )
        proc_token = win32security.OpenProcessToken(proc_handle, win32con.MAXIMUM_ALLOWED)

        #
        # 프로세스 권한 상승 유무 정보 가져오기
        #
        is_elevated = win32security.GetTokenInformation(proc_token, win32security.TokenElevation)

        #
        #  프로세스 권한 상승 타입 가져오기
        #
        elevation_type = win32security.GetTokenInformation(proc_token, win32security.TokenElevationType)
        return is_elevated, elevation_type
    except Exception as ex:
        raise ex


class Process(object):
    """pslist api object 추출
    """
    def __init__(self,
                 ppid: int,
                 pid: int,
                 creation_timestamp: int,
                 exit_timestamp: int,
                 name: str,
                 image_path: str,  cwd: str, cmd: str, is_exists_in_ps_list: bool, is_exists_in_ps_api: bool):
        self.ppid = ppid
        self.parent_creation_timestamp = 0
        self.parent_exit_timestamp = 0
        self.parent_proc_name = ''
        self.parent_image_path = ''
        self.parent_cmdline = ''
        self.parent_elevated = False
        self.parent_elevation_type = win32security.TokenElevationTypeDefault

        self.pid = pid
        self.creation_timestamp = creation_timestamp
        self.exit_timestamp = exit_timestamp
        self.name = name
        self.image_path = image_path
        self.cwd = cwd
        self.cmd = cmd

        self.terminated_process = False

        self.elevation_type = win32security.TokenElevationTypeDefault
        self.elevated = False

        self.is_exists_in_ps_list = is_exists_in_ps_list
        self.is_exists_in_ps_api = is_exists_in_ps_api

        self.verify_result = windows.wintrust.VerifyResult.VrUnknown
        self.signers = []
        self.sha2 = ''

        # 프로세스의 부가적인 정보 수집 유무를 확인 하는 플래그 값이다.
        self.prepared = False

    def prepare(self, logging):
        if len(self.image_path) > 1 and os.path.isfile(self.image_path):
            self.sha2 = sha256sum(self.image_path)
            self.verify_result, self.signers = windows.wintrust.verify_file_ex(self.image_path)

        if self.exit_timestamp != 0:
            try:
                self.elevated, self.elevation_type = get_elevated_n_elevation_type(self.pid)
            except Exception as ex:
                logging.error(f'get_elevated_n_elevation_type() failed. pid={self.pid}, name={self.name}, ex={str(ex)}')
                self.elevated = False
                self.elevation_type = win32security.TokenElevationTypeDefault
        else:
            self.terminated_process = True
        self.prepared = True

    def set_parent_info(self,
                        creation_timestamp: int,
                        exit_timestamp: int, proc_name: str,
                        image_path: str, cmdline: str, elevated: bool, elevation_type: int):
        self.parent_creation_timestamp = creation_timestamp
        self.parent_exit_timestamp = exit_timestamp
        self.parent_proc_name = proc_name
        self.parent_image_path = image_path
        self.parent_cmdline = cmdline
        self.parent_elevated = elevated
        self.parent_elevation_type = elevation_type

    def to_dict(self) -> dict:
        return dict(
            ppid=self.ppid,
            parent_proc_name=self.parent_proc_name,
            parent_proc_image_path=self.parent_image_path,
            parent_proc_cmdline=self.parent_cmdline,
            parent_creation_timestamp=self.parent_creation_timestamp,
            parent_exit_timestamp=self.parent_creation_timestamp,
            parent_elevated=self.parent_elevated,
            parent_elevation_type=self.parent_elevation_type,
            pid=self.pid,
            proc_name=self.name,
            image_path=self.image_path,
            elevated=self.elevated,
            elevation_type=self.elevation_type,
            creation_timestamp=self.creation_timestamp,
            exit_timestamp=self.exit_timestamp,
            psscan_driver=True,
            is_exists_in_ps_api=self.is_exists_in_ps_api,
            is_exists_in_ps_list=self.is_exists_in_ps_list,
            sha2=self.sha2,
            verify_result=self.verify_result,
            signers='|'.join(self.signers)
        )


class ProcessTree:
    """pslist api object 추출
    """
    def __init__(self):
        self.proc_list = {}
        self._build_process_tree()

    def _build_process_tree(self):
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'ppid', 'cwd', 'exe', 'name', 'create_time', 'cmdline'])
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except Exception as e:
                continue
            else:
                if pinfo['name'] is None:
                    proc_name = ''
                else:
                    proc_name = pinfo['name']
                if pinfo['exe'] is None:
                    image_path = ''
                else:
                    image_path = pinfo['exe']
                if pinfo['cwd'] is None:
                    cwd = ''
                else:
                    cwd = pinfo['cwd']

                if pinfo['cmdline'] is None:
                    cmdline = ''
                else:
                    cmdline = ' '.join(pinfo['cmdline'])

                self._add_process(proc_name,
                                  pinfo['ppid'],
                                  pinfo['pid'],
                                  pinfo['create_time'],
                                  image_path,
                                  cwd,
                                  cmdline)

    def _add_process(self, name: str, ppid:int, pid: int, creation_time: float,  full_path: str, cwd: str, cmd: str):
        self.proc_list[pid] = {
            'name': name,
            'ppid': ppid,
            'ctime': creation_time,
            'image_path': full_path,
            'cwd': cwd,
            'cmdline': cmd,
        }


class PSMerge(common.WinScanner):
    """ 프로세스 아티팩트 통합 플러그인
    """
    name = "psmerge"

    table_header = [
        dict(name="offset_p", type="_EPROCESS"),
        dict(name="ppid", width=6, align="r"),
        dict(name="imagepath", width=75),
        dict(name="is_elevated", width=5),
        dict(name="elevation_type", width=27),
        dict(name="create_time", width=24),
        dict(name="exit_time", width=24),
        dict(name="psscan_driver", width=5),
        dict(name="pslist_driver", width=5),
        dict(name="pslist_api", width=5),
        dict(name="hash_sha256", width=32),
        dict(name="is_signed", width=5),
        dict(name="issuer", width=15)
    ]

    __args = [
        dict(name='output_path',
             default=os.path.join(
                 os.path.abspath(os.path.dirname(__file__)), f'psmerge_{datetime.datetime.utcnow().timestamp()}.tsv'))
    ]

    # Only bother to scan non paged pool by default.
    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True
    )

    proc_driver_list = dict()
    proc_api_list = dict()

    file_path_cache = {}

    @staticmethod
    def find_image_abs_path(proc_name_or_image_path: str):
        if len(proc_name_or_image_path) <= 1 or proc_name_or_image_path is None:
            return ''

        # 윈도우 시스템 디렉토리에서 찾아 본다.
        system_root = os.environ.get('systemroot', 'c:\\windows')

        abs_path = os.path.join(system_root, 'system32', os.path.basename(proc_name_or_image_path))
        if os.path.exists(abs_path) is True and os.path.isfile(abs_path):
            return abs_path

        #  윈도우 디렉토리에서 찾아본다.
        abs_path = os.path.join(system_root, os.path.basename(proc_name_or_image_path))
        if os.path.exists(abs_path) is True and os.path.isfile(abs_path):
            return abs_path

        #  PATH 환경 변수에 저장된 디렉토리 경로
        path_list = os.environ.get('path', '').split(';')
        for path in path_list:
            abs_path = os.path.join(path, os.path.basename(proc_name_or_image_path))
            if os.path.exists(abs_path) is True and os.path.isfile(abs_path):
                return abs_path
        return ''

    def collect(self):
        """Render results in a table."""
        # Try to do a regular process listing so we can compare if the process
        # is known.
        self.set_debug_privilege()

        # print(cache_data)
        pslist = self.session.plugins.pslist()
        for task in pslist.list_eprocess():
            # self.session.plugins.pslist().filter_processes() -> Eprocess 반환
            self.proc_driver_list[task.pid.value] = task

        # refac ps_list_driver = list(proc_driver_list.keys())

        self.proc_api_list = ProcessTree().proc_list

        # refac
        # ps_scan_result = set()
        # ps_scan_error = set()
        # json_data = {}

        proc_list = {}
        for run in self.generate_memory_ranges():
            # Just grab the AS and scan it using our scanner
            scanner = PoolScanProcess(session=self.session,
                                      profile=self.profile,
                                      address_space=run.address_space)

            for pool_object, eprocess in scanner.scan(offset=run.start, maxlen=run.length):
                pid = eprocess.pid.value

                # eprocess 구조체에 있는 프로세스명은 최대 16글자만 표현 되므로, psutil에서 가져온다.
                if pid in self.proc_api_list:
                    proc_name = self.proc_api_list[pid]['name']
                else:
                    proc_name = str(eprocess.name)

                if proc_name == 'cmd.exe':
                    temp = 0

                #
                # 종료 되지 않은 프로세스임에도 불구 하고,
                # eprocess.Peb.ProcessParameters.ImagePathName 값이 공백인 경우가 존재한다.
                #
                key = str(eprocess.Peb.ProcessParameters.ImagePathName)
                if len(key) <= 1:
                    key = proc_name

                if key in self.file_path_cache:
                    image_path = self.file_path_cache[key]
                else:
                    image_path = self.get_image_path(pid, key)
                    if len(image_path) > 1:
                        self.file_path_cache[key] = image_path

                proc = Process(
                    ppid=eprocess.InheritedFromUniqueProcessId,
                    pid=pid,
                    creation_timestamp=eprocess.CreateTime.as_windows_timestamp(),
                    exit_timestamp=eprocess.ExitTime.as_windows_timestamp(),
                    name=proc_name,
                    image_path=image_path,
                    cwd='',
                    cmd=eprocess.Peb.ProcessParameters.CommandLine,
                    is_exists_in_ps_list=eprocess.pid.value in self.proc_driver_list,
                    is_exists_in_ps_api=eprocess.pid.value in self.proc_api_list
                )
                proc.prepare(self.session.logging)

                assert proc.prepared is True
                proc_list[proc.pid] = proc

                if run.data["type"] == "PhysicalAS":
                    # Switch address space from physical to virtual.
                    virtual_eprocess = (
                        pslist.virtual_process_from_physical_offset(eprocess))
                else:
                    virtual_eprocess = eprocess

                yield dict(
                    offset_p=virtual_eprocess,
                    ppid=eprocess.InheritedFromUniqueProcessId,
                    imagepath=proc.image_path,
                    is_elevated=proc.elevated,
                    elevation_type=proc.elevation_type,
                    create_time=eprocess.CreateTime or '',
                    exit_time=eprocess.ExitTime or '',
                    psscan_driver=True,
                    pslist_api=proc.is_exists_in_ps_api,
                    pslist_driver=proc.is_exists_in_ps_list,
                    hash_sha256=proc.sha2,
                    is_signed=proc.verify_result,
                    issuer=','.join(proc.signers)
                )

        exporter = Exporter(self.plugin_args.output_path)
        for pid, proc in proc_list.items():
            if proc.ppid in proc_list:
                pproc = proc_list[proc.ppid]
                proc.set_parent_info(
                    creation_timestamp=pproc.creation_timestamp,
                    exit_timestamp=pproc.exit_timestamp,
                    proc_name=pproc.name,
                    image_path=pproc.image_path,
                    cmdline=pproc.cmd,
                    elevated=pproc.elevated,
                    elevation_type=pproc.elevation_type
                )
            exporter.export_to_tsv(proc.to_dict().values())
        del exporter

    def get_image_path(self, pid: int, proc_name_or_image_path: str):
        """ 프로세스 이미지 경로 반환, QueryFullProcessImageNameW, PEB
        """
        # 1. 드라이버를 통해 수집한 프로세스 목록과 API를 사용한 프로세스 목록에서 찾을 수 없는 경우
        #    다음과 같은 순서로 이미지 절대 경로를 찾아 본다.
        #    1. 윈도우 시스템 디렉토리
        #    2. 윈도우 디렉토리
        #    3. PATH 환경 변수에 저장된 디렉토리 경로
        if pid not in self.proc_driver_list and pid not in self.proc_api_list:
            # 이미지 경로가 "-"인 경우를 체크 한다.
            if len(proc_name_or_image_path) <= 1:
                return ''
            return self.find_image_abs_path(proc_name_or_image_path)

        # 2. API를 사용한 프로세스 목록에서 찾을 수 있는 경우
        abs_path = ''
        if pid in self.proc_api_list:
            abs_path = self.proc_api_list[pid]['image_path']

        # 3. 드라이버 목록인 경우
        if pid in self.proc_driver_list:
            abs_path = str(self.proc_driver_list[pid].Peb.ProcessParameters.ImagePathName)

        if len(abs_path) <= 1:
            return self.find_image_abs_path(proc_name_or_image_path)

        return abs_path

    @staticmethod
    def set_debug_privilege():
        """ 프로세스의 상세 정보를 조회 하기 위해서는 "seDebugPrivilege" 권한이 필요하다.
            그러므로, 현재 프로세스의 권한을 조정한다.
        """
        try:
            proc_token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )
            privilege_id = win32security.LookupPrivilegeValue(None, "seDebugPrivilege")
            win32security.AdjustTokenPrivileges(
                proc_token,
                0,
                [
                    (privilege_id, win32security.SE_PRIVILEGE_ENABLED)
                ]
            )
        except Exception as ex:
            raise ex
