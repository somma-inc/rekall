import os
import unittest
import pywintypes
import win32security
import psutil
import hashlib

import win32api,win32con
import pandas as pd

from rekall.plugins.windows import common
from rekall.plugins.windows.filescan import PoolScanProcess


class TestGetTokenInformation(unittest.TestCase):

    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def seDebug(self):
        try:
            """SEDebug"""
            flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
            id = win32security.LookupPrivilegeValue(None, "seDebugPrivilege")
            newPrivileges = [(id, win32security.SE_PRIVILEGE_ENABLED)]
            win32security.AdjustTokenPrivileges(htoken, 0, newPrivileges)
        except Exception as e:
            print ('seDebug error')
            pass 


    def test_get_elevated(self):

        self.seDebug()
        

        process_list=ProcessTree().process_map()

        for pid in process_list:
            try:
                # print(process_list[i].name)
                ph = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
                th = win32security.OpenProcessToken(ph, win32con.MAXIMUM_ALLOWED)

                is_elevated=win32security.GetTokenInformation(th, win32security.TokenElevation)                        
                elevation_type = win32security.GetTokenInformation(th, win32security.TokenElevationType)
                
                print(f"{process_list[pid].name}({pid})\t{is_elevated}\t{elevation_type}")

            except Exception as e:
                pass

        # pass

class GetTokenInformation:
    def __init__(self):
        self.is_elevated={}
        self.elevation_type={}
    
    def token_map(self,pid):
        self.get_elevated(pid)
        return self.is_elevated, self.elevation_type

    def seDebug(self):
        try:
            """SEDebug"""
            flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
            id = win32security.LookupPrivilegeValue(None, "seDebugPrivilege")
            newPrivileges = [(id, win32security.SE_PRIVILEGE_ENABLED)]
            win32security.AdjustTokenPrivileges(htoken, 0, newPrivileges)
        except Exception as e:
            print ('seDebug error')
            pass 

    def get_elevated(self,pid):
        self.seDebug()
        # process_list=ProcessTree().process_map()

        # for pid in psscan_pid:
        try:
            # print(process_list[i].name)
            ph = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
            th = win32security.OpenProcessToken(ph, win32con.MAXIMUM_ALLOWED)

            is_elevated=win32security.GetTokenInformation(th, win32security.TokenElevation)         
            if int(is_elevated) == 0:
                self.is_elevated[pid]=[0,"False"]
            else:
                self.is_elevated[pid]=[int(is_elevated),"True"]


            elevation_type = win32security.GetTokenInformation(th, win32security.TokenElevationType)
            if int(elevation_type) == 1:
                self.elevation_type[pid] = [1,"TokenElevationTypeDefault"]
            elif int(elevation_type) == 2:
                self.elevation_type[pid] = [2,"TokenElevationTypeFull"]
            elif int(elevation_type) == 3:
                self.elevation_type[pid] = [3,"TokenElevationTypeLimited"]
            else:
                self.elevation_type[pid] = [int(elevation_type),"Unknown"]

            # print(f"{process_list[pid].name}({pid})\t{is_elevated}\t{elevation_type}")

        except Exception as e:
            pass

    

class Process(object):
    def __init__(self, name:str, ppid:int, pid:int, creation_time:float, full_path:str,  cwd:str, cmd:str):
        self.name = name
        self.ppid = ppid
        self.pid = pid
        self.creation_time = creation_time
        self.full_path = full_path
        self.cwd = cwd
        self.cmd = cmd


class ProcessTree:
    def __init__(self):
        self._proc_map = {}
        self._build_process_tree()

    def iterate_process(self):
        procs = []
        current_pid = os.getpid()
        for pid in self._proc_map.keys():
            p = self._proc_map[pid]
            if p.pid == current_pid:
                continue
            if self._get_parent(p) is None:
                procs.append(p)
        return procs

    def process_map(self):
        return self._proc_map

    def _build_process_tree(self):
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'ppid', 'cwd', 'exe', 'name', 'create_time', 'cmdline'])
                # print(pinfo)
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
            except Exception as e:
                # print(pinfo)
                # print(e)
                pass
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
                # todo
                # 부모 권한 상승 정보 등을 여기서 추가 하면 어떨까?
                self._add_process(proc_name,
                                  pinfo['ppid'],
                                  pinfo['pid'],
                                  pinfo['create_time'],
                                  image_path,
                                  cwd,
                                  cmdline)
                

    def _add_process(self, name:str, ppid:int, pid:int, creation_time: float,  full_path:str, cwd:str, cmd:str):
        p = Process(name, ppid, pid, creation_time, full_path, cwd, cmd)
        self._proc_map[pid] = p

    def _get_parent(self, process: Process):
        if process.ppid in self._proc_map:
            p = self._proc_map[process.ppid]
            if p.creation_time <= process.creation_time:
                return p
            return None


def md5sum(file_path: str, blocksize=8192):
    if os.path.exists(file_path) is False:
        return ""
    hash_func = hashlib.md5()
    with open(file_path, 'rb') as file_object:
        for block in iter(lambda: file_object.read(blocksize), b""):
            hash_func.update(block)
    return hash_func.hexdigest()


class PSMerge(common.WinScanner):
    name = "psmerge"

    table_header = [
        # dict(name='a', width=1),
        # dict(name='a', width=1),
        dict(name="offset_p", type="_EPROCESS"),
        # dict(name="offset_v", style="address"),
        dict(name="ppid", width=6, align="r"),
        # dict(name="pdb", style="address"),
        # dict(name='stat', width=4),
        dict(name="imagepath", width=75),
        dict(name="create_time", width=24),
        dict(name="exit_time", width=24),
    ]

    # Only bother to scan non paged pool by default.
    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True
    )
    
    def collect(self):
        """Render results in a table."""
        # Try to do a regular process listing so we can compare if the process
        # is known.
        pslist = self.session.plugins.pslist()
        pslist_data = {}
        # pslist_gen = self.session.plugins.pslist().filter_processes()
        for i in pslist.list_eprocess():
            pslist_data[i.pid.value]=i
        
        api_ps_list = ProcessTree()
        # print("[+]",pslist.list_eprocess())
        # These are virtual addresses.
        known_eprocess = set()
        known_pids = set()
        for task in pslist.list_eprocess():
            known_eprocess.add(task)
            known_pids.add(task.UniqueProcessId)
            # print("[+]", task.Peb.ProcessParameters.ImagePathName)

        # Scan each requested run in turn.
        psscan_result = []
        for run in self.generate_memory_ranges():
            # Just grab the AS and scan it using our scanner
            scanner = PoolScanProcess(session=self.session,
                                      profile=self.profile,
                                      address_space=run.address_space)

            for pool_obj, eprocess in scanner.scan(offset=run.start, maxlen=run.length):
                if run.data["type"] == "PhysicalAS":
                    # Switch address space from physical to virtual.
                    virtual_eprocess = (
                        pslist.virtual_process_from_physical_offset(eprocess))
                else:
                    virtual_eprocess = eprocess

                known = ""
                if virtual_eprocess in known_eprocess:
                    known += "E"

                if eprocess.UniqueProcessId in known_pids:
                    known += "P"


                # print(pslist.filter_processes(pids=eprocess.pid))
                try:
                    data = dict(
                        # a='F' if pool_obj.FreePool else "",
                        offset_p=eprocess,
                        # offset_v=virtual_eprocess.obj_offset,
                        ppid=eprocess.InheritedFromUniqueProcessId,
                        # imagepath=eprocess.Peb.ProcessParameters.ImagePathName,
                        imagepath=pslist_data[eprocess.pid.value].Peb.ProcessParameters.ImagePathName,
                        # pdb=eprocess.Pcb.DirectoryTableBase,
                        create_time=eprocess.CreateTime or '',
                        exit_time=eprocess.ExitTime or ''
                )
                except KeyError:
                    pass
                
                # print("[+]", eprocess.Peb.ProcessParameters.ImagePathName)
                # psscan_result.append(
                #     data
                # )

                yield data
        print(psscan_result)
        # pslist plugin 결과, api를 통해서 얻은 프로세스 목록 결과, psscan 결과




test1,test2=GetTokenInformation().token_map(1552)

print(test1,test2)

