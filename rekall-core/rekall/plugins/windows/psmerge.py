import os
import unittest
import pywintypes
import win32security
import psutil
import hashlib
import csv

import win32api,win32con

from rekall.plugins.windows import common
from rekall.plugins.windows.filescan import PoolScanProcess
# from rekall.plugins.response import processes



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

        try:
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

            # (f"{process_list[pid].name}({pid})\t{is_elevated}\t{elevation_type}")
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
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
            except Exception as e:
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
        dict(name="offset_p", type="_EPROCESS"),
        dict(name="ppid", width=6, align="r"),
        dict(name="imagepath", width=75),
        dict(name="is_elevated", width=5),
        dict(name="elevation_type", width=27),
        dict(name="create_time", width=24),
        dict(name="exit_time", width=24),
        dict(name="psscan_driver", width=5),
        dict(name="pslist_driver", width=5),
        dict(name="pslist_api", width=5)
    ]

    # Only bother to scan non paged pool by default.
    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True
    )
    
    def data_set(self, offset:str, ppid:int, is_elevated:str, elevation_type: str, imagepath:str,
                    create_time:str, exit_time:str, psscan_d:str, pslist_a:str, pslist_d:str):
        """render dict 생성"""
        data = dict(
                    offset_p=offset,
                    ppid=ppid,
                    is_elevated=is_elevated,
                    elevation_type=elevation_type,
                    imagepath=imagepath,
                    create_time=create_time,
                    exit_time=exit_time,
                    psscan_driver=psscan_d,
                    pslist_api=pslist_a,
                    pslist_driver=pslist_d
                )
        return data
    
    def collect(self):
        """Render results in a table."""
        # Try to do a regular process listing so we can compare if the process
        # is known.
        pslist = self.session.plugins.pslist()
        pslist_data = {}

        # self.session.plugins.pslist().filter_processes() -> Eprocess 반환 
        for task in pslist.list_eprocess():
            pslist_data[task.pid.value]=task
        pslist_driver=list(pslist_data.keys())
        api_ps_list = ProcessTree()

        # These are virtual addresses.
        known_eprocess = set()
        known_pids = set()
        for task in pslist.list_eprocess():
            known_eprocess.add(task)
            known_pids.add(task.UniqueProcessId)

        pslist_api=ProcessTree().process_map()
        psscan_result = []
        psscan_error=set()
        for run in self.generate_memory_ranges():
            # Just grab the AS and scan it using our scanner
            scanner = PoolScanProcess(session=self.session,
                                      profile=self.profile,
                                      address_space=run.address_space)
            # print(os.getcwd())
            with open('mycsvfile.csv','a') as f:
                w = csv.writer(f)
                
                w.writerow(["offset_p",	"ppid",	"is_elevated", "elevation_type", "imagepath", "create_time", "exit_time", "psscan_driver", "pslist_api", "pslist_driver"])
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
        
                    pid=eprocess.pid.value
                    ppid=eprocess.InheritedFromUniqueProcessId

                    # 2021.01.05 추후 elevated Unknown -> '' None 처리 해야함
                    is_elevated, elevated_type=GetTokenInformation().token_map(pid)
                    if len(is_elevated) == 0:
                        is_elevated[pid]=[None,"Unknown"]
                        elevated_type[pid]=[None,"Unknown"]

                    is_pslist_api="True"
                    if pid not in list(pslist_api.keys()):
                        is_pslist_api="False"

                    is_pslist_driver="True"
                    if pid not in pslist_driver:
                        is_pslist_driver="False"
                    try:
                        data = dict(
                            offset_p=eprocess.obj_offset,
                            ppid=ppid,                  
                            is_elevated = is_elevated[pid][1] or '',
                            elevation_type = elevated_type[pid][1] or '',
                            # whether Parents elevated 
                            # is_elevated_p = is_elevated[ppid][1],
                            # elevation_type_p = elevated_type[ppid][1],
                            imagepath=pslist_data[pid].Peb.ProcessParameters.ImagePathName,
                            create_time=eprocess.CreateTime or '',
                            exit_time=eprocess.ExitTime or '',
                            psscan_driver="True",
                            pslist_api=is_pslist_api,
                            pslist_driver=is_pslist_driver
                    )
                    
                        
                        w.writerow(data.values())

                    except Exception as e:
                        # print("error")
                        print(e)
                        psscan_error.add(pid)
                        
                        # print(eprocess.pid.value)
                        # print(eprocess.name)
                    
                    psscan_result.append(pid)

                    yield data

        try:
            print(os.get_terminal_size().columns*"-")
        except Exception as e:
            print("---Debug mode---")
        
        print("[List of processes not included in PSSCAN results]\n")
        psscan_error=psscan_error | (set(list(pslist_api.keys())).difference(set(psscan_result)))
        # pslist.add(11996)
        index=0
        
        if len(psscan_error) != 0:
            for pid in psscan_error:
                index += 1
                is_elevated, elevated_type=GetTokenInformation().token_map(pid)

                try:
                    # data = self.data_set(
                    #     None,
                    #     pslist_api[pid].ppid,
                    #     is_elevated[pid][1] or "unknown",
                    #     elevated_type[pid][1] or "unknown",
                    #     pslist_api[pid].full_path,
                    #     pslist_api[pid].creation_time,
                    #     "Activated", "False", "False", "True"
                    #     )
                    data =dict(
                        name=pslist_api[pid].name,
                        process_id=pslist_api[pid].pid,
                        ppid=pslist_api[pid].ppid,
                        path=pslist_api[pid].full_path,
                        creation_time=pslist_api[pid].creation_time,
                        elevated=is_elevated[pid][1] or "unknown",
                        elevated_type=elevated_type[pid][1] or "unknown",
                    )

                except Exception as e:
                    data=dict(
                    name=pslist_api[pid].name,
                    process_id=pslist_api[pid].pid,
                    ppid=pslist_api[pid].ppid,
                    path=pslist_api[pid].full_path,
                    creation_time=pslist_api[pid].creation_time,
                    elevated="unknown",
                    elevated_type="unknown"
                    )

                print(f" [{index}] {data['name']}\tPID: {data['process_id']}\tPPID: {data['ppid']}\timagepath: {data['path']}")
                print(f"\tcreat_time: {data['creation_time']}\t\tis_elevated: {data['elevated']}\televation_type: {data['elevated_type']}")
                
                        # offset_p="unknown",
                        # ppid=pslist_api[pid].ppid,                  
                        # is_elevated = is_elevated[pid][1] or '',
                        # elevation_type = elevated_type[pid][1] or '',
                        # # whether Parents elevated 
                        # # is_elevated_p = is_elevated[ppid][1],
                        # # elevation_type_p = elevated_type[ppid][1],
                        # imagepath=pslist_data[pid].Peb.ProcessParameters.ImagePathName,
                        # create_time=eprocess.CreateTime or '',
                        # exit_time=eprocess.ExitTime or '',
                        # psscan_driver="True",
                        # pslist_api=is_pslist_api,
                        # pslist_driver=is_pslist_driver
            

     
        