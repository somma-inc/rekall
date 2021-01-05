import os

from itertools import chain
from collections import defaultdict

import psutil
import pandas as pd
import hashlib

from rekall.plugins.windows import common
from rekall.plugins.windows.filescan import PoolScanProcess

'''refac hong
class WindowsPsmerge(common.WinProcessFilter)"
    """
    Find hidden processes with various process listings
    """

    __name = "psmerge"

    METHODS = common.WinProcessFilter.METHODS + [
        "PSScan", "Thrdproc"
    ]

    __args = [
        dict(name="method", choices=list(METHODS), type="ChoiceArray",
             default=list(METHODS), help="Method to list processes.",
             override=True),
    ]
    """ Table Header 출력 부분(현재 사용하지 않음) """

    def render(self, renderer):
        headers = [
            dict(type="_EPROCESS", name="_EPROCESS"),
        ]
        header_list = ["Pslist_API", "Pslist_Live", "PSScan_Live"]
        
        # for method in header_list:
        #     headers.append((method, method, "%s" % len(method)))
        # renderer.table_header(headers) 

        # PSScan session 받아오기
        psscan_n = self.session.plugins.psmerge_psscan()

        # PSList session 받아오기
        pslist = self.session.plugins.pslist()

        # temp = self.PSScan_merge()
        # print(temp.collect())

        #
        # PSScan Driver mode 처리(PID(UniqueID), ImageFileName)
        #
        psscan_data = {}  # psscan_count = 0
        for row in psscan_n.collect():  # psscan_count += 1
            psscan_data[str(row['pid'])] = "[1]" + row['imagename']


        # PSList Driver mode 처리(PID(UniqueID), ImageFileName)
        pslist_data = {}  # pslist_count = 0
        for task in pslist.filter_processes():  # pslist_count += 1
            pslist_data[str(task.UniqueProcessId)] = "[2]" + str(task.ImageFileName)
            # print(task.Peb.ProcessParameters.ImagePathName)

        # PSList API mode 처리(Psutil lib, PID, ProcessName)
        pslist_api_data = {}
        for proc in psutil.process_iter():
            pslist_api_data[str(proc.pid)] = "[3]" + proc.name()

        # 플러그인 결과 값 취합, Key:Pid, Value:[N]processName
        #    [1] PSScan / [2] PSList_DRIVER / [3] PSList_API
        psmerge = defaultdict(list)
        for k, v in chain(psscan_data.items(), pslist_data.items(), pslist_api_data.items()):
            psmerge[k].append(v)

        # PID 오름차순 psmerge Dict key 정렬, int  """
        sort_psmerge = sorted(list(map(int, list(psmerge.keys()))))

        # Pandas 데이터 셋 생성
        PSexistence = {}
        for pid in sort_psmerge:
            PSexistence[str(pid)] = ["True"] * 3

        """ 플러그인 결과 값 유무 체크 """
        Dataset = [psscan_data, pslist_data, pslist_api_data]
        for plugin in Dataset:
            for pid in set(psmerge.keys()).difference(set(plugin.keys())):
                PSexistence[str(pid)][Dataset.index(plugin)] = "False"

        """ '프로세스 이름(PID)' 형식의 INDEX 값 생성 """
        ProcessName_PID = []
        for i in sort_psmerge:
            PSName = max(psmerge.get(str(i)), key=len)[3:]
            ProcessName_PID.append(PSName + "(" + str(i) + ")")

        """ 데이터 출력을 위한 임시 Pandas DataFrame 생성 """
        df = pd.DataFrame({
            'Process': ProcessName_PID,
            '   PSScan': [exist[0] for exist in list(PSexistence.values())],
            '   PSList_Driver': [exist[1] for exist in list(PSexistence.values())],
            '   PSList_API': [exist[2] for exist in list(PSexistence.values())]
        }
        ).set_index('Process')



        # df_i = df.set_index('Process')

        """ csv 저장 """
        df.to_csv('psmerge.csv')
        print(df)
'''


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
