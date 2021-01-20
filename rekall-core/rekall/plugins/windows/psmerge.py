# @author       JeongPil, Lee(jeongpil@somma.kr)
# @date         2021/01/05 10:00 created.
# @copyright    (C)Somma,Inc. All rights reserved.

import os
import unittest
import pywintypes
import win32security
import psutil
import hashlib
import csv
import datetime

import pefile
import win32api,win32con
from OpenSSL import crypto
from OpenSSL.crypto import _lib, _ffi, X509

from rekall.plugins.windows import common
from rekall.plugins.windows.filescan import PoolScanProcess
# from rekall.plugins.response import processes


class GetTokenInformation:
    "자식, 부모 프로세스 권한 값 추출"
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
            if pid==5688:
                print (ph,"/",th)
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
            self.is_elevated[pid]=[None,""]
            self.elevation_type[pid]=[None,""]

    

class Process(object):
    "pslist api object 추출"
    def __init__(self, name:str, ppid:int, pid:int, creation_time:float, full_path:str,  cwd:str, cmd:str):
        self.name = name
        self.ppid = ppid
        self.pid = pid
        self.creation_time = creation_time
        self.full_path = full_path
        self.cwd = cwd
        self.cmd = cmd

class ProcessTree:
    "pslist api object 추출"
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

def sha256sum(file_path: str, blocksize=8192):
    "sha-1 해시함수 사용"
    if os.path.exists(file_path) is False:
        return ""
    hash_func = hashlib.sha256()
    with open(file_path, 'rb') as file_object:
        for block in iter(lambda: file_object.read(blocksize), b""):
            hash_func.update(block)
    return hash_func.hexdigest()

def get_certificates(self):
    "디지털 서명 관련 Openssl x509 오브젝트 처리"    
    certs = _ffi.NULL
    if self.type_is_signed():
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        certs = self._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        pycert._x509 = _lib.sk_X509_value(certs, i)
        pycerts.append(pycert)

    if not pycerts:
        return None
    return tuple(pycerts)


class PSMerge(common.WinScanner):
    "프로세스 아티팩트 통합 플러그인"
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
        dict(name="issuer", width=45)
    ]

    # Only bother to scan non paged pool by default.
    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True
    )
    
    pslist_api={}

    # def data_set(self, offset:str, ppid:int, is_elevated:str, elevation_type: str, imagepath:str,
    #                 create_time:str, exit_time:str, psscan_d:str, pslist_a:str, pslist_d:str):
    #     """render dict 생성"""
    #     data = dict(
    #                 offset_p=offset,
    #                 ppid=ppid,
    #                 is_elevated=is_elevated,
    #                 elevation_type=elevation_type,
    #                 imagepath=imagepath,
    #                 create_time=create_time,
    #                 exit_time=exit_time,
    #                 psscan_driver=psscan_d,
    #                 pslist_api=pslist_a,
    #                 pslist_driver=pslist_d
    #             )
    #     return data

    def get_imagepath(self, pid):
        """프로세스 이미지 경로 반환, QueryFullProcessImageNameW, PEB """
        try:
            imagepath=self.pslist_api[pid].full_path
        except KeyError:
            try:
                imagepath=str(pslist_data[pid].Peb.ProcessParameters.ImagePathName)
            except Exception:
                return ''
        return imagepath
            
    def get_psname(self,eprocess):
        """프로세스 이름 반환, 길이 15 짤림 관련"""
        try:
            psname=self.pslist_api[eprocess.pid.value].name
        except KeyError:
            psname=eprocess.name
        return psname

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

        # These are virtual addresses.
        known_eprocess = set()
        known_pids = set()

        for task in pslist.list_eprocess():
            known_eprocess.add(task)
            known_pids.add(task.UniqueProcessId)

        self.pslist_api=ProcessTree().process_map()
        psscan_result = set()
        psscan_error=set()
        
        for run in self.generate_memory_ranges():
            # Just grab the AS and scan it using our scanner
            scanner = PoolScanProcess(session=self.session,
                                      profile=self.profile,
                                      address_space=run.address_space)

            with open('psmerge.tsv','a', newline="") as f:
                w = csv.writer(f, delimiter='\t')
                
                w.writerow(["name",	"pid", "ppid", "is_elevated", "elevation_type", "is_elevated_p", "elevation_type_p", "imagepath", "create_time", "exit_time", "psscan_driver", "pslist_api", "pslist_driver", "hash_sha256", "is_signed", "issuer", "\n"])
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
                    is_elevated_p, elevated_type_p=GetTokenInformation().token_map(ppid)
                    is_pslist_api=True
                    if pid not in list(self.pslist_api.keys()):
                        is_pslist_api=False

                    is_pslist_driver=True
                    if pid not in pslist_driver:
                        is_pslist_driver=False

                    cert_object = {}
                    
                    try:
                        imagepath=self.get_imagepath(pid)
                        sha_256=sha256sum(imagepath)
                        pe = pefile.PE(imagepath)

                        address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                        ].VirtualAddress
                        size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                        ].Size
                        
                    ##todo : address 값 / 인증서 없을 때 부터 코드 작성 필요
                        if address == 0: #인증서 없는 경우
                            is_signed=False
                            cert_object['']=''
                
                        else:
                            is_signed=True
                            signature = pe.write()[address + 8 :]
                            pkcs = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, bytes(signature))
                            certs = get_certificates(pkcs)
                            for cert in certs:
                                c = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                                x509 = crypto.load_certificate(crypto.FILETYPE_PEM, c)

                                components=x509.get_subject().get_components()+x509.get_issuer().get_components()
                                cnt=0
                                key_issuer=''
                                for cert_value in components:
                                    
                                    if b'CN' in cert_value:
                                        if cnt==0:
                                            key_issuer=cert_value[1].decode()
                                            cert_object[key_issuer]=''
                                            cnt=cnt+1
                                        else:
                                            cert_object[key_issuer]=cert_value[1].decode()
                                        
                    except Exception as e:# 풀스캔 결과값에만 오브젝트가 존재할경우
                        imagepath=''
                        sha_256=''
                        is_signed=''
                        cert_object['']=''
                            
                    try:
                        data = dict(
                            offset_p=eprocess,
                            ppid=ppid,                  
                            is_elevated = is_elevated[pid][1] or '',
                            elevation_type = elevated_type[pid][1] or '',
                            # whether Parents elevated 
                            # is_elevated_p = is_elevated[ppid][1],
                            # elevation_type_p = elevated_type[ppid][1],
                            imagepath=imagepath,
                            create_time=eprocess.CreateTime or '',
                            exit_time=eprocess.ExitTime or '',
                            psscan_driver=True,
                            pslist_api=is_pslist_api,
                            pslist_driver=is_pslist_driver,
                            hash_sha256=sha_256,
                            is_signed=is_signed,
                            issuer=list(cert_object.keys())[0]
                    )
                        tsv_data = dict(
                            name=self.get_psname(eprocess),
                            pid=pid,
                            ppid=ppid,
                            is_elevated = is_elevated[pid][1],
                            elevation_type = elevated_type[pid][1],
                            is_elevated_p = is_elevated_p[ppid][1],
                            elevation_type_p = elevated_type_p[ppid][1],
                            imagepath=imagepath,
                            create_time=eprocess.CreateTime.as_windows_timestamp(),
                            exit_time=eprocess.ExitTime.as_windows_timestamp(),
                            psscan_driver=True,
                            pslist_api=is_pslist_api,
                            pslist_driver=is_pslist_driver,
                            hash_sha256=sha_256,
                            is_signed=is_signed,
                            issuer=list(cert_object.keys())
                        )
                        w.writerow(tsv_data.values())
                    # except KeyError as e:
                    #     #pslist_driver object에 없는 경우임
                    except Exception as e:
                        # print(e)
                        psscan_error.add(pid)                        

                    psscan_result.add(pid)  
                    yield data

        try:
            print(os.get_terminal_size().columns*"-")
        except Exception as e:
            print("---Debug mode---")
        

        print(f"[+]PSSCAN count : {len(psscan_result)}\n")
        print("[List of processes not included in PSSCAN results]\n")
        psscan_error=psscan_error | (set(list(self.pslist_api.keys())).difference(psscan_result))
        # debug psscan_error.add(11188)
        index=0
        
        if len(psscan_error) != 0:
            for pid in psscan_error:
                index += 1
                is_elevated, elevated_type=GetTokenInformation().token_map(pid)
                print("[+]",is_elevated, elevated_type)
                try:
                    data =dict(
                        name = self.pslist_api[pid].name,
                        process_id = self.pslist_api[pid].pid,
                        ppid = self.pslist_api[pid].ppid,
                        path = self.pslist_api[pid].full_path,
                        creation_time = datetime.datetime.fromtimestamp(self.pslist_api[pid].creation_time).strftime("%Y-%m-%d %H:%M:%S"),
                        elevated = is_elevated[pid][1],
                        elevated_type = elevated_type[pid][1]
                    )

                except Exception as e:
                    # 모든 결과값을 충족하지 못 할 경우
                    pass

                print(f" [{index}] {data['name']}\tPID: {data['process_id']}\tPPID: {data['ppid']}\timagepath: {data['path']}")
                print(f"\tcreat_time: {data['creation_time']}\t\tis_elevated: {data['elevated']}\televation_type: {data['elevated_type']}")
                
        '''
        1. psscan object 'Peb.ProcessParameters.ImagePathName'값이 왜 없을까?
            1.1 덩달아 hash값 구할 수 없음
            1.2 엔트리가 파일리스인 프로세스의 해시 탐지 불가능
        2. offset value 기반으로 name과 pid가 출력됨
        3. pslist에는 있는데 psscan에는 없을 경우 예외처리 안 됨(psscan 작동 시 pslist plugin default)

        '''
