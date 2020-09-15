#!/usr/bin/python
# -*- coding:utf-8 -*-
#
# @author       Yonghwan, Roh(somma@somma.kr)
# @date
# @copyright    (C)Somma,Inc. All rights reserved.
#
import os
import sys
from typing import List

class xview:
    def __init__(self, address):
        self.windbg = None
        self.pslist = None
        self.psscan = None


class eprocess:
    def __init__(self, **kwargs):
        self.eprocess = kwargs['eprocess'] if 'eprocess' in kwargs else None
        self.name = kwargs['name'] if 'name' in kwargs else None
        self.pid = kwargs['pid'] if 'pid' in kwargs else None
        self.ppid = kwargs['ppid'] if 'ppid' in kwargs else None
        self.thread_count = kwargs['thread_count'] if 'thread_count' in kwargs else None
        self.handle_count = kwargs['handle_count'] if 'handle_count' in kwargs else None
        self.session_id = kwargs['session_id'] if 'session_id' in kwargs else None
        self.wow64 = kwargs['wow64'] if 'wow64' in kwargs else None
        self.process_create_time = kwargs['process_create_time'] if 'process_create_time' in kwargs else None
        self.process_exit_time = kwargs['process_exit_time'] if 'process_exit_time' in kwargs else None
        self.dtb = kwargs['dtb'] if 'dtb' in kwargs else None


def parse_pslist_line(line: str) -> eprocess:
    tks: List[str] = line.strip().split()
    exit_time = '{} {}'.format(tks[10], tks[11]) if not tks[10] == '-' else None

    return eprocess(eprocess=int(tks[0].strip()[2:], 16),
                    name=tks[1],
                    pid=tks[2],
                    ppid=tks[3],
                    thread_count=tks[4],
                    handle_count=tks[5],
                    session_id=tks[6],
                    wow64=tks[7],
                    process_create_time='{} {}'.format(tks[8], tks[9]),
                    process_exit_time=exit_time,
                    dtb=None)


def read_pslist(file_path: str):
    with open(file_path, mode='r') as f:
        for line in f:
            if not line.startswith('0x'):
                continue
            else:
                yield parse_pslist_line(line)





def parse_psscan_line(line: str) -> eprocess:
    tks: List[str] = line.split()

    """
    아래처럼 괴상한 로그라인도 있으므로 token 갯수를 확인해야 함

    0xbd058a961660                          0 0xbd058a961660 367326 0xffffbd058abda688
                                                             8224
    """
    if len(tks) < 9:
        return None

    if len(tks) < 11:
        exit_time = None
    else:
        exit_time = '{} {}'.format(tks[7], tks[8])

    return eprocess(eprocess=int(tks[0].strip()[2:], 16),
                    name=tks[1],
                    pid=tks[2],
                    ppid=tks[4],
                    thread_count=None,
                    handle_count=None,
                    session_id=None,
                    wow64=None,
                    process_create_time='{} {}'.format(tks[7], tks[8]),
                    process_exit_time=exit_time,
                    dtb=None)

def read_psscan(file_path: str):
    with open(file_path, mode='r') as f:
        for line in f:
            if not line.strip().startswith('0x'):
                continue
            else:
                yield parse_psscan_line(line)







def read_windbg(file_path: str):
    """
    `kd>!process 0 0` output 파싱

        PROCESS ffffbd0581e83040
            SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
            DirBase: 001aa002  ObjectTable: ffffad0206c04b80  HandleCount: 2519.
            Image: System

        PROCESS ffffbd0581ef0080
            SessionId: none  Cid: 0080    Peb: 00000000  ParentCid: 0004
            DirBase: 03d47002  ObjectTable: ffffad0206c33ac0  HandleCount:   0.
            Image: Registry

        PROCESS ffffbd058ac1c4c0
            SessionId: 1  Cid: 1434    Peb: 4f3df58000  ParentCid: 0330
        DeepFreeze
            DirBase: 45b2c002  ObjectTable: ffffad020e5c8b40  HandleCount: <Data Not Accessible>
            Image: LockApp.exe
    """
    with open(file_path, mode='r') as f:
        for line in f:
            if not line.startswith('PROCESS'):
                continue
            else:
                d = {}

                # PROCESS ffffbd0581e83040
                tks = line.strip().split()
                d['eprocess'] = int(tks[1].strip()[4:], 16)

                l2 = f.readline()
                tks = l2.strip().split()
                # SessionId: none  Cid: 0080    Peb: 00000000  ParentCid: 0004
                d['session_id'] = tks[1] if tks[1] != 'none' else None
                d['pid'] = str(int(tks[3], 16))
                d['ppid'] = str(int(tks[7], 16))

                # DirBase: 03d47002  ObjectTable: ffffad0206c33ac0  HandleCount:   0.
                l3 = f.readline().strip()
                if l3.startswith("DeepFreeze"):
                    l3 = f.readline().strip()

                tks = l3.strip().split()
                d['dtb'] = str(int(tks[1], 16))
                d['handle_count'] = str(int(tks[5].strip('.'))) if not tks[5].startswith('<Data') else None

                l4 = f.readline()
                tks = l4.strip().split()
                d['name'] = tks[1].strip()

                yield eprocess(eprocess=d['eprocess'],
                               name=d['name'],
                               pid=d['pid'],
                               ppid=d['ppid'],
                               thread_count=None,
                               handle_count=d['handle_count'],
                               session_id=d['session_id'],
                               wow64=None,
                               process_create_time=None,
                               process_exit_time=None,
                               dtb=d['dtb'])

if __name__ == '__main__':
    # pslist
    idx = 0
    pslist = {}
    for obj in read_pslist(os.path.join(os.getcwd(), '..', 'pslist_2004.txt')):
        pslist[obj.eprocess] = obj
        #if not obj.process_exit_time:
        #    print('{:>04}, {}, {}, {}'.format(idx, obj.eprocess, obj.name, obj.process_exit_time))
        #idx += 1

    # psscan
    idx = 0
    psscan = {}
    for obj in read_psscan(os.path.join(os.getcwd(), '..', 'psscan_2004.txt')):
        if obj:
            psscan[obj.eprocess] = obj
            #if not obj.process_exit_time:
            #    print('{:>04}, {}, {}, {}'.format(idx, obj.eprocess, obj.name, obj.process_exit_time))
            #idx += 1

    # windbg
    idx = 0
    windbg = {}
    for obj in read_windbg(os.path.join(os.getcwd(), '..', 'windbg_2004.txt')):
        windbg[obj.eprocess] = obj
        #print('{:>04}, {}, {}, {}'.format(idx, obj.eprocess, obj.name, obj.process_exit_time))
        #idx += 1

    # xview
    xv = {}
    for k, v in windbg.items():
        if k not in xv:
            xv[k] = xview(k)
        xv[k].windbg = v

    for k, v in pslist.items():
        if k not in xv:
            xv[k] = xview(k)
        xv[k].pslist = v

    for k, v in psscan.items():
        if k not in xv:
            xv[k] = xview(k)
        xv[k].psscan = v


    # dump all
    print("WinDBG  PSList  PSScan  _EPROCESS")
    c_windbg = 0
    c_pslist = 0
    c_psscan = 0
    c_match = 0

    for k, v in xv.items():
        if v.windbg and v.pslist and v.psscan:
            ret = True
        else:
            ret = False

        #
        #   Name check
        #
        shortest_name = ''
        names = []
        if v.windbg:
            c_windbg += 1
            names.append(v.windbg.name)
            shortest_name = v.windbg.name

        if v.pslist:
            c_pslist += 1
            names.append(v.pslist.name)
            if len(v.pslist.name) < len(shortest_name):
                shortest_name = v.pslist.name

        if v.psscan:
            c_psscan += 1
            names.append(v.psscan.name)
            if len(v.psscan.name) < len(shortest_name):
                shortest_name = v.psscan.name

        for name in names:
            if shortest_name not in name:
                ret = False
                break

        if ret:
            c_match += 1

        print('  {}        {}      {}      0x{:>016x}    {}   {}'.format(
            'O' if v.windbg else ' ',
            'O' if v.pslist else ' ',
            'O' if v.psscan else ' ',
            k,
            'O' if ret else ' ',
            ', '.join(names)))
    print('--------------------------------------------------')
    print(' {}      {}     {}                           {}'.format(c_windbg, c_pslist, c_psscan, c_match))
