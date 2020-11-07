# Rekall 설치
+ git for windows 설치
+ 윈도우즈용 컴파일러 설치 
    - https://wiki.python.org/moin/WindowsCompilers
    - python 3.5 - 3.8 은 vs 14.x 버전 설치 필요
    - visual studio setup -> 컴파일러, 빌드 도구 및 런타임 -> build tools 설치해야 함
        ```
        ...
        error: Setup script exited with error: Microsoft Visual C++ 14.0 or greater is required. Get it with "Microsoft C++ Build Tools": https://visualstudio.microsoft.com/visual-cpp-build-tools/
        ...
        ```

+ rekall 실행 환경 구성 (관리자 사용자 권한으로)
    ```
    >conda create --name rekall python=3.8.5
    >activate rekall
    >pip install --upgrade setuptools pip wheel --user
    >conda install -c anaconda pywin32
    >conda install -c saedrna capstone
    ```

+ rekall 소스코드 다운로드 && 설치
    ```
    >git clone https://github.com/somma-inc/rekall.git c:\work.rekall
    >cd rekall-core
    >python setup.py install        (최초 빌드/설치시 관리자권한으로, 일반 사용자권한으로 하면 에러남)
    ```

# 참고
+ Official rekall
    - https://github.com/google/rekall/
    - [Rekall tutorial](http://www.rekall-forensic.com/documentation-1/rekall-documentation/tutorial)
    - [fixes bug in VA translation process (#538)](https://github.com/google/rekall/commit/b6f632f167c7d5cd80decf6fcb5481b45e38101c)
    - [winpmem](https://github.com/google/rekall/tree/master/tools/windows/winpmem)

+ FireEye fork version (add memory compression analysis)
    - https://github.com/fireeye/win10_rekall
    - https://github.com/fireeye/win10_rekall/commit/2027518aae789e54d408cd8e2e414557122a6096

+ ETC
    - [Virtual Secure Mode (VSM) in Windows 10 Enterprise](http://woshub.com/virtual-secure-mode-vsm-in-windows-10-enterprise/)
    - [Pool tag quick scanning for windows memory analysis, DFRWS2016](https://www.sciencedirect.com/science/article/pii/S1742287616000062)

## Profile
- ntkrnlmp.pdb 상의 내용을 파싱해서 익스포트된 심볼들의 RVA 를 기록
- 내부에서 사용되는 거의 모든 상수값/오프셋들을 여기서 처리 (session 객체내 profile 객체로 관리)

- `nt!PsActiveProcessHead` 심볼의 RVA 는 `4426368` 
    ```
    1: kd> lmvm nt
    Browse full module list
    start             end                 module name
    fffff805`28a19000 fffff805`294d0000   nt         (pdb symbols)          C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym\ntkrnlmp.pdb\512C583E636270A8A26A461F4B383A091\ntkrnlmp.pdb
    ...
    1: kd> x nt!PsActiveProcessHead
    fffff805`28e51a80 nt!PsActiveProcessHead = <no type information>
    ...
    1: kd> ? fffff805`28e51a80-fffff805`28a19000
    Evaluate expression: 4426368 = 00000000`00438a80
    ```

- `c:\Users\unsor\.rekall_cache\v1.0\nt\GUID\512C583E636270A8A26A461F4B383A091.gz\512C583E636270A8A26A461F4B383A091` 파일을 확인해보면 값이 정확히 일치함을 확인 가능

    ```
    ...
    "ProgressBarTop": ..., 
    "PsActiveProcessHead": 4426368, 
    "PsContinueWaiting": ...,  
    ...  
    ```

## Address space 
- C:\work.rekall\rekall-core\build\lib\rekall\plugins\addrspaces\win32.py
- Win32AddressSpace
    - WinPmemAddressSpace
    + WinPmemAddressSpace::ConfigureSession() 
        - 여기서 `CR3` 값을 읽어서 `dtb` 값을 세션에 캐시하는것 같음
        - `kernel_base` 값도 제대로 설정되는지 확인 필요

+ DTB alignment 관련 분석
    - 실제로 DTB 값이 이상한거 맞음
    - 메모리는 정확함

    ```
    Rekall 로그
    2020-09-09 01:36:17,081:DEBUG:rekall.1:somma, dtb mis-alignment skip eprocess=0x0000ae0166caa080, pid=5132, dtb=0x000000004e312002, LockApp.exe

    WinDbg 로그
    PROCESS ffffae0166caa080
        SessionId: 1  Cid: 140c    Peb: 3965a22000  ParentCid: 0330
    DeepFreeze
        DirBase: 4e312002  ObjectTable: ffffcf0a4cf1c8c0  HandleCount: <Data Not Accessible>
        Image: LockApp.exe
    ```

    - WinDbg 로 확인한 다른 프로세스들도 `DirBase` 는 page align 되지 않음

    ```
    PROCESS ffffae017a46f4c0
        SessionId: 1  Cid: 19cc    Peb: 4e5208f000  ParentCid: 0618
        DirBase: 6969e002  ObjectTable: ffffcf0a4bbdcb00  HandleCount: <Data Not Accessible>
        Image: python.exe

    PROCESS ffffae016c7e7080
        SessionId: 0  Cid: 11d0    Peb: 903d83e000  ParentCid: 0330
        DirBase: 0370e002  ObjectTable: ffffcf0a5b8acf00  HandleCount: 330.
        Image: usocoreworker.exe

    PROCESS ffffae016e7c6080
        SessionId: 0  Cid: 1730    Peb: da9f7fe000  ParentCid: 028c
        DirBase: 08cf6002  ObjectTable: ffffcf0a50c14880  HandleCount: 227.
        Image: sppsvc.exe

    PROCESS ffffae016e6b14c0
        SessionId: 0  Cid: 0f0c    Peb: 1134678000  ParentCid: 01c0
        DirBase: 6eac2002  ObjectTable: ffffcf0a5d985700  HandleCount: <Data Not Accessible>
        Image: MusNotification.exe

    PROCESS ffffae0178ad04c0
        SessionId: 0  Cid: 1ed8    Peb: 74899a9000  ParentCid: 01c0
        DirBase: 0c870002  ObjectTable: ffffcf0a5b8af400  HandleCount: <Data Not Accessible>
        Image: MusNotification.exe
    ```

+ 중요한 클래스들(?)
    ```
    class WinFindDTB(AbstractWindowsCommandPlugin, core.FindDTB):
        """A plugin to search for the Directory Table Base for windows systems.

        There are a number of ways to find the DTB:

        - Scanner method: Scans the image for a known kernel process, and read the
        DTB from its Process Environment Block (PEB).

        - Get the DTB from the KPCR structure.

        - Note that the kernel is mapped into every process's address space (with
        the exception of session space which might be different) so using any
        process's DTB from the same session will work to read kernel data
        structures. If this plugin fails, try psscan to find potential DTBs.
        """
    ```

    - winpmem 처리 클래스
    ```
    class Live(plugin.TypedProfileCommand,
            plugin.ProfileCommand):
        """Launch a Rekall shell for live analysis on the current system."""

        name = "live"    
    ```


+ **ing**
    - Windbg 의 !poolfind -tag Proc -nonpaged 명령의 결과와 PSScan 대상 메모리 영역과 비교해보기

    
    - !poolfind -tag Proc -nonpaged
    ```    
    ffffe303c4e80010 : tag Proc, size     0xdf0, Nonpaged pool
    ffffe303c4eec010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c4f33010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c4f3a010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c4f69010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c4f73010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c4f75010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c7d34010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c8403010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c840f010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c863a010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c86bd010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c872d010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c880f010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c8811010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c8c41010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c8d96010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c9243010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c9320010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c93d2010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c9929010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c9957010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c9960010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c99b7010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c99f2010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c9a94010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c9bd1010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c9c5b010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303c9d69010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303ca0a8010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303ca18d010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303ca9a3010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303caa3a010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303caa57010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303caa5e010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303cc07d010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303cc2bc010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303cc2c3010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303cc2c7010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303cc310010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303cc343010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303cc7fb010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303cc91b010 : tag Proc, size     0xcf0, Nonpaged pool
    ffffe303cc92a010 : tag Proc, size     0xcf0, Nonpaged pool
    ```

    - rekal --live Memory psscan
    ```
    2020-09-14 02:59:00,104:INFO:rekall.1:Scanning in: Pool NonPagedPool. [0xe300'00000000-0xf300'00000000]     <!!> 메모리 영역 확인 필요
    2020-09-14 02:59:00,104:DEBUG:rekall.1:somma, run=0xe300'00000000->0xf300'00000000, type=Pool NonPagedPool
    2020-09-14 02:59:00,104:DEBUG:rekall.1:somma, self.kernel=0x800000000000,                                   <!!> 0xffff8000000000000 이어야 하는데?!
        checks=[
            ('PoolTagCheck', {'tag': b'Proc'}), 
            ('CheckPoolSize', {'min_size': 2624}), 
            ('CheckPoolType', 
                {
                    'paged': True, 
                    'non_paged': True,
                    'free': True
                }
            ), 
            ('CheckPoolIndex', 
                {
                    'value': 0
                }
            )
        ]
                    <!!> check() 내부에서 skipper 로직이 잘못되었는지 확인필요
                    <!!> 실제 할당된 pool 들의 영역과 스캔 대상 영역 일치 여부 확인 필요

    2020-09-14 02:59:00,244:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:00,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c4eec8f0, pid=0, 
    2020-09-14 02:59:00,385:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c4f3a6c0, pid=0, 
    2020-09-14 02:59:00,697:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c70de9d0, pid=0, 
    2020-09-14 02:59:00,807:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:00,807:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:00,807:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cd9a0, pid=0, 
    2020-09-14 02:59:00,807:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cd9b0, pid=0, 
    2020-09-14 02:59:00,807:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cd9c0, pid=0, 
    2020-09-14 02:59:00,823:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cd9d0, pid=0, 
    2020-09-14 02:59:00,823:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:00,823:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:00,823:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:00,823:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cda10, pid=0, 
    2020-09-14 02:59:00,823:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cdb60, pid=0, 
    2020-09-14 02:59:00,823:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cdc50, pid=0, 
    2020-09-14 02:59:00,823:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:00,823:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:00,823:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cdc80, pid=0, 
    2020-09-14 02:59:00,838:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cdc90, pid=0, 
    2020-09-14 02:59:00,838:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cdca0, pid=0, 
    2020-09-14 02:59:00,838:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:00,838:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cdcd0, pid=0, 
    2020-09-14 02:59:00,838:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cdce0, pid=0, 
    2020-09-14 02:59:00,838:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c74cdd20, pid=0, 
    2020-09-14 02:59:01,041:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c8411b30, pid=0, 
    2020-09-14 02:59:01,135:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,166:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c852c430, pid=6649957, Y\x01
    2020-09-14 02:59:01,338:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bd930, pid=0, 
    2020-09-14 02:59:01,338:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,353:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bda00, pid=0, 
    2020-09-14 02:59:01,353:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,353:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bdc40, pid=0, 
    2020-09-14 02:59:01,353:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bdc50, pid=0, 
    2020-09-14 02:59:01,353:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bdc60, pid=0, 
    2020-09-14 02:59:01,353:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bdc70, pid=0, 
    2020-09-14 02:59:01,369:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,369:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,369:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bdca0, pid=0, 
    2020-09-14 02:59:01,369:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bdcb0, pid=0, 
    2020-09-14 02:59:01,369:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bdcf0, pid=0, 
    2020-09-14 02:59:01,369:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bdd00, pid=0, 
    2020-09-14 02:59:01,369:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bdd10, pid=0, 
    2020-09-14 02:59:01,369:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c86bdd20, pid=0, 
    2020-09-14 02:59:01,447:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c8811790, pid=0, 
    2020-09-14 02:59:01,463:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c8811cc0, pid=0, 
    2020-09-14 02:59:01,744:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,744:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,744:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,744:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,744:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c900d9f0, pid=7, 
    2020-09-14 02:59:01,744:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c900da00, pid=0, 
    2020-09-14 02:59:01,744:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c900da10, pid=0, 
    2020-09-14 02:59:01,744:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,760:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,760:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,760:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c900dcc0, pid=0, 
    2020-09-14 02:59:01,760:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c900dcd0, pid=0, 
    2020-09-14 02:59:01,760:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c900dce0, pid=0, 
    2020-09-14 02:59:01,760:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,760:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c900dd10, pid=0, 
    2020-09-14 02:59:01,760:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c900dd20, pid=0, 
    2020-09-14 02:59:01,838:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,838:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,838:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c90cd990, pid=0, 
    2020-09-14 02:59:01,838:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c90cd9a0, pid=0, \x0f\x1fD
    2020-09-14 02:59:01,838:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,838:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,838:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,854:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c90cdc80, pid=0, 
    2020-09-14 02:59:01,854:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,854:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,854:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:01,916:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c93201f0, pid=1919251564, Y\x01
    2020-09-14 02:59:01,963:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c93d2b30, pid=0, 
    2020-09-14 02:59:02,151:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c9868470, pid=1701539698, Y\x01
    2020-09-14 02:59:02,291:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303c99601f0, pid=1702389038, Y\x01
    2020-09-14 02:59:02,401:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:02,432:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:02,479:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca0a8cc0, pid=0, 
    2020-09-14 02:59:02,526:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18d790, pid=0, 
    2020-09-14 02:59:02,541:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18d930, pid=0, 
    2020-09-14 02:59:02,541:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:02,541:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18da00, pid=0, 
    2020-09-14 02:59:02,541:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:02,556:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18dc40, pid=0, 
    2020-09-14 02:59:02,556:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18dc50, pid=0, 
    2020-09-14 02:59:02,556:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18dc60, pid=0, 
    2020-09-14 02:59:02,556:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18dc70, pid=0, 
    2020-09-14 02:59:02,572:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:02,572:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:02,572:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18dca0, pid=0, 
    2020-09-14 02:59:02,572:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18dcb0, pid=0, 
    2020-09-14 02:59:02,572:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18dcc0, pid=0, 
    2020-09-14 02:59:02,572:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18dcf0, pid=0, 
    2020-09-14 02:59:02,572:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18dd00, pid=0, 
    2020-09-14 02:59:02,572:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303ca18dd10, pid=0, 
    2020-09-14 02:59:03,291:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07d930, pid=0, 
    2020-09-14 02:59:03,291:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:03,307:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07da00, pid=0, 
    2020-09-14 02:59:03,307:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07da10, pid=0, 
    2020-09-14 02:59:03,307:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:03,307:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dc40, pid=0, 
    2020-09-14 02:59:03,307:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dc50, pid=0, 
    2020-09-14 02:59:03,307:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dc60, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dc70, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dc80, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dc90, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dca0, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dcb0, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dcc0, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dcd0, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, invalid range skip list flink=None, blink=None
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dcf0, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dd00, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dd10, pid=0, 
    2020-09-14 02:59:03,323:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc07dd20, pid=0, 
    2020-09-14 02:59:03,431:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc2c76e0, pid=0, 
    2020-09-14 02:59:03,447:DEBUG:rekall.1:somma, no dtb, skip eprocess=0x0000e303cc3101f0, pid=0, Y\x01












# Windows 2004 Enterprise test

+ winpmem::DriverEntry
    - ntoskrnl 시작주소를 찾기 위해 NtBuildNumber 심볼로부터 페이지만큼 스캔함
    - 19041 버전에서는 기존 Symbol 스캔의 범위 밖에 시작주소가 있어서 스캔이 안되었음

    ```
    [2004, 19041]
    1: kd> lmvm nt
    Browse full module list
    start             end                 module name
    fffff800`5bc19000 fffff800`5cc5f000   nt         (pdb symbols)          c:\symbols\ntkrnlmp.pdb\641F55C592201DCC4F59FACC72EA54DA1\ntkrnlmp.pdb
        Loaded symbol image file: ntkrnlmp.exe
        Image path: ntkrnlmp.exe
        Image name: ntkrnlmp.exe
        Browse all global symbols  functions  data
        Image was built with /Brepro flag.
        Timestamp:        A371A2E9 (This is a reproducible build file hash, not a timestamp)
        CheckSum:         00A611D3
        ImageSize:        01046000
        File version:     10.0.19041.508
        Product version:  10.0.19041.508
        File flags:       0 (Mask 3F)
        File OS:          40004 NT Win32
        File type:        1.0 App
        File date:        00000000.00000000
        Translations:     0409.04b0
        Information from resource tables:
            CompanyName:      Microsoft Corporation
            ProductName:      Microsoft® Windows® Operating System
            InternalName:     ntkrnlmp.exe
            OriginalFilename: ntkrnlmp.exe
            ProductVersion:   10.0.19041.508
            FileVersion:      10.0.19041.508 (WinBuild.160101.0800)
            FileDescription:  NT Kernel & System
            LegalCopyright:   © Microsoft Corporation. All rights reserved.

    1: kd> vertarget
    Windows 10 Kernel Version 19041 MP (2 procs) Free x64
    Product: WinNt, suite: TerminalServer SingleUserTS
    Built by: 19041.1.amd64fre.vb_release.191206-1406
    Machine Name:
    Kernel base = 0xfffff800`5bc19000 PsLoadedModuleList = 0xfffff800`5c843310
    Debug session time: Mon Sep 14 02:36:31.401 2020 (UTC + 9:00)
    System Uptime: 0 days 1:00:21.210


    1: kd> db fffff800`5bc19000 L8
    fffff800`5bc19000  4d 5a 90 00 03 00 00 00                          MZ......

    1: kd> x nt!NtBuildNumber
    fffff800`5c82ae90 nt!NtBuildNumber = <no type information>

    1: kd> ? fffff800`5c82ae90-fffff800`5bc19000
    Evaluate expression: 12656272 = 00000000`00c11e90

    ```

    ```
    [Win10, Kernel version 18362]
    0: kd> lmvm nt
    Browse full module list
    start             end                 module name
    fffff805`63c1e000 fffff805`646d5000   nt         (pdb symbols)          C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym\ntkrnlmp.pdb\512C583E636270A8A26A461F4B383A091\ntkrnlmp.pdb
        Loaded symbol image file: ntkrnlmp.exe
        Image path: ntkrnlmp.exe
        Image name: ntkrnlmp.exe
        Browse all global symbols  functions  data
        Image was built with /Brepro flag.
        Timestamp:        7530C6D3 (This is a reproducible build file hash, not a timestamp)
        CheckSum:         0097FD44
        ImageSize:        00AB7000
        Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4
        Information from resource tables:

    0: kd> vertarget
    Windows 10 Kernel Version 18362 MP (2 procs) Free x64
    Product: WinNt, suite: TerminalServer SingleUserTS
    Built by: 18362.1.amd64fre.19h1_release.190318-1202
    Machine Name:
    Kernel base = 0xfffff805`63c1e000 PsLoadedModuleList = 0xfffff805`640660f0
    Debug session time: Mon Sep 14 02:32:59.715 2020 (UTC + 9:00)
    System Uptime: 3 days 3:25:30.184


    0: kd> db fffff805`63c1e000 L8
    fffff805`63c1e000  4d 5a 90 00 03 00 00 00                          MZ......


    0: kd> x nt!NtBuildNumber
    fffff805`63fb4238 nt!NtBuildNumber = <no type information>

    0: kd> ? fffff805`63fb4238 - fffff805`63c1e000
    Evaluate expression: 3760696 = 00000000`00396238
    ```

# Commands ref.
- winpmem 드라이버를 사용하기때문에 항상 관리자권한으로
    ```
    rekal --live Memory psxview
    rekal --live Memory psscan --scan_kernel_paged_pool --scan_kernel_nonpaged_pool --scan_kernel_code --scan_physical --logging_level DEBUG
    rekal --live Memory psscan --logging_level DEBUG
    rekal --live Memory psscan --scan_kernel_paged_pool --scan_kernel_nonpaged_pool --scan_kernel_code --scan_physical --logging_level DEBUG 2> psscan2.txt

    rekal --live Memory --verbose
    ```

- debugging (I) 하기 
    - `rekal --live Memory --verbose` 명령으로 rekall 실행
    - pycharm 을 관리자 권한으로 실행
    - pycharm -> Run -> Attach to process 로 rekall 프로세스에 어태치
    - pycharm -> External Libraries -> rekall-core ->

- debugging (II)
    - Pycharm 디버거로 `C:\work.rekall\rekall-core\rekall\rekal.py --live Memory --verbose` 실행
    - pycharm -> Run -> Attach to process 로 rekall 프로세스에 어태치
    - pycharm -> External Libraries -> rekall-core 내 python 모듈에 브레이크 포인트 설정
    - 아래와 같은 에러발생시 `c:\Users\unsor\anaconda3\envs\rekall\Lib\site-packages\rekall_capstone-3.0.5.post2-py3.8-win-amd64.egg\capstone\capstone.dll` 을 system32 폴더에 복사해주고, 다시 실행한다.
    
        ```
        Connected to pydev debugger (build 202.6948.78)
        Traceback (most recent call last):
        File "<frozen importlib._bootstrap>", line 991, in _find_and_load
        File "<frozen importlib._bootstrap>", line 975, in _find_and_load_unlocked
        File "<frozen importlib._bootstrap>", line 671, in _load_unlocked
        File "<frozen importlib._bootstrap_external>", line 783, in exec_module
        File "<frozen importlib._bootstrap>", line 219, in _call_with_frames_removed
        File "C:\Users\unsor\anaconda3\envs\rekall\lib\site-packages\rekall_core-1.7.3.dev65-py3.8.egg\rekall\plugins\__init__.py", line 4, in <module>
            from rekall.plugins import addrspaces
        File "C:\Users\unsor\anaconda3\envs\rekall\lib\site-packages\rekall_core-1.7.3.dev65-py3.8.egg\rekall\plugins\addrspaces\__init__.py", line 8, in <module>
            from rekall.plugins.addrspaces import ewf
        File "C:\Users\unsor\anaconda3\envs\rekall\lib\site-packages\rekall_core-1.7.3.dev65-py3.8.egg\rekall\plugins\addrspaces\ewf.py", line 26, in <module>
            from rekall.plugins.tools import ewf
        File "C:\Users\unsor\anaconda3\envs\rekall\lib\site-packages\rekall_core-1.7.3.dev65-py3.8.egg\rekall\plugins\tools\__init__.py", line 30, in <module>
            from rekall.plugins.tools import disassembler
        File "C:\Users\unsor\anaconda3\envs\rekall\lib\site-packages\rekall_core-1.7.3.dev65-py3.8.egg\rekall\plugins\tools\disassembler.py", line 29, in <module>
            import capstone
        File "C:\Users\unsor\anaconda3\envs\rekall\lib\site-packages\rekall_capstone-3.0.5.post2-py3.8-win-amd64.egg\capstone\__init__.py", line 252, in <module>
            raise ImportError("ERROR: fail to load the dynamic library.")
        ImportError: ERROR: fail to load the dynamic library.
        ```


# 각 플러그인간 결과 비교

## win10 18362, WinDbg, PsList, PsScan 비교
    ```
    WinDBG  PSList  PSScan  _EPROCESS
    O        O      O      0x0000bd0581e83040    O   System, System, System
    O        O             0x0000bd0581ef0080        Registry, Registry
    O        O             0x0000bd0584911400        smss.exe, smss.exe
    O        O             0x0000bd05849d1080        csrss.exe, csrss.exe
    O        O             0x0000bd0588865080        wininit.exe, wininit.exe
    O        O             0x0000bd058886c140        csrss.exe, csrss.exe
    O        O      O      0x0000bd058817a080    O   winlogon.exe, winlogon.exe, winlogon.exe
    O        O             0x0000bd05888b40c0        services.exe, services.exe
    O        O             0x0000bd05888b5080        lsass.exe, lsass.exe
    O        O      O      0x0000bd0588921180    O   fontdrvhost.exe, fontdrvhost.ex, fontdrvhost.ex
    O        O             0x0000bd05888eb180        fontdrvhost.exe, fontdrvhost.ex
    O        O      O      0x0000bd0588923280    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000bd05889c2300    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000bd058901f080    O   dwm.exe, dwm.exe, dwm.exe
    O        O             0x0000bd05890210c0        LogonUI.exe, LogonUI.exe
    O        O             0x0000bd05890a7280        svchost.exe, svchost.exe
    O        O             0x0000bd05890b2300        svchost.exe, svchost.exe
    O        O      O      0x0000bd05890c3300    O   svchost.exe, svchost.exe, svchost.exe
    O        O             0x0000bd05890e2280        svchost.exe, svchost.exe
    O        O      O      0x0000bd058919e300    O   svchost.exe, svchost.exe, svchost.exe
    O        O             0x0000bd05892bb300        svchost.exe, svchost.exe
    O        O      O      0x0000bd0581ef7080    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000bd0581ee3040    O   MemCompression, MemCompression, MemCompression
    O        O             0x0000bd0581f60340        svchost.exe, svchost.exe
    O        O      O      0x0000bd05894cc300    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000bd058956e140    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000bd05896b6240    O   spoolsv.exe, spoolsv.exe, spoolsv.exe
    O        O             0x0000bd0589745380        svchost.exe, svchost.exe
    O        O      O      0x0000bd0589749300    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000bd0589987280    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000bd058997b080    O   dasHost.exe, dasHost.exe, dasHost.exe
    O        O      O      0x0000bd05899d2340    O   VGAuthService.exe, VGAuthService., VGAuthService.
    O        O      O      0x0000bd05899ce2c0    O   vmtoolsd.exe, vmtoolsd.exe, vmtoolsd.exe
    O        O      O      0x0000bd0589a6b340    O   MsMpEng.exe, MsMpEng.exe, MsMpEng.exe
    O        O      O      0x0000bd0589ab0280    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000bd0589c50080    O   dllhost.exe, dllhost.exe, dllhost.exe
    O        O      O      0x0000bd0589c51080    O   WmiPrvSE.exe, WmiPrvSE.exe, WmiPrvSE.exe
    O        O      O      0x0000bd0589850080    O   msdtc.exe, msdtc.exe, msdtc.exe
    O        O      O      0x0000bd058a007080    O   NisSrv.exe, NisSrv.exe, NisSrv.exe
    O        O      O      0x0000bd058a0c3080    O   sihost.exe, sihost.exe, sihost.exe
    O        O      O      0x0000bd058a0c4080    O   svchost.exe, svchost.exe, svchost.exe
    O        O             0x0000bd058a0e3440        taskhostw.exe, taskhostw.exe
    O        O      O      0x0000bd058a1363c0    O   ctfmon.exe, ctfmon.exe, ctfmon.exe
    O        O             0x0000bd058a1a8080        userinit.exe, userinit.exe
    O        O      O      0x0000bd058a2ae080    O   explorer.exe, explorer.exe, explorer.exe
    O        O             0x0000bd058a3430c0        svchost.exe, svchost.exe
    O        O      O      0x0000bd058a4ae280    O   SearchIndexer.exe, SearchIndexer., SearchIndexer.
    O        O      O      0x0000bd058a66d080    O   StartMenuExperienceHost.exe, StartMenuExper, StartMenuExper
    O        O             0x0000bd058a671440        RuntimeBroker.exe, RuntimeBroker.
    O        O      O      0x0000bd058a5e4080    O   SearchUI.exe, SearchUI.exe, SearchUI.exe
    O        O      O      0x0000bd058a961440    O   RuntimeBroker.exe, RuntimeBroker., RuntimeBroker.
    O        O             0x0000bd058abda440        SettingSyncHost.exe, SettingSyncHos
    O        O             0x0000bd058ac1c4c0        LockApp.exe, LockApp.exe
    O        O      O      0x0000bd058ac3a080    O   RuntimeBroker.exe, RuntimeBroker., RuntimeBroker.
    O        O      O      0x0000bd058a887080    O   backgroundTaskHost.exe, backgroundTask, backgroundTask
    O        O      O      0x0000bd058aeb2080    O   SecurityHealthSystray.exe, SecurityHealth, SecurityHealth
    O        O      O      0x0000bd058aebe280    O   SecurityHealthService.exe, SecurityHealth, SecurityHealth
    O        O      O      0x0000bd058aec8080    O   vm3dservice.exe, vm3dservice.ex, vm3dservice.ex
    O        O             0x0000bd058aafa080        vmtoolsd.exe, vmtoolsd.exe
    O        O      O      0x0000bd058aec1080    O   OneDrive.exe, OneDrive.exe, OneDrive.exe
    O        O             0x0000bd058a4b4080        RuntimeBroker.exe, RuntimeBroker.
    O        O             0x0000bd058b0d6080        ApplicationFrameHost.exe, ApplicationFra
    O        O             0x0000bd058aca1080        RuntimeBroker.exe, RuntimeBroker.
    O        O      O      0x0000bd058aaf4080    O   SystemSettings.exe, SystemSettings, SystemSettings
    O        O             0x0000bd0589be10c0        UserOOBEBroker.exe, UserOOBEBroker
    O        O      O      0x0000bd058ba0c280    O   svchost.exe, svchost.exe, svchost.exe
    O        O             0x0000bd0589380080        SgrmBroker.exe, SgrmBroker.exe
    O        O             0x0000bd058937c080        sppsvc.exe, sppsvc.exe
    O        O             0x0000bd0589256240        svchost.exe, svchost.exe
    O        O             0x0000bd058acad080        Microsoft.Photos.exe, Microsoft.Phot
    O        O             0x0000bd058a9a6080        RuntimeBroker.exe, RuntimeBroker.
    O        O             0x0000bd058a7ec080        svchost.exe, svchost.exe
    O        O             0x0000bd058b57f080        WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe, WindowsInterna
    O        O             0x0000bd058c31b080        msvsmon.exe, msvsmon.exe
    O        O             0x0000bd058ab5f080        msvsmon.exe, msvsmon.exe
    O        O             0x0000bd058ab5e080        msvsmon.exe, msvsmon.exe
    O        O             0x0000bd058a97c4c0        ShellExperienceHost.exe, ShellExperienc
    O        O             0x0000bd058cac9080        RuntimeBroker.exe, RuntimeBroker.
    O        O             0x0000bd058939b080        dllhost.exe, dllhost.exe
    O        O      O      0x0000bd058baa8080    O   msvsmon.exe, msvsmon.exe, msvsmon.exe
    O        O             0x0000bd0589e54080        StandardCollector.Service.exe, StandardCollec
    O        O             0x0000bd0589b40080        msedge.exe, msedge.exe
    O        O             0x0000bd058a386080        msedge.exe, msedge.exe
    O        O             0x0000bd058a29e080        msedge.exe, msedge.exe
    O        O      O      0x0000bd058c4b44c0    O   msvsmon.exe, msvsmon.exe, msvsmon.exe
    O        O      O      0x0000bd058c8d84c0    O   msvsmon.exe, msvsmon.exe, msvsmon.exe
    O        O      O      0x0000bd058aebf080    O   msvsmon.exe, msvsmon.exe, msvsmon.exe
    O        O             0x0000bd058b579080        msedge.exe, msedge.exe
    O        O      O      0x0000bd058ce10080    O   msedge.exe, msedge.exe, msedge.exe
    O        O             0x0000bd058bc81080        msvsmon.exe, msvsmon.exe
    O        O             0x0000bd0581ef1080        msvsmon.exe, msvsmon.exe
    O        O      O      0x0000bd05893b9080    O   msvsmon.exe, msvsmon.exe, msvsmon.exe
    O        O      O      0x0000bd058e22f480    O   msvsmon.exe, msvsmon.exe, msvsmon.exe
    O        O      O      0x0000bd058c4a70c0    O   msvsmon.exe, msvsmon.exe, msvsmon.exe
    O        O             0x0000bd058392c080        cmd.exe, cmd.exe
    O        O      O      0x0000bd0589b380c0    O   conhost.exe, conhost.exe, conhost.exe
    O        O             0x0000bd058cb744c0        Microsoft.Msn.News.exe, Microsoft.Msn.
    O        O      O      0x0000bd0595aa3440    O   RuntimeBroker.exe, RuntimeBroker., RuntimeBroker.
    O        O             0x0000bd05893bd080        YourPhone.exe, YourPhone.exe
    O        O             0x0000bd058a4bc080        RuntimeBroker.exe, RuntimeBroker.
    O        O             0x0000bd058d5f2080        SecurityHealthHost.exe, SecurityHealth
    O        O             0x0000bd0592b89080        TOTALCMD64.EXE, TOTALCMD64.EXE
    O        O      O      0x0000bd0595a904c0        svchost.exe, rekall.exe, svchost.exe
    O                      0x0000bd0592b77380        SearchProtocolHost.exe
    O                      0x0000bd0592b652c0        SearchFilterHost.exe
    O                      0x0000bd0594a8b080        RuntimeBroker.exe
    O                      0x0000bd058c250080        RuntimeBroker.exe
            O             0x0000bd0594a8b4c0        python.exe
    --------------------------------------------------
    107      104     51                         50
    ```

## win10 19041 Enterprise, WinDbg, PsList, PsScan 비교 

    ```
    WinDBG  PSList  PSScan  _EPROCESS
    O        O      O      0x0000e303c4e80040    O   System, System, System
    O        O      O      0x0000e303c4ed2080    O   Registry, Registry, Registry
    O        O             0x0000e303c5b4b080        smss.exe, smss.exe
    O        O             0x0000e303c5942140        csrss.exe, csrss.exe
    O        O      O      0x0000e303c7d34080    O   wininit.exe, wininit.exe, wininit.exe
    O        O             0x0000e303c7d830c0        csrss.exe, csrss.exe
    O        O             0x0000e303c8403080        winlogon.exe, winlogon.exe
    O        O             0x0000e303c840f080        services.exe, services.exe
    O        O      O      0x0000e303c8411080    O   lsass.exe, lsass.exe, lsass.exe
    O        O      O      0x0000e303c84a0140    O   fontdrvhost.exe, fontdrvhost.ex, fontdrvhost.ex
    O        O      O      0x0000e303c849e140    O   fontdrvhost.exe, fontdrvhost.ex, fontdrvhost.ex
    O        O      O      0x0000e303c84a2240    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303c852c2c0    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303c86372c0    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303c862e2c0    O   svchost.exe, svchost.exe, svchost.exe
    O        O             0x0000e303c863a080        dwm.exe, dwm.exe
    O        O             0x0000e303c863c080        LogonUI.exe, LogonUI.exe
    O        O      O      0x0000e303c86a4240    O   svchost.exe, svchost.exe, svchost.exe
    O        O             0x0000e303c86de2c0        svchost.exe, svchost.exe
    O        O      O      0x0000e303c86bd080    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303c8811080    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303c880f040    O   MemCompression, MemCompression, MemCompression
    O        O      O      0x0000e303c74cd240    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303c70de2c0    O   svchost.exe, svchost.exe, svchost.exe
    O        O             0x0000e303c89a90c0        svchost.exe, svchost.exe
    O        O      O      0x0000e303c4f75080    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303c4f73080    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303c4f69080    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303c4f33080    O   spoolsv.exe, spoolsv.exe, spoolsv.exe
    O        O      O      0x0000e303c4eec080    O   svchost.exe, svchost.exe, svchost.exe
    O        O             0x0000e303c8c40280        dasHost.exe, dasHost.exe
    O        O             0x0000e303c8c41080        svchost.exe, svchost.exe
    O        O      O      0x0000e303c8c93300    O   VGAuthService.exe, VGAuthService., VGAuthService.
    O        O             0x0000e303c8cb7280        vmtoolsd.exe, vmtoolsd.exe
    O        O      O      0x0000e303c8cb9340    O   MsMpEng.exe, MsMpEng.exe, MsMpEng.exe
    O        O             0x0000e303c8b2e280        WmiPrvSE.exe, WmiPrvSE.exe
    O        O             0x0000e303c8bca280        dllhost.exe, dllhost.exe
    O        O      O      0x0000e303c8fe9280    O   msdtc.exe, msdtc.exe, msdtc.exe
    O        O      O      0x0000e303c909a280    O   sihost.exe, sihost.exe, sihost.exe
    O        O             0x0000e303c909d2c0        svchost.exe, svchost.exe
    O        O             0x0000e303c90c62c0        taskhostw.exe, taskhostw.exe
    O        O      O      0x0000e303c90cd300    O   taskhostw.exe, taskhostw.exe, taskhostw.exe
    O        O      O      0x0000e303c900d280    O   ctfmon.exe, ctfmon.exe, ctfmon.exe
    O        O             0x0000e303c91a0340        userinit.exe, userinit.exe
    O        O      O      0x0000e303c9243080    O   explorer.exe, explorer.exe, explorer.exe
    O        O      O      0x0000e303c92850c0    O   svchost.exe, svchost.exe, svchost.exe
    O        O             0x0000e303c940b2c0        NisSrv.exe, NisSrv.exe
    O        O             0x0000e303c95ec300        svchost.exe, svchost.exe
    O        O             0x0000e303c9679300        StartMenuExperienceHost.exe, StartMenuExper
    O        O      O      0x0000e303c9742240    O   SearchIndexer.exe, SearchIndexer., SearchIndexer.
    O        O             0x0000e303c97cc0c0        LockApp.exe, LockApp.exe
    O        O      O      0x0000e303c9868300    O   RuntimeBroker.exe, RuntimeBroker., RuntimeBroker.
    O        O      O      0x0000e303c9909300    O   RuntimeBroker.exe, RuntimeBroker., RuntimeBroker.
    O        O             0x0000e303c99b7080        SearchApp.exe, SearchApp.exe
    O        O             0x0000e303c99f2080        RuntimeBroker.exe, RuntimeBroker.
    O        O      O      0x0000e303c9a94080    O   ApplicationFrameHost.exe, ApplicationFra, ApplicationFra
    O        O      O      0x0000e303c9bd1080    O   MicrosoftEdge.exe, MicrosoftEdge., MicrosoftEdge.
    O        O      O      0x0000e303c94020c0    O   RuntimeBroker.exe, RuntimeBroker., RuntimeBroker.
    O        O             0x0000e303c93d7300        RuntimeBroker.exe, RuntimeBroker.
    O        O      O      0x0000e303c9ed10c0    O   SecurityHealthSystray.exe, SecurityHealth, SecurityHealth
    O        O      O      0x0000e303c9929080    O   SecurityHealthService.exe, SecurityHealth, SecurityHealth
    O        O             0x0000e303c93d9340        vm3dservice.exe, vm3dservice.ex
    O        O             0x0000e303ca0a50c0        vmtoolsd.exe, vmtoolsd.exe
    O        O      O      0x0000e303c9960080    O   OneDrive.exe, OneDrive.exe, OneDrive.exe
    O        O      O      0x0000e303c9d69080    O   TextInputHost.exe, TextInputHost., TextInputHost.
    O        O             0x0000e303c970e300        dllhost.exe, dllhost.exe
    O        O      O      0x0000e303caa5e080    O   SgrmBroker.exe, SgrmBroker.exe, SgrmBroker.exe
    O        O      O      0x0000e303ca9a3080    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303ca18d080    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303c9957080    O   svchost.exe, svchost.exe, svchost.exe
    O        O             0x0000e303cc145340        MicrosoftEdge.exe, MicrosoftEdge.
    O        O      O      0x0000e303c8d96080    O   browser_broker.exe, browser_broker, browser_broker
    O        O             0x0000e303c9c5b080        MicrosoftEdgeSH.exe, MicrosoftEdgeS
    O        O             0x0000e303cc343080        MicrosoftEdgeCP.exe, MicrosoftEdgeC
    O        O             0x0000e303cc411340        Code.exe, Code.exe
    O        O      O      0x0000e303cc21c340    O   taskhostw.exe, taskhostw.exe, taskhostw.exe
    O        O      O      0x0000e303cc92a080    O   TOTALCMD64.EXE, TOTALCMD64.EXE, TOTALCMD64.EXE
    O        O      O      0x0000e303cc2c7080    O   ShellExperienceHost.exe, ShellExperienc, ShellExperienc
    O        O             0x0000e303c872d080        RuntimeBroker.exe, RuntimeBroker.
    O        O      O      0x0000e303cc7fb080    O   cmd.exe, cmd.exe, cmd.exe
    O        O             0x0000e303cdcc5300        conhost.exe, conhost.exe
    O        O      O      0x0000e303caa57080    O   svchost.exe, svchost.exe, svchost.exe
    O        O      O      0x0000e303cc2c3080    O   Microsoft.Photos.exe, Microsoft.Phot, Microsoft.Phot
    O        O      O      0x0000e303ca0a8080    O   RuntimeBroker.exe, RuntimeBroker., RuntimeBroker.
    O        O      O      0x0000e303cc91b080    O   svchost.exe, svchost.exe, svchost.exe
             O      O      0x0000e303c9c79080        rekal.exe, rekal.exe
             O      O      0x0000e303caa3a080        python.exe, python.exe
                    O      0x0000e303c4f3a080        git.exe
                    O      0x0000e303c9320080        SearchFilterHo
                    O      0x0000e303c93d2080        git.exe
                    O      0x0000e303cc07d080        taskhostw.exe
                    O      0x0000e303cc310080        git.exe
                    O      0x0000e303cc688080        git.exe
    --------------------------------------------------
    85      87     60                           52

    Process finished with exit code 0

    ```

## winpmem driver 관련
+ 2020.10.09 일 현재 
  - rekall 의 winpmem 버전은 `#define PMEM_VERSION "v1.6.3"`  (https://github.com/google/rekall)
  - 개발자의 최신 버전은 `#define PMEM_DRIVER_VERSION "2.0.1"`  (https://github.com/Velocidex/WinPmem)
  - 두 드라이버 호환 안됨
  - 많은 부분에서 변경이 있고, 개선된 버전으로 보임 (예외처리 코드등)
  - python 도구는 현재 개발중, user mode exe 프로그램은 개발 완료 되었으나 테스트 안해봤음
  - 아무튼 이전 버전의 rekall 과는 호환되지 않음
+ https://github.com/somma-inc/rekall/commit/d410e5adbce10f737096eaab4b0a88caa1889cd9 커밋에서 수정 완료


## _OBJECT_HEADER.TypeIndex 관련 리서치

- https://medium.com/@ashabdalhalim/a-light-on-windows-10s-object-header-typeindex-value-e8f907e7073a

    ```
    0: kd> dt _object_header -v
    nt!_OBJECT_HEADER
    struct _OBJECT_HEADER, 23 elements, 0x38 bytes
    +0x000 PointerCount     : Int8B
    +0x008 HandleCount      : Int8B
    +0x008 NextToFree       : Ptr64 to Void
    +0x010 Lock             : struct _EX_PUSH_LOCK, 7 elements, 0x8 bytes
    +0x018 TypeIndex        : UChar                                                      <<!!!>>
    +0x019 TraceFlags       : UChar
    +0x019 DbgRefTrace      : Bitfield Pos 0, 1 Bit
    +0x019 DbgTracePermanent : Bitfield Pos 1, 1 Bit
    +0x01a InfoMask         : UChar
    +0x01b Flags            : UChar
    +0x01b NewObject        : Bitfield Pos 0, 1 Bit
    +0x01b KernelObject     : Bitfield Pos 1, 1 Bit
    +0x01b KernelOnlyAccess : Bitfield Pos 2, 1 Bit
    +0x01b ExclusiveObject  : Bitfield Pos 3, 1 Bit
    +0x01b PermanentObject  : Bitfield Pos 4, 1 Bit
    +0x01b DefaultSecurityQuota : Bitfield Pos 5, 1 Bit
    +0x01b SingleHandleEntry : Bitfield Pos 6, 1 Bit
    +0x01b DeletedInline    : Bitfield Pos 7, 1 Bit
    +0x01c Reserved         : Uint4B
    +0x020 ObjectCreateInfo : Ptr64 to struct _OBJECT_CREATE_INFORMATION, 9 elements, 0x40 bytes
    +0x020 QuotaBlockCharged : Ptr64 to Void
    +0x028 SecurityDescriptor : Ptr64 to Void
    +0x030 Body             : struct _QUAD, 2 elements, 0x8 bytes                


    0: kd> dps nt!ObTypeIndexTable
    fffff803`22a2cd80  00000000`00000000
    fffff803`22a2cd88  ffffa180`5758e000
    fffff803`22a2cd90  ffff830d`a0ccd4e0
    fffff803`22a2cd98  ffff830d`a0ccd640
    fffff803`22a2cda0  ffff830d`a0ccd7a0
    fffff803`22a2cda8  ffff830d`a0ccda60
    fffff803`22a2cdb0  ffff830d`a0ccd900
    fffff803`22a2cdb8  ffff830d`a0ccde80
    fffff803`22a2cdc0  ffff830d`a0cd4980
    fffff803`22a2cdc8  ffff830d`a0cd30c0
    fffff803`22a2cdd0  ffff830d`a0cd3640
    fffff803`22a2cdd8  ffff830d`a0cd3900
    fffff803`22a2cde0  ffff830d`a0cd3220
    fffff803`22a2cde8  ffff830d`a0cd3d20
    fffff803`22a2cdf0  ffff830d`a0cd3a60
    fffff803`22a2cdf8  ffff830d`a0cd4140


    0: kd> dt _OBJECT_TYPE ffffbd05`81e3f620 -s
    nt!_OBJECT_TYPE
    +0x000 TypeList         : _LIST_ENTRY [ 0xffffbd05`81e3f620 - 0xffffbd05`81e3f620 ]
    +0x010 Name             : _UNICODE_STRING "Directory"
    +0x020 DefaultObject    : 0xfffff805`64065a00 Void
    +0x028 Index            : 0x3 ''
    +0x02c TotalNumberOfObjects : 0x48
    +0x030 TotalNumberOfHandles : 0x104
    +0x034 HighWaterNumberOfObjects : 0x56
    +0x038 HighWaterNumberOfHandles : 0x152
    +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
    +0x0b8 TypeLock         : _EX_PUSH_LOCK
    +0x0c0 Key              : 0x65726944
    +0x0c8 CallbackList     : _LIST_ENTRY [ 0xffffbd05`81e3f6e8 - 0xffffbd05`81e3f6e8 ]

    0: kd> dt _OBJECT_TYPE ffffbd05`81e3fcd0 -s
    nt!_OBJECT_TYPE
    +0x000 TypeList         : _LIST_ENTRY [ 0xffffbd05`81e3fcd0 - 0xffffbd05`81e3fcd0 ]
    +0x010 Name             : _UNICODE_STRING "SymbolicLink"
    +0x020 DefaultObject    : 0xfffff805`64065a00 Void
    +0x028 Index            : 0x4 ''
    +0x02c TotalNumberOfObjects : 0x125
    +0x030 TotalNumberOfHandles : 0x85
    +0x034 HighWaterNumberOfObjects : 0x134
    +0x038 HighWaterNumberOfHandles : 0x9a
    +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
    +0x0b8 TypeLock         : _EX_PUSH_LOCK
    +0x0c0 Key              : 0x626d7953
    +0x0c8 CallbackList     : _LIST_ENTRY [ 0xffffbd05`81e3fd98 - 0xffffbd05`81e3fd98 ]
    ```

+ `!poolfind` 로 찾은 pool 의 type 을 찾아보자

    ```
    0: kd> !poolfind -tag Proc -nonpaged
    ...
    ffff830da0ce8010 : tag Proc, size     0xc70, Nonpaged pool
    ...
    ```

+ 1 번 pool, `ffff830da0ce8010` 추적        
    ```
    1: kd> dt _OBJECT_HEADER -s
    nt!_OBJECT_HEADER
    +0x000 PointerCount     : Int8B
    +0x008 HandleCount      : Int8B
    +0x008 NextToFree       : Ptr64 Void
    +0x010 Lock             : _EX_PUSH_LOCK
    +0x018 TypeIndex        : UChar             <<!>>
    +0x019 TraceFlags       : UChar
    +0x019 DbgRefTrace      : Pos 0, 1 Bit
    +0x019 DbgTracePermanent : Pos 1, 1 Bit
    +0x01a InfoMask         : UChar
    +0x01b Flags            : UChar
    +0x01b NewObject        : Pos 0, 1 Bit
    +0x01b KernelObject     : Pos 1, 1 Bit
    +0x01b KernelOnlyAccess : Pos 2, 1 Bit
    +0x01b ExclusiveObject  : Pos 3, 1 Bit
    +0x01b PermanentObject  : Pos 4, 1 Bit
    +0x01b DefaultSecurityQuota : Pos 5, 1 Bit
    +0x01b SingleHandleEntry : Pos 6, 1 Bit
    +0x01b DeletedInline    : Pos 7, 1 Bit
    +0x01c Reserved         : Uint4B
    +0x020 ObjectCreateInfo : Ptr64 _OBJECT_CREATE_INFORMATION
    +0x020 QuotaBlockCharged : Ptr64 Void
    +0x028 SecurityDescriptor : Ptr64 Void
    +0x030 Body             : _QUAD


    0: kd> dt _OBJECT_HEADER ffff830da0ce8010 -s
    nt!_OBJECT_HEADER
    +0x000 PointerCount     : 0n0
    +0x008 HandleCount      : 0n-137380385956880
    +0x008 NextToFree       : 0xffff830d`a2e55bf0 Void
    +0x010 Lock             : _EX_PUSH_LOCK
    +0x018 TypeIndex        : 0x28 '('          <<!>>
    +0x019 TraceFlags       : 0x80 ''
    +0x019 DbgRefTrace      : 0y0
    +0x019 DbgTracePermanent : 0y0
    +0x01a InfoMask         : 0xce ''
    +0x01b Flags            : 0xa0 ''
    +0x01b NewObject        : 0y0
    +0x01b KernelObject     : 0y0
    +0x01b KernelOnlyAccess : 0y0
    +0x01b ExclusiveObject  : 0y0
    +0x01b PermanentObject  : 0y0
    +0x01b DefaultSecurityQuota : 0y1
    +0x01b SingleHandleEntry : 0y0
    +0x01b DeletedInline    : 0y1
    +0x01c Reserved         : 0x20
    +0x020 ObjectCreateInfo : 0x00000a88`00001000 _OBJECT_CREATE_INFORMATION
    +0x020 QuotaBlockCharged : 0x00000a88`00001000 Void
    +0x028 SecurityDescriptor : 0x00000000`0000006c Void
    +0x030 Body             : _QUAD

    ```

+ `TypeIndex` 값은 인코딩 되어있으며 디코딩 루틴은 `nt!ObGetObjectType` 함수를 리버싱해서 알아낸다.

    ```
    1: kd> uf nt!ObGetObjectType
    nt!ObGetObjectType:
    fffff805`641fcb20 488d41d0        lea     rax,[rcx-30h]
    fffff805`641fcb24 0fb649e8        movzx   ecx,byte ptr [rcx-18h]
    fffff805`641fcb28 48c1e808        shr     rax,8
    fffff805`641fcb2c 0fb6c0          movzx   eax,al
    fffff805`641fcb2f 4833c1          xor     rax,rcx
    fffff805`641fcb32 0fb60d475bf9ff  movzx   ecx,byte ptr [nt!ObHeaderCookie (fffff805`64192680)]
    fffff805`641fcb39 4833c1          xor     rax,rcx
    fffff805`641fcb3c 488d0d3d62f9ff  lea     rcx,[nt!ObTypeIndexTable (fffff805`64192d80)]
    fffff805`641fcb43 488b04c1        mov     rax,qword ptr [rcx+rax*8]
    fffff805`641fcb47 c3              ret

    0: kd> db nt!ObHeaderCookie l1
    fffff803`22a2c680  a0 
    ```

+ ObTypeIndexTable[`Object 의 주소 하위 두번째 바이트` xor `ObHeaderCookie` xor `TypeIndex`]
    ```
    int64_t ObGetObjectType(uint64_t object_address)
    {
        POBJECT_HEADER ObjectHeader = CONTAINING_RECORD(object_address, OBJECT_HEADER, Body);   // rcx-30h
        char TypeIndex = ObjectHeader->TypeIndex;           // rcx-18h
        int8_t value = (int8_t)(ObjectHeader >> 8);
        return (int64_t) ObTypeIndexTable[ntObHeaderCookie ^ value ^ TypeIndex];
    }
    ```

+ Object 의 주소는 `ffff830da0ce8010` 이므로 `0x80` ^ `0xa0` ^ `0x28` 식으로 디코딩하면 됨 (엥..!! Proc 이 아니라 Thread?!)

    ```
    0: kd> ? 0x80 ^ 0xa0 ^ 0x28
    Evaluate expression: 8 = 00000000`00000008

    0: kd> dt nt!_OBJECT_TYPE poi(nt!ObTypeIndexTable + (8*8))
    +0x000 TypeList         : _LIST_ENTRY [ 0xffff830d`a0cd4980 - 0xffff830d`a0cd4980 ]
    +0x010 Name             : _UNICODE_STRING "Thread"      <<!>>
    +0x020 DefaultObject    : (null) 
    +0x028 Index            : 0x8 ''
    +0x02c TotalNumberOfObjects : 0x525
    +0x030 TotalNumberOfHandles : 0x745
    +0x034 HighWaterNumberOfObjects : 0x607
    +0x038 HighWaterNumberOfHandles : 0x822
    +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
    +0x0b8 TypeLock         : _EX_PUSH_LOCK
    +0x0c0 Key              : 0x65726854
    +0x0c8 CallbackList     : _LIST_ENTRY [ 0xffff830d`a0cd4a48 - 0xffff830d`a0cd4a48 ]

    ```


## `_OBJECT_HEADER.InfoMask` 관련 리서치
- https://codemachine.com/article_objectheader.html
- The Art of Memory Forensics (Wiley)

  ```
  1: kd> dt _object_header
  nt!_OBJECT_HEADER
    +0x000 PointerCount     : Int8B
    +0x008 HandleCount      : Int8B
    +0x008 NextToFree       : Ptr64 Void
    +0x010 Lock             : _EX_PUSH_LOCK
    +0x018 TypeIndex        : UChar
    +0x019 TraceFlags       : UChar
    +0x019 DbgRefTrace      : Pos 0, 1 Bit
    +0x019 DbgTracePermanent : Pos 1, 1 Bit
    +0x01a InfoMask         : UChar              <<!>>
    +0x01b Flags            : UChar
    +0x01b NewObject        : Pos 0, 1 Bit
    +0x01b KernelObject     : Pos 1, 1 Bit
    +0x01b KernelOnlyAccess : Pos 2, 1 Bit
    +0x01b ExclusiveObject  : Pos 3, 1 Bit
    +0x01b PermanentObject  : Pos 4, 1 Bit
    +0x01b DefaultSecurityQuota : Pos 5, 1 Bit
    +0x01b SingleHandleEntry : Pos 6, 1 Bit
    +0x01b DeletedInline    : Pos 7, 1 Bit
    +0x01c Reserved         : Uint4B
    +0x020 ObjectCreateInfo : Ptr64 _OBJECT_CREATE_INFORMATION
    +0x020 QuotaBlockCharged : Ptr64 Void
    +0x028 SecurityDescriptor : Ptr64 Void
    +0x030 Body             : _QUAD

  0: kd> dt nt!_OBJECT_HEADER_*
            ntkrnlmp!_OBJECT_HEADER_QUOTA_INFO
            ntkrnlmp!_OBJECT_HEADER_PROCESS_INFO
            ntkrnlmp!_OBJECT_HEADER_HANDLE_INFO
            ntkrnlmp!_OBJECT_HEADER_NAME_INFO
            ntkrnlmp!_OBJECT_HEADER_CREATOR_INFO
            ntkrnlmp!_OBJECT_HEADER_AUDIT_INFO
            ntkrnlmp!_OBJECT_HEADER_EXTENDED_INFO
            ntkrnlmp!_OBJECT_HEADER_PADDING_INFO
            OBJECT_HEADER_TO_HANDLE_REVOCATION_INFO
  ```

+ `ffffd08810a83010` pool 분석
  - 0xffffd08810a83010 를 0x10 alignment 를 맞추고 `_POOL_HEADER` 로 캐스팅
  - x64 에서 pool allocation alignment 가 0x10 인가봄
  
  ```python
  
  # volatility3.poolscanner.py 참고
  class PoolScanner(plugins.PluginInterface):
    ...
    @classmethod
      def generate_pool_scan(cls,
                            context: interfaces.context.ContextInterface,
                            layer_name: str,
                            symbol_table: str,
                            constraints: List[PoolConstraint]) 
              -> Generator[Tuple[
                              PoolConstraint, interfaces.objects.ObjectInterface, interfaces.objects.ObjectInterface], None, None]:
          ...
          if symbols.symbol_table_is_64bit(context, symbol_table):
              alignment = 0x10
          else:
              alignment = 8
  ```


  ```
  Pool page ffffd08810a83010 region is Nonpaged pool
  *ffffd08810a83000 size:  c80 previous size:    0  (Allocated) *Proc
      Pooltag Proc : Process objects, Binary : nt!ps

  0: kd> ?? 0xffffd08810a83010  & ~0x10
  unsigned int64 0xffffd088`10a83000

  0: kd> dt nt!_pool_header 0xffffd088`10a83000 -s
    +0x000 PreviousSize     : 0y00000000 (0)
    +0x000 PoolIndex        : 0y00000000 (0)
    +0x002 BlockSize        : 0y11001000 (0xc8)

        `PoolAlignment` x BlockSize 한 값이 실제 allocation size 

        _POOL_HEADER.IterObject() 참고
          ...
          pool_align = self.obj_profile.get_constant("PoolAlignment")
          allocation_size = self.BlockSize * pool_align
          ...

    +0x002 PoolType         : 0y00000010 (0x2)
    +0x000 Ulong1           : 0x2c80000
    +0x004 PoolTag          : 0x636f7250        <<!>> 'corP'
    +0x008 ProcessBilled    : (null) 
    +0x008 AllocatorBackTraceIndex : 0
    +0x00a PoolTagHash      : 0
  ```

  - `!pool` 명령 결과와 동일함을 확인
  ```
  0: kd> !pool 0xffffd088`10a83000
  Pool page ffffd08810a83000 region is Nonpaged pool
  *ffffd08810a83000 size:  c80 previous size:    0  (Allocated) *Proc
      Pooltag Proc : Process objects, Binary : nt!ps

  ```



## _EPROCESS 에서 _POOL_HEADER 찾아가기

+ Target Windows 10 18362 build
    ```
    1: kd> vertarget
    Windows 10 Kernel Version 18362 MP (2 procs) Free x64
    Product: WinNt, suite: TerminalServer SingleUserTS
    Edition build lab: 18362.1.amd64fre.19h1_release.190318-1202
    Machine Name:
    Kernel base = 0xfffff800`124c1000 PsLoadedModuleList = 0xfffff800`129071b0
    Debug session time: Sun Nov  1 20:51:00.790 2020 (UTC + 9:00)
    System Uptime: 3 days 21:49:28.994
    ```


+ `_OBJECT_HEADER` 구조 이해하기
    + `_OBJECT_HEADER.InfoMask` 를 아래 식으로 디코딩하면 유효한 Optional Header 의 오프셋을 구할 수 있음
    
        ```
        nt!ObpInfoMaskToOffset[InfoMask & (DesiredHeaderBit | (DesiredHeaderBit -1))]
        ```
    
    + `DesiredHeaderBit` 상수 정의 (Optional header 관련 상수값)

        ```c++
        #define OB_INFOMASK_PADDING_INFO        0x80

        NtBuildNumber == NT_WIN10_THRESHOLD2
            #define OB_INFOMASK_REOVOCATION_INFO        0x40    
        else
            #define OB_INFOMASK_HEADER_EXTENDED_INFO    0x40

        NtBuildNumber < NT_WIN8_RTM
            #define OB_INFOMASK_PADDING_INFO    0x20    
        else
            #define OB_INFOMASK_AUDIO_INFO      0x20

        #define OB_INFOMASK_PROCESS_INFO    0x10
        #define OB_INFOMASK_QUOTA           0x08
        #define OB_INFOMASK_HANDLE          0x04
        #define OB_INFOMASK_NAME            0x02
        #define OB_INFOMASK_CREATOR_INFO    0x01
        ```

## Optional Header 중 `_OBJECT_HEADER_PADDING_INFO.PaddingAmount` 값 계산식 이해하기
- `_POOL_HEADER` 와 `_OBJECT_HEADER` 사이에 패딩이 얼마만큼 있는지 나타내는 값
- `_OBJECT_HEADER` 주소는 `0xffffd488800752d0` 이고, `InfoMask = 0x80` 일때
    - Optional header 는 `OB_INFOMASK_PADDING_INFO` 를 가짐
    - `?? ((unsigned char *)@@masm(nt!ObpInfoMaskToOffset))[0x80 & (0x80 | (0x80-1))]` 계산을 통해 Offset 은 `0x04`
    - `_OBJECT_HEADER` 주소는 `0xffffd488800752d0` - `0x04` 에 `_OBJECT_HEADER_PADDING_INFO` 구조체가 위치함을 의미함

    ```
    1: kd> ?? ((unsigned char *)@@masm(nt!ObpInfoMaskToOffset))[0x80 & (0x80 | (0x80-1))]
    unsigned char 0x04 ''
    1: kd> dt nt!_OBJECT_HEADER_PADDING_INFO (0xffffd488800752d0-0x04)
    +0x000 PaddingAmount    : 0x30
    ```

    - `_OBJECT_HEADER_PADDING_INFO.PaddingAmount = 0x30` 이므로 

    ```
    1: kd> ? 0xffffd488800752d0 - 0x30 - @@(sizeof(nt!_POOL_HEADER))
    Evaluate expression: -47792248106352 = ffffd488`80075290
    
    ```

    - `_POOL_HEADER` 의 주소는 `0xffffd48880075290` 임

    ```
    1: kd> dt nt!_POOL_HEADER 0xffffd48880075290
    +0x000 PreviousSize     : 0y00000000 (0)
    +0x000 PoolIndex        : 0y11001111 (0xcf)
    +0x002 BlockSize        : 0y11001000 (0xc8)
    +0x002 PoolType         : 0y00000010 (0x2)
    +0x000 Ulong1           : 0x2c8cf00
    +0x004 PoolTag          : 0x636f7250
    +0x008 ProcessBilled    : 0xffffd488`8005bce8 _EPROCESS
    +0x008 AllocatorBackTraceIndex : 0xbce8
    +0x00a PoolTagHash      : 0x8005
    ```

## `system` 프로세스의 `_POOL_HEADER` 찾기

- `0xffffd48880075290	0x00000c80	Proc	0xffffd48880075300	0x00000004	System`

    ```
    -003c   +0000   0xffffd48880075290      +0000   _POOL_HEADER (struct _POOL_HEADER, 9 elements, 0x10 bytes)                                        
                                            +0x000 PreviousSize     : Bitfield Pos 0, 8 Bits
                                            +0x000 PoolIndex        : Bitfield Pos 8, 8 Bits
                                            +0x002 BlockSize        : Bitfield Pos 0, 8 Bits
                                            +0x002 PoolType         : Bitfield Pos 8, 8 Bits
                                            +0x000 Ulong1           : Uint4B
                                            +0x004 PoolTag          : Uint4B
                                            +0x008 ProcessBilled    : Ptr64 to struct _EPROCESS, 226 elements, 0x880 bytes
                                            +0x008 AllocatorBackTraceIndex : Uint2B
                                            +0x00a PoolTagHash      : Uint2B

    -0004   +003c   0xffffd488800752cc      +0000   _OBJECT_HEADER_PADDING_INFO
                                            +0000   PaddingAmount   0x30

    -0030   +0040   0xffffd488800752d0      +0000   OBJECT_HEADER
                                            +0018   TypeIndex       0x18    -> 0x07 (Process object)
                                            +001a   InfoMask        0x80    -> OB_INFOMASK_PADDING_INFO
                                                padding offset      = 0x04 


    +0000   +0070   0xffffd48880075300      +0000   EPROCESS
    ```


## `svchost.exe` 의 `_POOL_HEADER` 찾기
- `0xffffd48880151000	0x00000b80	Proc	0xffffd48880151080	0x00000694	svchost.exe`

    ```
    -0080   +0000   0xffffd48880151000      nt!_pool_header (struct _POOL_HEADER, 9 elements, 0x10 bytes)
                                            +0x000 PreviousSize     : Bitfield 0y00000000 (0)
                                            +0x000 PoolIndex        : Bitfield 0y00000000 (0)
                                            +0x002 BlockSize        : Bitfield 0y10111000 (0xb8)
                                            +0x002 PoolType         : Bitfield 0y00000010 (0x2)
                                            +0x000 Ulong1           : 0x2b80000
                                            +0x004 PoolTag          : 0x636f7250
                                            +0x008 ProcessBilled    : (null) 
                                            +0x008 AllocatorBackTraceIndex : 0
                                            +0x00a PoolTagHash      : 0

    -0054   +002c   0xffffd4888015102c      nt!_OBJECT_HEADER_PADDING_INFO (struct _OBJECT_HEADER_PADDING_INFO, 1 elements, 0x4 bytes)
                                            +0x000 PaddingAmount    : 0x20
                                            
    -0050   +0030   0xffffd48880151030      nt!_OBJECT_HEADER_QUOTA_INFO (struct _OBJECT_HEADER_QUOTA_INFO, 6 elements, 0x20 bytes)
                                            +0x000 PagedPoolCharge  : 0x20
                                            +0x004 NonPagedPoolCharge : 0x1000
                                            +0x008 SecurityDescriptorCharge : 0xa88
                                            +0x00c Reserved1        : 0x48
                                            +0x010 SecurityDescriptorQuotaBlock : 0x1292c540`00000f78 Void
                                            +0x018 Reserved2        : 0x80151078`fffff800

    -0030   +0050   0xffffd48880151050      nt!_object_header (struct _OBJECT_HEADER, 23 elements, 0x38 bytes)
                                            +0018   TypeIndex       0x5a    -> 0x07 (Process object)
                                            +001a   InfoMask        0x88    -> OB_INFOMASK_QUOTA, OB_INFOMASK_PADDING_INFO
                                                quota offset    = 0x20 (?? ((unsigned char *)@@masm(nt!ObpInfoMaskToOffset))[0x88 & (0x8 | (0x8-1))])
                                                padding offset  = 0x24 (0: kd> ?? ((unsigned char *)@@masm(nt!ObpInfoMaskToOffset))[0x88 & (0x80 | (0x80-1))])

    +0000  +0080    0xffffd48880151080      +0000   EPROCESS (0x880 bytes)
    ```


