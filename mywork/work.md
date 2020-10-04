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




## todo - ing

poolfind 결과와 psscan() 에서 스캔대상으로 잡은 pool 영역 (pool header) 가 왜 일치하지 않는지 알아내라


0: kd> !poolfind -tag Proc -nonpaged

Scanning large pool allocation table for tag 0x636f7250 (Proc) (ffff830da1e60000 : ffff830da1f20000)


Searching nonpaged pool (ffff830000000000 : ffff930000000000) for tag 0x636f7250 (Proc)

ffff830da0ce8010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da0d3a010 : tag Proc, size     0xaf0, Nonpaged pool
ffff830da0d80010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da0d82010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da0dc8010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da0dcf010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da35c9010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da6faa010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da7608010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da7ee0010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da848d010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da86dc010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da88ae010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da88cd010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da88ce010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da88e0010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da88e4010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da92d1010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da931b010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da932d010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da972b010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da9a3f010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da9bc9010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da9cd4010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da9de9010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da9e68010 : tag Proc, size     0xb70, Nonpaged pool
ffff830da9ecb010 : tag Proc, size     0xb70, Nonpaged pool
ffff830daa19f010 : tag Proc, size     0xb70, Nonpaged pool
ffff830daa1a7010 : tag Proc, size     0xb70, Nonpaged pool
ffff830daa1bd010 : tag Proc, size     0xb70, Nonpaged pool
ffff830daa1cf010 : tag Proc, size     0xb70, Nonpaged pool
ffff830daa329010 : tag Proc, size     0xb70, Nonpaged pool
ffff830daab85010 : tag Proc, size     0xb70, Nonpaged pool
ffff830daabf0010 : tag Proc, size     0xb70, Nonpaged pool
ffff830daade2010 : tag Proc, size     0xb70, Nonpaged pool
ffff830dab6b6010 : tag Proc, size     0xb70, Nonpaged pool




-----

0: kd> !py _process_list.py
EPROCESS=0xffff830da0c79340, pid=4, image_name=System
EPROCESS=0xffff830da0ca4080, pid=128, image_name=Registry
EPROCESS=0xffff830da0ce8080, pid=4360, image_name=conhost.exe
EPROCESS=0xffff830da0d3a040, pid=1492, image_name=MemCompression
EPROCESS=0xffff830da0d80080, pid=2152, image_name=python.exe
EPROCESS=0xffff830da0d82080, pid=1436, image_name=svchost.exe
EPROCESS=0xffff830da0dc8080, pid=1708, image_name=svchost.exe
EPROCESS=0xffff830da0dcf080, pid=1700, image_name=svchost.exe
EPROCESS=0xffff830da33e4080, pid=384, image_name=smss.exe
EPROCESS=0xffff830da35b22c0, pid=2132, image_name=svchost.exe
EPROCESS=0xffff830da35c9080, pid=2252, image_name=VGAuthService.
EPROCESS=0xffff830da35cd2c0, pid=2156, image_name=svchost.exe
EPROCESS=0xffff830da35f00c0, pid=468, image_name=csrss.exe
EPROCESS=0xffff830da6f570c0, pid=560, image_name=csrss.exe
EPROCESS=0xffff830da6faa080, pid=692, image_name=lsass.exe
EPROCESS=0xffff830da7608080, pid=544, image_name=wininit.exe
EPROCESS=0xffff830da766d380, pid=644, image_name=winlogon.exe
EPROCESS=0xffff830da7675100, pid=680, image_name=services.exe
EPROCESS=0xffff830da76d80c0, pid=864, image_name=fontdrvhost.ex
EPROCESS=0xffff830da77051c0, pid=788, image_name=fontdrvhost.ex
EPROCESS=0xffff830da770c2c0, pid=800, image_name=svchost.exe
EPROCESS=0xffff830da7798340, pid=928, image_name=svchost.exe
EPROCESS=0xffff830da7e0e100, pid=1012, image_name=LogonUI.exe
EPROCESS=0xffff830da7e10080, pid=1020, image_name=dwm.exe
EPROCESS=0xffff830da7e762c0, pid=744, image_name=svchost.exe
EPROCESS=0xffff830da7e8a340, pid=712, image_name=svchost.exe
EPROCESS=0xffff830da7e9f340, pid=972, image_name=svchost.exe
EPROCESS=0xffff830da7ede2c0, pid=1088, image_name=svchost.exe
EPROCESS=0xffff830da7ee0080, pid=5128, image_name=ApplicationFra
EPROCESS=0xffff830da7f40340, pid=1148, image_name=svchost.exe
EPROCESS=0xffff830da8055340, pid=1348, image_name=svchost.exe
EPROCESS=0xffff830da80b6340, pid=1576, image_name=svchost.exe
EPROCESS=0xffff830da8319280, pid=1812, image_name=spoolsv.exe
EPROCESS=0xffff830da831e3c0, pid=1860, image_name=svchost.exe
EPROCESS=0xffff830da848d080, pid=2280, image_name=vmtoolsd.exe
EPROCESS=0xffff830da84df340, pid=2040, image_name=svchost.exe
EPROCESS=0xffff830da86dc080, pid=6440, image_name=sppsvc.exe
EPROCESS=0xffff830da86ee4c0, pid=3676, image_name=rekal.exe
EPROCESS=0xffff830da88cd080, pid=4556, image_name=cmd.exe
EPROCESS=0xffff830da88ce080, pid=5316, image_name=python.exe
EPROCESS=0xffff830da88e0080, pid=4328, image_name=audiodg.exe
EPROCESS=0xffff830da88e4080, pid=5968, image_name=cmd.exe
EPROCESS=0xffff830da89d1300, pid=2196, image_name=dasHost.exe
EPROCESS=0xffff830da8b193c0, pid=2364, image_name=MsMpEng.exe
EPROCESS=0xffff830da8b240c0, pid=2384, image_name=svchost.exe
EPROCESS=0xffff830da8e130c0, pid=2776, image_name=WmiPrvSE.exe
EPROCESS=0xffff830da8f71300, pid=2852, image_name=dllhost.exe
EPROCESS=0xffff830da91ac300, pid=3204, image_name=msdtc.exe
EPROCESS=0xffff830da9229400, pid=3096, image_name=NisSrv.exe
EPROCESS=0xffff830da927b400, pid=3340, image_name=sihost.exe
EPROCESS=0xffff830da927d440, pid=3360, image_name=svchost.exe
EPROCESS=0xffff830da92d1080, pid=3504, image_name=taskhostw.exe
EPROCESS=0xffff830da931b080, pid=5636, image_name=svchost.exe
EPROCESS=0xffff830da932d080, pid=3624, image_name=userinit.exe
EPROCESS=0xffff830da93764c0, pid=4876, image_name=WinStore.App.e
EPROCESS=0xffff830da93780c0, pid=3664, image_name=explorer.exe
EPROCESS=0xffff830da94de440, pid=3920, image_name=svchost.exe
EPROCESS=0xffff830da96720c0, pid=4024, image_name=SearchIndexer.
EPROCESS=0xffff830da972b080, pid=4208, image_name=StartMenuExper
EPROCESS=0xffff830da9732300, pid=4184, image_name=WmiPrvSE.exe
EPROCESS=0xffff830da98044c0, pid=5904, image_name=conhost.exe
EPROCESS=0xffff830da9820480, pid=5516, image_name=MusNotifyIcon.
EPROCESS=0xffff830da993b480, pid=4320, image_name=RuntimeBroker.
EPROCESS=0xffff830da9a3f080, pid=5076, image_name=fsnotifier64.e
EPROCESS=0xffff830da9bc70c0, pid=4676, image_name=RuntimeBroker.
EPROCESS=0xffff830da9bc9080, pid=1032, image_name=SearchUI.exe
EPROCESS=0xffff830da9bca4c0, pid=4788, image_name=dllhost.exe
EPROCESS=0xffff830da9ccf240, pid=4916, image_name=YourPhone.exe
EPROCESS=0xffff830da9cd4080, pid=6480, image_name=smartscreen.ex
EPROCESS=0xffff830da9cdc300, pid=5712, image_name=SecurityHealth
EPROCESS=0xffff830da9d34480, pid=5112, image_name=SettingSyncHos
EPROCESS=0xffff830da9d902c0, pid=5644, image_name=SecurityHealth
EPROCESS=0xffff830da9de9080, pid=2204, image_name=RuntimeBroker.
EPROCESS=0xffff830da9e68080, pid=876, image_name=LockApp.exe
EPROCESS=0xffff830da9ecb080, pid=656, image_name=pycharm64.exe
EPROCESS=0xffff830da9ed4480, pid=2736, image_name=RuntimeBroker.
EPROCESS=0xffff830daa19f080, pid=5756, image_name=vm3dservice.ex
EPROCESS=0xffff830daa1a7080, pid=5820, image_name=vmtoolsd.exe
EPROCESS=0xffff830daa1bd080, pid=3500, image_name=RuntimeBroker.
EPROCESS=0xffff830daa1c9340, pid=5872, image_name=OneDrive.exe
EPROCESS=0xffff830daa1cf080, pid=4308, image_name=SgrmBroker.exe
EPROCESS=0xffff830daa1fd400, pid=4672, image_name=ctfmon.exe
EPROCESS=0xffff830daabf0080, pid=6608, image_name=cmd.exe
EPROCESS=0xffff830dab6b6080, pid=6192, image_name=WindowsInterna
EPROCESS=0xffff830dab86b0c0, pid=6692, image_name=MicrosoftEdgeU


>>> psscan() 로그

2020-10-05 04:44:22,945:INFO:rekall.1:Scanning in: Pool NonPagedPool. [0x830000000000-0x930000000000]
2020-10-05 04:44:22,945:DEBUG:rekall.1:somma, run=0x830000000000->0x930000000000, type=Pool NonPagedPool
2020-10-05 04:44:22,945:DEBUG:rekall.1:somma, self.kernel=0x800000000000, checks=[('PoolTagCheck', {'tag': b'Proc'}), ('CheckPoolSize', {'min_size': 2176}), ('CheckPoolType', {'paged': True, 'non_paged': True, 'free': True}), ('CheckPoolIndex', {'value': 0})]
2020-10-05 04:44:23,632:DEBUG:rekall.1:[!] pool=0x0000830da0e9a7d5, eprocess=0x0000830da0e9a805
2020-10-05 04:44:23,632:DEBUG:rekall.1:[!] eprocess=0x0000830da0e9a805, pid=0, , invalid flink=None, blink=None
2020-10-05 04:44:23,647:DEBUG:rekall.1:[!] pool=0x0000830da0e9a71d, eprocess=0x0000830da0e9a74d
2020-10-05 04:44:23,647:DEBUG:rekall.1:[!] eprocess=0x0000830da0e9a74d, pid=1734437731, \x94\xf1K\x9d{\x01M\x86L\xf7\x1fg, invalid flink=None, blink=None
2020-10-05 04:44:25,116:DEBUG:rekall.1:[!] pool=0x0000830da35b2290, eprocess=0x0000830da35b22c0
  0x830da35b22c0 svchost.exe           2132 0x830da35b22c0    680     0x238d0002 P    2020-10-04 14:58:53Z                             
2020-10-05 04:44:25,194:DEBUG:rekall.1:[!] pool=0x0000830da35c9050, eprocess=0x0000830da35c9080
  0x830da35c9080 VGAuthService.        2252 0x830da35c9080    680     0x545ed002 P    2020-10-04 14:58:54Z                             
2020-10-05 04:44:26,741:DEBUG:rekall.1:[!] pool=0x0000830da6faa050, eprocess=0x0000830da6faa080
2020-10-05 04:44:26,757:DEBUG:rekall.1:[!] pool=0x0000830da6faa100, eprocess=0x0000830da6faa130
2020-10-05 04:44:26,757:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa130, pid=0, \x94/\x01, no dtb
2020-10-05 04:44:26,757:DEBUG:rekall.1:[!] pool=0x0000830da6faa110, eprocess=0x0000830da6faa140
2020-10-05 04:44:26,757:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa140, pid=3, Plg\xa7\x0d\x83\xff\xff\xd8Vp\xa7\x0d\x83\xff\xff, no dtb
2020-10-05 04:44:26,757:DEBUG:rekall.1:[!] pool=0x0000830da6faa120, eprocess=0x0000830da6faa150
  0x830da6faa080 lsass.exe              692 0x830da6faa080    544     0x11302002 P    2020-10-04 14:58:44Z                             
2020-10-05 04:44:26,772:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa150, pid=0, \x18Vg\xa7\x0d\x83\xff\xff<, invalid flink=None, blink=None
2020-10-05 04:44:26,772:DEBUG:rekall.1:[!] pool=0x0000830da6faa130, eprocess=0x0000830da6faa160
2020-10-05 04:44:26,772:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa160, pid=3250716672, \xec, no dtb
2020-10-05 04:44:26,772:DEBUG:rekall.1:[!] pool=0x0000830da6faa140, eprocess=0x0000830da6faa170
2020-10-05 04:44:26,772:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa170, pid=0, \x18, no dtb
2020-10-05 04:44:26,772:DEBUG:rekall.1:[!] pool=0x0000830da6faa150, eprocess=0x0000830da6faa180
2020-10-05 04:44:26,772:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa180, pid=544, , no dtb
2020-10-05 04:44:26,772:DEBUG:rekall.1:[!] pool=0x0000830da6faa1a0, eprocess=0x0000830da6faa1d0
2020-10-05 04:44:26,788:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa1d0, pid=2738109904, A\x0f, no dtb
2020-10-05 04:44:26,788:DEBUG:rekall.1:[!] pool=0x0000830da6faa1b0, eprocess=0x0000830da6faa1e0
2020-10-05 04:44:26,788:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa1e0, pid=2808726832, , no dtb
2020-10-05 04:44:26,788:DEBUG:rekall.1:[!] pool=0x0000830da6faa1c0, eprocess=0x0000830da6faa1f0
2020-10-05 04:44:26,788:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa1f0, pid=101, , no dtb
2020-10-05 04:44:26,788:DEBUG:rekall.1:[!] pool=0x0000830da6faa1d0, eprocess=0x0000830da6faa200
2020-10-05 04:44:26,788:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa200, pid=2740326000, , no dtb
2020-10-05 04:44:26,788:DEBUG:rekall.1:[!] pool=0x0000830da6faa1e0, eprocess=0x0000830da6faa210
2020-10-05 04:44:26,788:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa210, pid=0, , invalid flink=None, blink=None
2020-10-05 04:44:26,804:DEBUG:rekall.1:[!] pool=0x0000830da6faa1f0, eprocess=0x0000830da6faa220
2020-10-05 04:44:26,804:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa220, pid=2808392248, , no dtb
2020-10-05 04:44:26,804:DEBUG:rekall.1:[!] pool=0x0000830da6faa200, eprocess=0x0000830da6faa230
2020-10-05 04:44:26,804:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa230, pid=8, , no dtb
2020-10-05 04:44:26,804:DEBUG:rekall.1:[!] pool=0x0000830da6faa210, eprocess=0x0000830da6faa240
2020-10-05 04:44:26,804:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa240, pid=0, , no dtb
2020-10-05 04:44:26,804:DEBUG:rekall.1:[!] pool=0x0000830da6faa250, eprocess=0x0000830da6faa280
2020-10-05 04:44:26,804:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa280, pid=0, l\, no dtb
2020-10-05 04:44:26,819:DEBUG:rekall.1:[!] pool=0x0000830da6faa260, eprocess=0x0000830da6faa290
2020-10-05 04:44:26,819:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa290, pid=1627, \xe0\xa5\xc9\xa2\x0d\x83\xff\xff\x94, no dtb
2020-10-05 04:44:26,819:DEBUG:rekall.1:[!] pool=0x0000830da6faa270, eprocess=0x0000830da6faa2a0
2020-10-05 04:44:26,819:DEBUG:rekall.1:[!] pool=0x0000830da6faa280, eprocess=0x0000830da6faa2b0
2020-10-05 04:44:26,819:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa2b0, pid=2809157336, , invalid flink=None, blink=None
2020-10-05 04:44:26,819:DEBUG:rekall.1:[!] pool=0x0000830da6faa290, eprocess=0x0000830da6faa2c0
2020-10-05 04:44:26,835:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa2c0, pid=60, \xf0`\x9e\xae\x0a\xb4\xff\xff\xf8\x02, no dtb
2020-10-05 04:44:26,835:DEBUG:rekall.1:[!] pool=0x0000830da6faa2a0, eprocess=0x0000830da6faa2d0
2020-10-05 04:44:26,835:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa2d0, pid=94, , invalid flink=None, blink=None
  0x830da6faa2a0                          0 0x830da6faa2a0      0 0xffff830da7705408                                                       
2020-10-05 04:44:26,866:DEBUG:rekall.1:[!] pool=0x0000830da6faa410, eprocess=0x0000830da6faa440
2020-10-05 04:44:26,866:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa440, pid=0, \x90\xa8\xfa\xa6\x0d\x83\xff\xff\x90\xa8\xfa\xa6\x0d\x83\xff\xff, invalid flink=None, blink=None
2020-10-05 04:44:26,897:DEBUG:rekall.1:[!] pool=0x0000830da6faa720, eprocess=0x0000830da6faa750
2020-10-05 04:44:26,913:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa750, pid=547, , invalid flink=None, blink=None
2020-10-05 04:44:26,913:DEBUG:rekall.1:[!] pool=0x0000830da6faa730, eprocess=0x0000830da6faa760
2020-10-05 04:44:26,913:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa760, pid=0, , no dtb
2020-10-05 04:44:26,913:DEBUG:rekall.1:[!] pool=0x0000830da6faa780, eprocess=0x0000830da6faa7b0
2020-10-05 04:44:26,913:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa7b0, pid=0, , no dtb
2020-10-05 04:44:26,913:DEBUG:rekall.1:[!] pool=0x0000830da6faa7c0, eprocess=0x0000830da6faa7f0
2020-10-05 04:44:26,913:DEBUG:rekall.1:[!] eprocess=0x0000830da6faa7f0, pid=0, , invalid flink=None, blink=None
2020-10-05 04:44:27,038:DEBUG:rekall.1:[!] pool=0x0000830da766d350, eprocess=0x0000830da766d380
  0x830da766d380 winlogon.exe           644 0x830da766d380    536     0x13c60002 P    2020-10-04 14:58:44Z                             
2020-10-05 04:44:27,116:DEBUG:rekall.1:[!] pool=0x0000830da76750d0, eprocess=0x0000830da7675100
  0x830da7675100 services.exe           680 0x830da7675100    544     0x15537002 P    2020-10-04 14:58:44Z                             
2020-10-05 04:44:27,179:DEBUG:rekall.1:[!] pool=0x0000830da76757d0, eprocess=0x0000830da7675800
2020-10-05 04:44:27,179:DEBUG:rekall.1:[!] eprocess=0x0000830da7675800, pid=0, , invalid flink=None, blink=None
2020-10-05 04:44:27,210:DEBUG:rekall.1:[!] pool=0x0000830da76d8090, eprocess=0x0000830da76d80c0
  0x830da76d80c0 fontdrvhost.ex         864 0x830da76d80c0    644     0x16cf9002 P    2020-10-04 14:58:44Z                             
2020-10-05 04:44:27,241:DEBUG:rekall.1:[!] pool=0x0000830da76d8260, eprocess=0x0000830da76d8290
2020-10-05 04:44:27,241:DEBUG:rekall.1:[!] eprocess=0x0000830da76d8290, pid=0, , no dtb
2020-10-05 04:44:27,382:DEBUG:rekall.1:[!] pool=0x0000830da76d8a60, eprocess=0x0000830da76d8a90
2020-10-05 04:44:27,382:DEBUG:rekall.1:[!] eprocess=0x0000830da76d8a90, pid=0, , no dtb
2020-10-05 04:44:27,413:DEBUG:rekall.1:[!] pool=0x0000830da770c290, eprocess=0x0000830da770c2c0
  0x830da770c2c0 svchost.exe            800 0x830da770c2c0    680     0x167b8002 P    2020-10-04 14:58:44Z                             
2020-10-05 04:44:27,460:DEBUG:rekall.1:[!] pool=0x0000830da770ca10, eprocess=0x0000830da770ca40
2020-10-05 04:44:27,460:DEBUG:rekall.1:[!] eprocess=0x0000830da770ca40, pid=2929696800, , invalid flink=None, blink=None
2020-10-05 04:44:27,944:DEBUG:rekall.1:[!] pool=0x0000830da7e76290, eprocess=0x0000830da7e762c0
  0x830da7e762c0 svchost.exe            744 0x830da7e762c0    680     0x193f3002 P    2020-10-04 14:58:45Z                             
2020-10-05 04:44:27,992:DEBUG:rekall.1:[!] pool=0x0000830da7e76a60, eprocess=0x0000830da7e76a90
2020-10-05 04:44:27,992:DEBUG:rekall.1:[!] eprocess=0x0000830da7e76a90, pid=262288, , no dtb
2020-10-05 04:44:28,022:DEBUG:rekall.1:[!] pool=0x0000830da7e9f310, eprocess=0x0000830da7e9f340
  0x830da7e9f340 svchost.exe            972 0x830da7e9f340    680     0x1969d002 P    2020-10-04 14:58:45Z                             
2020-10-05 04:44:28,053:DEBUG:rekall.1:[!] pool=0x0000830da7e9f8c0, eprocess=0x0000830da7e9f8f0
2020-10-05 04:44:28,053:DEBUG:rekall.1:[!] eprocess=0x0000830da7e9f8f0, pid=835, , no dtb
2020-10-05 04:44:28,100:DEBUG:rekall.1:[!] pool=0x0000830da7ede290, eprocess=0x0000830da7ede2c0
  0x830da7ede2c0 svchost.exe           1088 0x830da7ede2c0    680     0x1397e002 P    2020-10-04 14:58:45Z                             
2020-10-05 04:44:28,225:DEBUG:rekall.1:[!] pool=0x0000830da8055310, eprocess=0x0000830da8055340
  0x830da8055340 svchost.exe           1348 0x830da8055340    680     0x1daf7002 P    2020-10-04 14:58:46Z                             
2020-10-05 04:44:28,881:DEBUG:rekall.1:[!] pool=0x0000830da8319250, eprocess=0x0000830da8319280
  0x830da8319280 spoolsv.exe           1812 0x830da8319280    680     0x206b9002 P    2020-10-04 14:58:48Z                             
2020-10-05 04:44:28,975:DEBUG:rekall.1:[!] pool=0x0000830da84df310, eprocess=0x0000830da84df340
  0x830da84df340 svchost.exe           2040 0x830da84df340    680     0x239c0002 P    2020-10-04 14:58:50Z                             
2020-10-05 04:44:29,022:DEBUG:rekall.1:[!] pool=0x0000830da84df8c0, eprocess=0x0000830da84df8f0
2020-10-05 04:44:29,022:DEBUG:rekall.1:[!] eprocess=0x0000830da84df8f0, pid=0, , no dtb
2020-10-05 04:44:29,054:DEBUG:rekall.1:[!] pool=0x0000830da86ee490, eprocess=0x0000830da86ee4c0
  0x830da86ee4c0 python.exe            6356 0x830da86ee4c0    656     0x6f3e1002 P    2020-10-04 19:42:15Z                             
2020-10-05 04:44:29,148:DEBUG:rekall.1:[!] pool=0x0000830da89d12d0, eprocess=0x0000830da89d1300
  0x830da89d1300 dasHost.exe           2196 0x830da89d1300   1088     0x27e0b002 P    2020-10-04 14:58:53Z                             
2020-10-05 04:44:29,226:DEBUG:rekall.1:[!] pool=0x0000830da8b3c050, eprocess=0x0000830da8b3c080
  0x830da8b3c080 Microsoft.Phot        4436 0x830da8b3c080    800     0x269f8002 P    2020-10-04 19:29:02Z                             
2020-10-05 04:44:29,882:DEBUG:rekall.1:[!] pool=0x0000830da8e13090, eprocess=0x0000830da8e130c0
  0x830da8e130c0 WmiPrvSE.exe          2776 0x830da8e130c0    800     0x2dde8002 P    2020-10-04 14:58:59Z                             
2020-10-05 04:44:29,928:DEBUG:rekall.1:[!] pool=0x0000830da8e13650, eprocess=0x0000830da8e13680
2020-10-05 04:44:29,928:DEBUG:rekall.1:[!] eprocess=0x0000830da8e13680, pid=0, , no dtb
2020-10-05 04:44:29,975:DEBUG:rekall.1:[!] pool=0x0000830da91ac2d0, eprocess=0x0000830da91ac300
  0x830da91ac300 msdtc.exe             3204 0x830da91ac300    680     0x3b424002 P    2020-10-04 14:59:04Z                             
2020-10-05 04:44:30,053:DEBUG:rekall.1:[!] pool=0x0000830da92293d0, eprocess=0x0000830da9229400
  0x830da9229400 NisSrv.exe            3096 0x830da9229400    680     0x2d876002 P    2020-10-04 14:59:04Z                             
2020-10-05 04:44:30,131:DEBUG:rekall.1:[!] pool=0x0000830da927b3d0, eprocess=0x0000830da927b400
  0x830da927b400 sihost.exe            3340 0x830da927b400    744     0x3e7a7002 P    2020-10-04 14:59:05Z                             
2020-10-05 04:44:30,178:DEBUG:rekall.1:[!] pool=0x0000830da927b660, eprocess=0x0000830da927b690
2020-10-05 04:44:30,178:DEBUG:rekall.1:[!] eprocess=0x0000830da927b690, pid=0, , no dtb
2020-10-05 04:44:30,194:DEBUG:rekall.1:[!] pool=0x0000830da927b8a0, eprocess=0x0000830da927b8d0
2020-10-05 04:44:30,210:DEBUG:rekall.1:[!] eprocess=0x0000830da927b8d0, pid=3002122184, , invalid flink=None, blink=None
2020-10-05 04:44:30,319:DEBUG:rekall.1:[!] pool=0x0000830da927d410, eprocess=0x0000830da927d440
  0x830da927d440 svchost.exe           3360 0x830da927d440    680     0x3e91a002 P    2020-10-04 14:59:05Z                             
2020-10-05 04:44:30,398:DEBUG:rekall.1:[!] pool=0x0000830da92d5050, eprocess=0x0000830da92d5080
  0x830da92d5080 conhost.exe           6456 0x830da92d5080   6356     0x3be5c002 P    2020-10-04 19:42:15Z                             
2020-10-05 04:44:30,491:DEBUG:rekall.1:[!] pool=0x0000830da932d050, eprocess=0x0000830da932d080
  0x830da932d080 userinit.exe          3624 0x830da932d080    644     0x3d6d4002 P    2020-10-04 14:59:07Z     2020-10-04 14:59:47Z    
2020-10-05 04:44:30,553:DEBUG:rekall.1:[!] pool=0x0000830da932db70, eprocess=0x0000830da932dba0
2020-10-05 04:44:30,553:DEBUG:rekall.1:[!] eprocess=0x0000830da932dba0, pid=0, , no dtb
2020-10-05 04:44:30,569:DEBUG:rekall.1:[!] pool=0x0000830da9378090, eprocess=0x0000830da93780c0
  0x830da93780c0 explorer.exe          3664 0x830da93780c0   3624     0x41c9b002 P    2020-10-04 14:59:07Z                             
2020-10-05 04:44:30,600:DEBUG:rekall.1:[!] pool=0x0000830da9378260, eprocess=0x0000830da9378290
2020-10-05 04:44:30,600:DEBUG:rekall.1:[!] eprocess=0x0000830da9378290, pid=354, , no dtb
2020-10-05 04:44:30,710:DEBUG:rekall.1:[!] pool=0x0000830da94de410, eprocess=0x0000830da94de440
  0x830da94de440 svchost.exe           3920 0x830da94de440    680     0x4a0dd002 P    2020-10-04 14:59:10Z                             
2020-10-05 04:44:30,757:DEBUG:rekall.1:[!] pool=0x0000830da94de9a0, eprocess=0x0000830da94de9d0
2020-10-05 04:44:30,757:DEBUG:rekall.1:[!] eprocess=0x0000830da94de9d0, pid=0, , no dtb
2020-10-05 04:44:31,412:DEBUG:rekall.1:[!] pool=0x0000830da972b050, eprocess=0x0000830da972b080
  0x830da972b080 StartMenuExper        4208 0x830da972b080    800     0x52b29002 P    2020-10-04 14:59:15Z                             
2020-10-05 04:44:31,475:DEBUG:rekall.1:[!] pool=0x0000830da972b2e0, eprocess=0x0000830da972b310
2020-10-05 04:44:31,491:DEBUG:rekall.1:[!] eprocess=0x0000830da972b310, pid=0, , no dtb
2020-10-05 04:44:31,601:DEBUG:rekall.1:[!] pool=0x0000830da9804490, eprocess=0x0000830da98044c0
  0x830da98044c0 conhost.exe           5904 0x830da98044c0   5076     0x5606b002 P    2020-10-04 15:02:34Z                             
2020-10-05 04:44:31,709:DEBUG:rekall.1:[!] pool=0x0000830da993b450, eprocess=0x0000830da993b480
  0x830da993b480 RuntimeBroker.        4320 0x830da993b480    800     0x5675e002 P    2020-10-04 14:59:16Z                             
2020-10-05 04:44:31,913:DEBUG:rekall.1:[!] pool=0x0000830da9bc7090, eprocess=0x0000830da9bc70c0
  0x830da9bc70c0 RuntimeBroker.        4676 0x830da9bc70c0    800     0x5a117002 P    2020-10-04 14:59:19Z                             
2020-10-05 04:44:31,991:DEBUG:rekall.1:[!] pool=0x0000830da9bca490, eprocess=0x0000830da9bca4c0
  0x830da9bca4c0 dllhost.exe           4788 0x830da9bca4c0    800     0x5aa05002 P    2020-10-04 14:59:20Z                             
2020-10-05 04:44:32,038:DEBUG:rekall.1:[!] pool=0x0000830da9bca720, eprocess=0x0000830da9bca750
2020-10-05 04:44:32,038:DEBUG:rekall.1:[!] eprocess=0x0000830da9bca750, pid=0, , no dtb
2020-10-05 04:44:32,038:DEBUG:rekall.1:[!] pool=0x0000830da9bca750, eprocess=0x0000830da9bca780
2020-10-05 04:44:32,038:DEBUG:rekall.1:[!] eprocess=0x0000830da9bca780, pid=197, , invalid flink=None, blink=None
2020-10-05 04:44:32,038:DEBUG:rekall.1:[!] pool=0x0000830da9bca760, eprocess=0x0000830da9bca790
2020-10-05 04:44:32,038:DEBUG:rekall.1:[!] eprocess=0x0000830da9bca790, pid=0, \xe0\xab\xbc\xa9\x0d\x83\xff\xff\xe0\xab\xbc\xa9\x0d\x83\xff\xff, invalid flink=None, blink=None
2020-10-05 04:44:32,053:DEBUG:rekall.1:[!] pool=0x0000830da9bca770, eprocess=0x0000830da9bca7a0
2020-10-05 04:44:32,053:DEBUG:rekall.1:[!] eprocess=0x0000830da9bca7a0, pid=0, , invalid flink=None, blink=None
2020-10-05 04:44:32,053:DEBUG:rekall.1:[!] pool=0x0000830da9bca780, eprocess=0x0000830da9bca7b0
2020-10-05 04:44:32,053:DEBUG:rekall.1:[!] eprocess=0x0000830da9bca7b0, pid=0, , invalid flink=None, blink=None
2020-10-05 04:44:32,100:DEBUG:rekall.1:[!] pool=0x0000830da9bcab80, eprocess=0x0000830da9bcabb0
2020-10-05 04:44:32,100:DEBUG:rekall.1:[!] eprocess=0x0000830da9bcabb0, pid=0, , no dtb
2020-10-05 04:44:32,194:DEBUG:rekall.1:[!] pool=0x0000830da9cdc2d0, eprocess=0x0000830da9cdc300
  0x830da9cdc300 SecurityHealth        5712 0x830da9cdc300    680     0x70580002 P    2020-10-04 14:59:33Z                             
2020-10-05 04:44:32,398:DEBUG:rekall.1:[!] pool=0x0000830da9d34450, eprocess=0x0000830da9d34480
  0x830da9d34480 SettingSyncHos        5112 0x830da9d34480    800     0x61db5002 P    2020-10-04 14:59:24Z                             
2020-10-05 04:44:32,475:DEBUG:rekall.1:[!] pool=0x0000830da9de9050, eprocess=0x0000830da9de9080
  0x830da9de9080 RuntimeBroker.        2204 0x830da9de9080    800      0x2804002 P    2020-10-04 15:00:04Z                             
2020-10-05 04:44:32,522:DEBUG:rekall.1:[!] pool=0x0000830da9de9220, eprocess=0x0000830da9de9250
2020-10-05 04:44:32,522:DEBUG:rekall.1:[!] eprocess=0x0000830da9de9250, pid=2, , no dtb
2020-10-05 04:44:32,553:DEBUG:rekall.1:[!] pool=0x0000830da9de9610, eprocess=0x0000830da9de9640
2020-10-05 04:44:32,553:DEBUG:rekall.1:[!] eprocess=0x0000830da9de9640, pid=0, , no dtb
2020-10-05 04:44:32,585:DEBUG:rekall.1:[!] pool=0x0000830da9e68050, eprocess=0x0000830da9e68080
  0x830da9e68080 LockApp.exe            876 0x830da9e68080    800     0x3bf06002 P    2020-10-04 14:59:24Z                             
2020-10-05 04:44:32,741:DEBUG:rekall.1:[!] pool=0x0000830da9ed4450, eprocess=0x0000830da9ed4480
  0x830da9ed4480 RuntimeBroker.        2736 0x830da9ed4480    800     0x65036002 P    2020-10-04 14:59:26Z                             
2020-10-05 04:44:33,553:DEBUG:rekall.1:[!] pool=0x0000830daa19f050, eprocess=0x0000830daa19f080
  0x830daa19f080 vm3dservice.ex        5756 0x830daa19f080   3664     0x6cbe3002 P    2020-10-04 14:59:33Z                             
2020-10-05 04:44:33,647:DEBUG:rekall.1:[!] pool=0x0000830daa1a7050, eprocess=0x0000830daa1a7080
  0x830daa1a7080 vmtoolsd.exe          5820 0x830daa1a7080   3664     0x59980002 P    2020-10-04 14:59:34Z                             
2020-10-05 04:44:33,725:DEBUG:rekall.1:[!] pool=0x0000830daa1c9310, eprocess=0x0000830daa1c9340
  0x830daa1c9340 OneDrive.exe          5872 0x830daa1c9340   3664     0x6718c002 P    2020-10-04 14:59:35Z                             
2020-10-05 04:44:33,804:DEBUG:rekall.1:[!] pool=0x0000830daa1fd3d0, eprocess=0x0000830daa1fd400
  0x830daa1fd400 ctfmon.exe            4672 0x830daa1fd400   1088     0x74bc5002 P    2020-10-04 14:59:43Z                             
2020-10-05 04:44:34,413:DEBUG:rekall.1:[!] pool=0x0000830daab83050, eprocess=0x0000830daab83080
  0x830daab83080 git.exe               6436 0x830daab83080   3156     0x238c2002      2020-10-04 19:44:12Z     2020-10-04 19:44:12Z    
Plugin: psscan (PSScan)
>>> 