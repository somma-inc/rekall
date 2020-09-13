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

    - [fixes bug in VA translation process (#538)](https://github.com/google/rekall/commit/b6f632f167c7d5cd80decf6fcb5481b45e38101c)

    - [winpmem](https://github.com/google/rekall/tree/master/tools/windows/winpmem)
    -     

+ FireEye fork version (add memory compression analysis)
    - https://github.com/fireeye/win10_rekall
    - https://github.com/fireeye/win10_rekall/commit/2027518aae789e54d408cd8e2e414557122a6096

## Profile
- ntkrnlmp.pdb 상의 내용을 파싱해서 익스포트된 심볼들의 RVA 를 기록
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

# Commands ref.
- winpmem 드라이버를 사용하기때문에 항상 관리자권한으로

rekal --live Memory psxview
rekal --live Memory psscan --scan_kernel_paged_pool --scan_kernel_nonpaged_pool --scan_kernel_code --scan_physical --logging_level DEBUG
rekal --live Memory psscan --logging_level DEBUG
rekal --live Memory psscan --scan_kernel_paged_pool --scan_kernel_nonpaged_pool --scan_kernel_code --scan_physical --logging_level DEBUG 2> psscan2.txt

---

rekal --live Memory --verbose





 `rekall-yara` 설치중 에러

    ```
    Installed c:\programdata\anaconda3\envs\rekall\lib\site-packages\rekall_core-1.7.3.dev65-py3.8.egg
    Processing dependencies for rekall-core==1.7.3.dev65
    Searching for rekall-yara==3.6.3.1
    Reading https://pypi.org/simple/rekall-yara/
    Downloading https://files.pythonhosted.org/packages/c1/a2/a1fd733b5855208c20408cb74d6303c90dededc127e78fbca2dee52ef54a/rekall_yara-3.6.3.1.tar.gz#sha256=84cd9bad4da12e2e8b32fb1a429eaee8793eda97f0859ed3edc063a7eac24915
    Best match: rekall-yara 3.6.3.1
    Processing rekall_yara-3.6.3.1.tar.gz
    Writing C:\Users\unsor\AppData\Local\Temp\easy_install-uyzl9mdk\rekall_yara-3.6.3.1\setup.cfg
    Running rekall_yara-3.6.3.1\setup.py -q bdist_egg --dist-dir C:\Users\unsor\AppData\Local\Temp\easy_install-uyzl9mdk\rekall_yara-3.6.3.1\egg-dist-tmp-vg2cxmrm
    no previously-included directories found matching 'rekall_yara\yara\windows'
    no previously-included directories found matching 'rekall_yara\yara\docs'
    no previously-included directories found matching 'rekall_yara\yara\tests'
    error: Setup script exited with error: Microsoft Visual C++ 14.0 or greater is required. Get it with "Microsoft C++ Build Tools": https://visualstudio.microsoft.com/visual-cpp-build-tools/
    ```

    ```
    (rekall) C:\work.rekall\rekall-core>pip install rekall-yara
    Collecting rekall-yara
    Using cached rekall_yara-3.6.3.1.tar.gz (1.2 MB)
    Building wheels for collected packages: rekall-yara
    Building wheel for rekall-yara (setup.py) ... error
    ERROR: Command errored out with exit status 1:
    command: 'c:\programdata\anaconda3\envs\rekall\python.exe' -u -c 'import sys, setuptools, tokenize; sys.argv[0] = '"'"'C:\\Users\\unsor\\AppData\\Local\\Temp\\pip-install-yhmk27zm\\rekall-yara\\setup.py'"'"'; __file__='"'"'C:\\Users\\unsor\\AppData\\Local\\Temp\\pip-install-yhmk27zm\\rekall-yara\\setup.py'"'"';f=getattr(tokenize, '"'"'open'"'"', open)(__file__);code=f.read().replace('"'"'\r\n'"'"', '"'"'\n'"'"');f.close();exec(compile(code, __file__, '"'"'exec'"'"'))' bdist_wheel -d 'C:\Users\unsor\AppData\Local\Temp\pip-wheel-lcci3h4g'
        cwd: C:\Users\unsor\AppData\Local\Temp\pip-install-yhmk27zm\rekall-yara\
    Complete output (10 lines):
    running bdist_wheel
    running build
    running build_py
    creating build
    creating build\lib.win-amd64-3.8
    creating build\lib.win-amd64-3.8\rekall_yara
    copying rekall_yara\__init__.py -> build\lib.win-amd64-3.8\rekall_yara
    running build_ext
    building 'yara' extension
    error: Microsoft Visual C++ 14.0 or greater is required. Get it with "Microsoft C++ Build Tools": https://visualstudio.microsoft.com/visual-cpp-build-tools/
    ----------------------------------------
    ERROR: Failed building wheel for rekall-yara
    Running setup.py clean for rekall-yara
  ```
