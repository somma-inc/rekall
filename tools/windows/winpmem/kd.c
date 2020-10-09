/*
  Copyright 2012 Michael Cohen <scudette@gmail.com>

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include "kd.h"
#include "SystemModInfoInvocation.h"

SIZE_T KernelGetModuleBaseByPtr()
{
	NTSTATUS status = STATUS_SUCCESS;

	ULONG ModuleCount = 0;
	ULONG i = 0, j = 0;

	ULONG NeedSize = 0;
	ULONG preAllocateSize = 0x1000;
	PVOID pBuffer = NULL;

	SIZE_T imagebase_of_nt = 0;

	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;

	PAGED_CODE();

	// Preallocate 0x1000 bytes and try.
	pBuffer = ExAllocatePoolWithTag(NonPagedPool, preAllocateSize, PMEM_POOL_TAG);
	if (pBuffer == NULL)
	{
		return 0;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, preAllocateSize, &NeedSize);

	if ((status == STATUS_INFO_LENGTH_MISMATCH) || (status == STATUS_BUFFER_OVERFLOW))
	{
		ExFreePool(pBuffer);
		pBuffer = ExAllocatePoolWithTag(NonPagedPool, NeedSize, PMEM_POOL_TAG);
		status = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, NeedSize, &NeedSize);
	}

	if (!NT_SUCCESS(status))
	{
		ExFreePool(pBuffer);
		DbgPrint("KernelGetModuleBaseByPtr() failed with %08x.\n", status);
		return 0;
	}

	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;

	ModuleCount = pSystemModuleInformation->Count;

	for (i = 0; i < ModuleCount; i++)
	{
		if (pSystemModuleInformation->Module[i].ImageName)
		{
			for (j = 0; j < 250; j++)
			{
				// There are so many names for NT kernels: ntoskrnl, ntkrpamp, ...
				if (
					((pSystemModuleInformation->Module[i].ImageName[j + 0] | 0x20) == 'n') &&
					((pSystemModuleInformation->Module[i].ImageName[j + 1] | 0x20) == 't') &&

					(((pSystemModuleInformation->Module[i].ImageName[j + 2] | 0x20) == 'o') &&
					((pSystemModuleInformation->Module[i].ImageName[j + 3] | 0x20) == 's'))
					||
					(((pSystemModuleInformation->Module[i].ImageName[j + 2] | 0x20) == 'k') &&
					((pSystemModuleInformation->Module[i].ImageName[j + 3] | 0x20) == 'r'))
					) // end of nt kernel name check.
				{
					imagebase_of_nt = (SIZE_T)pSystemModuleInformation->Module[i].Base;
					return imagebase_of_nt;
				}

			}
		}
	}

	ExFreePool(pBuffer);
	return 0;
}

/* Resolve a kernel function by name.
 */
void *KernelGetProcAddress(void *image_base, char *func_name) {
  void *func_address = NULL;

  __try  {
    int size = 0;
    IMAGE_DOS_HEADER *dos =(IMAGE_DOS_HEADER *)image_base;
    IMAGE_NT_HEADERS *nt  =(IMAGE_NT_HEADERS *)((uintptr_t)image_base + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY *expdir = (IMAGE_DATA_DIRECTORY *)
      (nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);

    IMAGE_EXPORT_DIRECTORY *exports =(PIMAGE_EXPORT_DIRECTORY)
      ((uintptr_t)image_base + expdir->VirtualAddress);

    uintptr_t addr = (uintptr_t)exports-(uintptr_t)image_base;

    // These are arrays of RVA addresses.
    unsigned int *functions = (unsigned int *)((uintptr_t)image_base +
                                               exports->AddressOfFunctions);

    unsigned int *names = (unsigned int *)((uintptr_t)image_base +
                                           exports->AddressOfNames);

    short *ordinals = (short *)((uintptr_t)image_base +
                                exports->AddressOfNameOrdinals);

    unsigned int max_name  = exports->NumberOfNames;
    unsigned int  max_func  = exports->NumberOfFunctions;

    unsigned int i;

    for (i = 0; i < max_name; i++) {
      unsigned int ord = ordinals[i];
      if(i >= max_name || ord >= max_func) {
        return NULL;
      }

      if (functions[ord] < addr || functions[ord] >= addr + size) {
        if (strcmp((char *)image_base + names[i], func_name)  == 0) {
          func_address = (char *)image_base + functions[ord];
          break;
        }
      }
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER) {
    func_address = NULL;
  }

  return func_address;
} // end KernelGetProcAddress()


/* Search for a section by name.

   Returns the mapped virtual memory section or NULL if not found.
*/
IMAGE_SECTION_HEADER *GetSection(IMAGE_DOS_HEADER *image_base, char *name) {
  IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)
    ((uintptr_t)image_base + image_base->e_lfanew);
  int i;
  int number_of_sections = nt->FileHeader.NumberOfSections;

  IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)
    ((uintptr_t)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

  for (i=0; i<number_of_sections; i++) {
    if(!strcmp((char *)sections[i].Name, name))
      return &sections[i];
  };

  return NULL;
};


/*
  Enumerate the KPCR blocks from all CPUs.
*/

int GetKPCR(struct PmemMemoryInfo *info) {
  __int64 active_processors = KeQueryActiveProcessors();
  int i;

  for (i=0; i < 32; i++) {
    info->KPCR[i].QuadPart = 0;
  };

  for (i=0; i < 32; i++) {
    if (active_processors & ((__int64)1 << i)) {
      KeSetSystemAffinityThread((__int64)1 << i);
#if _WIN64 || __amd64__
      //64 bit uses gs and _KPCR.Self is at 0x18:
      info->KPCR[i].QuadPart = (uintptr_t)__readgsqword(0x18);
#else
      //32 bit uses fs and _KPCR.SelfPcr is at 0x1c:
      info->KPCR[i].QuadPart = (uintptr_t)__readfsword(0x1c);
#endif
    };
  };

  KeRevertToUserAffinityThread();

  return 1;
};
