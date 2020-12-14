import functools
import six
import struct

from typing import Tuple, List

from rekall.plugins.overlays.windows import win8, common
from rekall_lib import utils
from rekall import addrspace

win10_undocumented_amd64 = {
    # wi10.raw 18:05:45> dis "nt!MiSessionInsertImage"
    #        call 0xf8014a9d4e80                      nt!memset
    # ...    or rax, 3    <---- Base address is ORed with 3.
    #        mov dword ptr [rbp + 0x3c], 1   <--- ImageCountInThisSession
    #        mov qword ptr [rbp + 0x28], rax  <---- Address
    '_IMAGE_ENTRY_IN_SESSION': [None, {
        'Address': [0x28, ["_EX_FAST_REF"]],
        }],
    }

win10_undocumented_i386 = {
    '_IMAGE_ENTRY_IN_SESSION': [None, {
        'Address': [0x14, ["Pointer"]],
        }],
    }

win10_overlays = {
    '_MM_SESSION_SPACE': [None, {
        # Specialized iterator to produce all the _IMAGE_ENTRY_IN_SESSION
        # records. In Win10 these are stored in an AVL tree instead.
        'ImageIterator': lambda x: x.ImageTree.Root.traverse(
            type="_IMAGE_ENTRY_IN_SESSION")
    }],

    "_UNLOADED_DRIVERS": [None, {
        "CurrentTime": [None, ["WinFileTime"]],
    }],

    "_OBJECT_HEADER": [None, {
        "InfoMask": [None, ["Flags", dict(
            maskmap=utils.Invert({
                0x01: "CreatorInfo",
                0x2: "NameInfo",
                0x4: "HandleInfo",
                0x8: "QuotaInfo",
                0x10: "ProcessInfo",
                0x20: "AuditInfo",
                0x40: "ExtendedInfo",
                0x80: "PaddingInfo",
                }),
            target="unsigned char",
            )]],
        }],

    "_MI_HARDWARE_STATE": [None, {
        "SystemNodeInformation": [None, ["Pointer", dict(
            target="Array",
            target_args=dict(
                target="_MI_SYSTEM_NODE_INFORMATION",
                count=lambda x: x.obj_profile.get_constant_object(
                    "KeNumberNodes", "unsigned int").v(),
            )
        )]],
    }],
}


class _POOL_HEADER(common._POOL_HEADER):
    """A class for pool headers"""

    MAX_PREAMBLE_SIZE = 0x50

    @utils.safe_property
    def NonPagedPool(self):
        return self.PoolType.v() % 2 == 0 and self.PoolType.v() > 0

    @utils.safe_property
    def PagedPool(self):
        return self.PoolType.v() % 2 == 1

    @utils.safe_property
    def FreePool(self):
        return self.PoolType.v() == 0

    # A class cached version of the lookup map. This is mutable and shared
    # between all instances.
    lookup = {}

    def _BuildLookupTable(self):
        """Create a fast lookup table mapping InfoMask -> minimum_offset.

        We are interested in the maximum distance between the _POOL_HEADER and
        _OBJECT_HEADER. This is dictated by the InfoMask field. Here we build a
        quick lookup table between the InfoMask field and the offset of the
        first optional header.
        """
        ObpInfoMaskToOffset = self.obj_session.GetParameter(
            "ObpInfoMaskToOffset")

        self.lookup[0] = 0

        # Iterate over all the possible InfoMask values (Bytes can take on 256
        # values).
        for i in range(0x100):
            # Locate the largest offset from the start of
            # _OBJECT_HEADER. Starting with the largest bit position 1 << 7.
            bit_position = 0x80
            while bit_position > 0:
                # This is the optional header with the largest offset.
                if bit_position & i:
                    self.lookup[i] = ObpInfoMaskToOffset[
                        i & (bit_position | (bit_position - 1))]

                    break
                bit_position >>= 1

    @classmethod
    @functools.lru_cache()
    def _CalculateOptionalHeaderLength(cls, obj_profile) -> Tuple[List[str], List[int]]:
        headers = []
        sizes = []
        for header in [
            'CREATOR_INFO', 'NAME_INFO', 'HANDLE_INFO', 'QUOTA_INFO', 'PROCESS_INFO', 'AUDIT_INFO', 'EXTENDED_INFO',
            'HANDLE_REVOCATION_INFO', 'PADDING_INFO'
        ]:
            object_size = obj_profile.get_obj_size(f'_OBJECT_HEADER_{header}')
            # 해당 정보가 없는 경우임.
            if hasattr(object_size, 'strict') is True:
                continue
            headers.append(header)
            sizes.append(object_size)
        return headers, sizes

    def IterObject(self, type=None, freed=True):
        """Generates possible _OBJECT_HEADER accounting for optional headers.

        Note that not all pool allocations have an _OBJECT_HEADER - only ones
        allocated from the the object manager. This means calling this method
        depends on which pool allocation you are after.

        On windows 8, pool allocations are done from preset sizes. This means
        that the allocation is never exactly the same size and we can not use
        the bottom up method like before.

        We therefore, have to build the headers forward by checking the preamble
        size and validity of each object. This is a little slower than with
        earlier versions of windows.

        Args:
          type: The object type name. If not specified we return all objects.
        """
        alignment = self.obj_profile.get_constant("PoolAlignment")

        # Operate on a cached version of the next page.
        # We use a temporary buffer for the object to save reads of the image.
        # self.obj_end는 _POOL_HEADER 다음 오프셋을 가르키고있음.
        start_offset = self.obj_end
        assert self.obj_size == 16
        allocation_size = self.BlockSize * alignment

        cached_data = self.obj_vm.read(start_offset, allocation_size)

        # for debug
        # if allocation_size > 0:
        #     pool_data = self.obj_vm.read(start - 16, allocation_size)
        #     with open(f'c:\\Temp\\psscan\\{start}_{allocation_size}.dmp', 'wb') as fp:
        #         fp.write((pool_data))
        cached_vm = addrspace.BufferAddressSpace(
            base_offset=start_offset, data=cached_data, session=self.obj_session)

        # We search for the _OBJECT_HEADER.InfoMask in close proximity to our
        # object. We build a lookup table between the values in the InfoMask and
        # the minimum distance there is between the start of _OBJECT_HEADER and
        # the end of _POOL_HEADER. This way we can quickly skip unreasonable
        # values.

        # This is the offset within _OBJECT_HEADER of InfoMask.
        info_mask_offset = self.obj_profile.get_obj_offset("_OBJECT_HEADER", "InfoMask")
        pointer_count_offset = self.obj_profile.get_obj_offset("_OBJECT_HEADER", "PointerCount")
        pointer_count_size = self.obj_profile.Object('_OBJECT_HEADER').PointerCount.obj_size

        optional_headers, lengths_of_optional_headers = self._CalculateOptionalHeaderLength(self.obj_profile)
        padding_available = None if 'PADDING_INFO' not in optional_headers else optional_headers.index('PADDING_INFO')
        max_optional_headers_length = sum(lengths_of_optional_headers)

        addr_limit = min(max_optional_headers_length, self.BlockSize * alignment)

        info_mask_data = self.obj_vm.read(start_offset, addr_limit + info_mask_offset)
        for addr in range(0, addr_limit, alignment):
            infomask_value = info_mask_data[addr + info_mask_offset]
            pointercount_value = int.from_bytes(
                info_mask_data[addr + pointer_count_offset:addr + pointer_count_offset + pointer_count_size],
                byteorder='little',
                signed=True
            )
            if not 0x1000000 > pointercount_value >= 0:
                continue

            padding_present = False
            optional_headers_length = 0
            for i in range(len(lengths_of_optional_headers)):
                if infomask_value & (1 << i):
                    optional_headers_length += lengths_of_optional_headers[i]
                    if i == padding_available:
                        padding_present = True

            padding_length = 0
            if padding_present:
                # Read the four bytes from just before the next optional_headers_length minus the padding_info size
                #
                #  ---------------
                #  POOL_HEADER
                #  ---------------
                #
                #  start of PADDING_INFO
                #  ---------------
                #  End of other optional headers
                #  ---------------
                #  OBJECT_HEADER
                #  ---------------
                if addr - optional_headers_length < 0:
                    continue
                padding_length = struct.unpack('<I', info_mask_data[
                    addr - optional_headers_length:addr - optional_headers_length + 4
                ])[0]
                padding_length -= lengths_of_optional_headers[padding_available or 0]
            if addr - optional_headers_length >= padding_length > addr:
                continue

            test_object = self.obj_profile._OBJECT_HEADER(offset=start_offset + addr, vm=cached_vm)
            #if test_object.is_valid():
            if (type is None or
                    test_object.get_object_type() == type or
                    # Freed objects point to index 1
                    #(which is also 0xbad0b0b0).
                    (freed and test_object.TypeIndex <= 2)):
                yield test_object
        #     else:
        #         self.obj_session.logging.debug(f"type index {test_object.TypeIndex}, "
        #                                        f"object type {test_object.get_object_type()}")
        # # object header를 찾지 못한 경우임. 왜?
        # with open(f'c:\\Temp\\psscan\\{start_offset}_{allocation_size}.dmp', 'wb') as fp:
        #     fp.write(cached_data)
        # temp = 0



def InitializeWindows10Profile(profile):
    """Initialize windows 10 profiles."""
    win8.InitializeWindows8Profile(profile)
    profile.add_overlay(win10_overlays)

    profile.add_classes(dict(
        _POOL_HEADER=_POOL_HEADER
    ))

    if profile.metadata("arch") == "AMD64":
        profile.add_overlay(win10_undocumented_amd64)
    else:
        profile.add_overlay(win10_undocumented_i386)

    # Older Win10 releases include SystemNodeInformation inside
    # _MI_SYSTEM_INFORMATION
    if not profile.has_type("_MI_HARDWARE_STATE"):
        profile.add_overlay({
            "_MI_SYSTEM_INFORMATION": [None, {
                "SystemNodeInformation": [None, ["Pointer", dict(
                    target="Array",
                    target_args=dict(
                        target="_MI_SYSTEM_NODE_INFORMATION",
                        count=lambda x: x.obj_profile.get_constant_object(
                            "KeNumberNodes", "unsigned int").v(),
                    )
                )]],
            }],
        })
