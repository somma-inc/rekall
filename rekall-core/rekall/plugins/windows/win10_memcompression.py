# Copyright (C) 2019 FireEye, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Authors:
# Sebastian Vogl <sebastian.vogl@FireEye.com>
# Blaine Stancill <blaine.stancill@FireEye.com>

"""This file adds support for memory compression on Windows 10.

Windows 10 adds a new memory compression feature. When used, pages are
compressed before they are written to the pagefile. The classes within
this file handle compressed pages and return the decompressed data
when a compressed page is read.
"""

from rekall import addrspace
from rekall import config
from rekall.plugins.windows import pagefile
from rekall.plugins.addrspaces import xpress
from rekall.plugins.addrspaces import intel

PAGE_SIZE = 0x1000
XPRESS_ALGO = 3


config.DeclareOption("--vspagefilenumber", type = "int", default = 2,
                     group = "Windows 10 Memory Compression",
                     help = ('Specify the page file number corresponding'
                             ' to the Virtual Store (default is 2)'))


class WindowsCompressedMemoryDescriptor(intel.AddressTranslationDescriptor):
    """A descriptor for compressed memory pages (Windows 10)."""

    def __init__(self, address=0, pagefile_number=0, pte_value=0, session=None):
        super().__init__(session=session)
        self.address = address
        self.pagefile_number = pagefile_number

        # Derive Page Key
        if self.session.GetCache("build_number") >= 17134:
            pte = self.session.profile._MMPTE()
            pte.u.Long = pte_value
            soft_pte = pte.u.Soft

            if pte_value & soft_pte.SwizzleBit.mask:
                self.page_key = (pagefile_number << 28) | soft_pte.PageFileHigh
            else:
                mistate = self.session.profile.get_constant_object(
                    "MiState", "_MI_SYSTEM_INFORMATION")

                self.page_key = (pagefile_number << 28) | (
                            soft_pte.PageFileHigh & ~(
                                mistate.Hardware.InvalidPteMask >> 32))
        else:
            self.page_key = (pagefile_number << 28) | (address >> 12)


    def render(self, renderer):
        renderer.format("This entry refers to a compressed page with "
                        "key {0}.\n", hex(self.page_key))

        try:
            renderer.format("\t -> SMKM store index: {0}\n",
                            self.smkm_store_index)
            renderer.format("\t -> Region key: {0:#x}\n", self.region_key)
            renderer.format("\t -> Page Record: {0:#x}\n", self.record.v())
            renderer.format("Compressed data located @ {0:#x} "
                            "(compressed size {1:#x}, Owner PID {2})\n",
                            self.resolved_address,
                            self.record.CompressedSize.v(),
                            self.owner_pid)
        except AttributeError:
            pass

    def __call__(self, *args, **kwargs):
        return self


class WindowsMemoryCompression(object):
    """Handles compressed pages on Windows 10."""

    def __init__(self, session):
        self.session = session
        self.debug = self.session.logging.debug

    @property
    def sm_globals(self):
        if not hasattr(self, "_sm_globals"):
            self._sm_globals = (
                self.session.profile.get_constant_object(
                    "SmGlobals", "_SM_GLOBALS"))
        return self._sm_globals

    def decompress(self, descriptor, data):
        if len(data) == PAGE_SIZE:
            # In case the compressed size is larger than a page, the data
            # Does not seem to be compressed, so we just return data.
            return data

        if descriptor.st_data_mgr.CompressionAlgorithm.v() != XPRESS_ALGO:
            return None

        try:
            length = descriptor.record.CompressedSize.v() & 0xFFF
            result = xpress.xpress_decode(data[:length])
        except Exception as e:
            self.debug("Error decompressing: {0}".format(str(e)))
            return None

        len_decompressed = len(result)
        if len_decompressed != PAGE_SIZE:
            self.debug("Decompressed data is not the "
                       "size of a page: {0:#x}".format(len_decompressed))
            return None

        return result

    def bisect_right(self, root, key):
        """Custom bisect right to avoid list copies"""
        lo = 0
        hi = root.Elements

        while lo < hi:
            mid = (lo + hi) // 2
            if key < root.Nodes[mid].Key.v():
                hi = mid
            else:
                lo = mid + 1
        return lo

    def b_tree_search(self, root, key):
        if not root:
            return None

        self.debug("Root: {0:#x}, Key: {1:#x}".format(root, key))

        leaf = bool(root.Leaf.v())
        self.debug("\tLeaf? {0}".format(leaf))

        index = self.bisect_right(root, key)
        self.debug("\tNode Index: {0:#x}".format(index))

        if index:
            node = root.Nodes[index - 1]
            self.debug("\tNode: {0:#x}".format(node))

            if not leaf:
                return self.b_tree_search(node.Child.dereference(), key)

            # Correct key found from leaf
            self.debug("\tNode Key: {0:#x}".format(node.Key.v()))
            if node.Key.v() == key:
                self.debug("\tNode Value: {0:#x}".format(node.Value.v()))
                return node.Value.v()

            # Worst case, no key found and we're at a leaf
            return None
        else:
            # If it's less than all the keys, use the root's left-most child
            return self.b_tree_search(root.LeftChild.dereference(), key)

    def get_smkm_store_index(self, descriptor):
        root = self.sm_globals.SmkmStoreMgr.KeyToStoreTree

        self.debug("Target Addr: {0:#x}".format(descriptor.address))
        self.debug("Page Key: {0:#x}".format(descriptor.page_key))

        index = self.b_tree_search(root, descriptor.page_key)
        if index is None:
            raise KeyError("Could not find SMKM store index for "
                           "page key {0:#x}".format(descriptor.page_key))

        if (index >> 24) & 0xFF == 1:
            raise KeyError("Smkm store index is not valid for "
                           "page key: {0:#x}".format(descriptor.page_key))

        descriptor.smkm_store_index = index & 0x3FF
        self.debug("Smkm Store Index: {0}".format(descriptor.smkm_store_index))

    def get_region_key(self, descriptor):
        meta_index = descriptor.smkm_store_index >> 5
        smkm_store_index = descriptor.smkm_store_index & 0x1F

        smkm = self.sm_globals.SmkmStoreMgr.Smkm
        self.debug("Smkm: {0:#x}".format(smkm))

        smkm_metadata = smkm.StoreMetaDataArray[meta_index][smkm_store_index]
        self.debug("Smkm Metadata: {0:#x}".format(smkm_metadata))

        descriptor.smkm_store = smkm_metadata.SmkmStore
        self.debug("Smkm Store: {0:#x}".format(smkm_metadata.SmkmStore))

        descriptor.st_data_mgr = smkm_metadata.SmkmStore.StStore.StDataMgr
        self.debug("StDataMgr: {0:#x}".format(descriptor.st_data_mgr))

        root = descriptor.st_data_mgr.PagesTree
        self.debug("Pages Tree: {0:#x}".format(root))

        region_key = self.b_tree_search(root, descriptor.page_key)
        if region_key is None:
            raise KeyError("Could not find region key for "
                           "page key {0:#x}".format(descriptor.page_key))

        descriptor.region_key = region_key
        self.debug("Region Key: {0:#x}".format(region_key))

    def get_page_record(self, descriptor):
        region_key = descriptor.region_key
        meta_data = descriptor.st_data_mgr.ChunkMetaData
        self.debug("Chunk Metadata: {0:#x}".format(meta_data))

        region_index_0 = region_key >> (meta_data.BitValue.v() & 0xFF)
        self.debug("Region Index 0: {0:#x}".format(region_index_0))

        region_index_1 = int(region_index_0).bit_length() - 1
        self.debug("Region Index 1: {0:#x}".format(region_index_1))

        region_index_2 = (((region_key &
                            meta_data.PageRecordsPerChunkMask.v()) *
                           meta_data.PageRecordSize.v()) & 0xFFFFFFF)
        self.debug("Region Index 2: {0:#x}".format(region_index_2))

        # Calculate region index 0
        if self.session.GetCache("build_number") >= 15063:
            # Bittest and complement
            region_index_0 = ((1 << (region_index_1 & 0xFF)) ^ region_index_0)

            if self.session.profile.metadata("arch") == "AMD64":
                region_index_0 *= 2
            else:
                region_index_0 *= 3
        else:
            region_index_0 = ((1 << region_index_1) ^ region_index_0) << 1

        self.debug("Region Index 0: {0:#x}".format(region_index_2))

        base_addr = meta_data.ChunkPtrArray[region_index_1][region_index_0].v()
        self.debug("Base Aaddr: {0:#x}".format(base_addr))

        record = self.session.profile._ST_PAGE_RECORD(
            base_addr +
            meta_data.ChunkPageHeaderSize.v() +
            region_index_2)
        self.debug("StPage Record: {0:#x}".format(record.v()))

        if record.Key.v() == 0xFFFFFFFF:
            descriptor.region_key = record.NextKey.v()
            return self.get_page_record(descriptor)

        descriptor.record = record

    def get_address(self, descriptor):
        record = descriptor.record
        key = record.Key.v()
        self.debug("Record Key: {0:#x}".format(key))

        index = (key >> (descriptor.st_data_mgr.RegionIndexMask.v() & 0xFF))
        self.debug("Region Index: {0:#x}".format(index))

        base = descriptor.smkm_store.CompressedRegionPtrArray[index].v()
        if self.session.profile.metadata("arch") == "AMD64":
            base &= 0x7FFFFFFFFFFF0000
        else:
            base &= 0x7FFF0000
        self.debug("Region Base: {0:#x}".format(base))

        offset = (key & descriptor.st_data_mgr.RegionSizeMask.v()) << 4
        self.debug("Page Offset: {0:#x}".format(offset))

        descriptor.resolved_address = base + offset
        self.debug("Resolved Page Addr: {0:#x}".format(
            descriptor.resolved_address))

    def get_owning_process(self, descriptor):
        smkm_store = descriptor.smkm_store
        descriptor.owner_pid = smkm_store.OwnerProcess.pid.v()
        self.debug("Owner Process: {}".format(descriptor.owner_pid))

    def resolve(self, descriptor):
        try:
            self.get_smkm_store_index(descriptor)
            self.get_region_key(descriptor)
            self.get_page_record(descriptor)
            self.get_address(descriptor)
            self.get_owning_process(descriptor)
        except KeyError as e:
            return (intel.InvalidAddress,
                    "Windows decompression error:\n{0}".format(str(e)))

        return descriptor


class WindowsCompressionMixin(pagefile.WindowsPagedMemoryMixin):
    """A mixin to implement windows specific paged memory address spaces.

    This mixin allows us to share code between 32 and 64 bit implementations.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Memory compression
        self._compression = WindowsMemoryCompression(self.session)
        self.debug = self.session.logging.debug

    def _resolve(self, vaddr):
        aligned_vaddr = vaddr & self.PAGE_MASK
        collection = self.describe_vtop(vaddr)

        if isinstance(collection[-1],
                      intel.PhysicalAddressDescriptor):
            paddr = collection[-1].address & self.PAGE_MASK
        else:
            paddr = None

        self._tlb.Put(aligned_vaddr, paddr)
        return (self._tlb.Get(vaddr), collection)

    def vtop(self, vaddr):
        # If the virual address already maps to a physical address, return it
        vaddr = int(vaddr)
        paddr = super().vtop(vaddr)
        if paddr:
            return paddr

        # Attempt to return a physical address for compressed pages.
        # Mainly to allow plugins to work if using vtop() to check if
        # an address is valid.
        collection = None
        try:
            paddr = self._tlb.Get(vaddr)
        except KeyError:
            paddr, collection = self._resolve(vaddr)

        if paddr is None and collection is None:
            paddr, collection = self._resolve(vaddr)

        if (paddr is None and
                len(collection.descriptors) > 0 and
                isinstance(collection[-1],
                           WindowsCompressedMemoryDescriptor)):
            # Compressed memory
            descriptor = collection[-1]

            # Try to translate the resolved address
            cc = self.session.plugins.cc(descriptor.owner_pid)
            with cc:
                cc.SwitchContext()
                paddr = self.session.default_address_space.vtop(
                    descriptor.resolved_address)

        return paddr

    def _read_chunk(self, vaddr, length):
        """Handle reads of compressed pages.

        We overwrite _read_chuck from PagedAddressSpace to be able
        to return the decompressed data when a compressed page is read.
        """
        to_read = min(length, self.PAGE_SIZE - (vaddr % self.PAGE_SIZE))
        collection = None

        # Force resolution of the pagefiles as we may need them during the
        # lookup.
        _ = self.session.GetParameter("pagefiles")

        try:
            paddr = self._tlb.Get(vaddr)
        except KeyError:
            paddr, collection = self._resolve(vaddr)

        if paddr is None and collection is None:
            paddr, collection = self._resolve(vaddr)

        if (paddr is None and
                len(collection.descriptors) > 0 and
                isinstance(collection[-1],
                           WindowsCompressedMemoryDescriptor)):
            # Compressed memory
            descriptor = collection[-1]

            # Read the compressed data in the context of the owning process
            compressed_size = descriptor.record.CompressedSize.v()

            # Try to translate the resolved address
            cc = self.session.plugins.cc(descriptor.owner_pid)

            with cc:
                cc.SwitchContext()
                compressed_data = self.session.default_address_space.read(
                    descriptor.resolved_address,
                    compressed_size)

            data = self._compression.decompress(descriptor, compressed_data)
            if data is None:
                return addrspace.ZEROER.GetZeros(to_read)

            offset = vaddr & (self.PAGE_SIZE - 1)
            return data[offset:offset + to_read]
        elif (paddr is None and
              len(collection.descriptors) > 0 and
              isinstance(collection[-1],
                         pagefile.WindowsPagefileDescriptor)):
            # Paged out
            descriptor = collection[-1]

            pf_as = self.session.GetParameter("pagefile_address_space", None)

            if pf_as is None:
                device = self.session.blk_devices.open("ide0-hd0")
                partition = device.partition(1)
                fs = partition.filesystem()
                pf_as = fs.MFTEntryByName("pagefile.sys").open_file()
                self.session.SetCache("pagefile_address_space", pf_as)

            return pf_as.read(descriptor.address, to_read)
        elif paddr is None:
            return addrspace.ZEROER.GetZeros(to_read)

        return self.base.read(paddr, to_read)

    def _get_pagefile_mapped_address(self, pagefile_number, pagefile_address):
        """Disable the method of the base class.

        We overwrite this function to ensure it does not return a PTE.
        If the processed entry require pagefile access, we will handle
        this in the corresponding "_describe_xxx" method.
        """
        return None

    def _describe_pagefile(self, collection, pte_value):
        if len(collection.descriptors) <= 0:
            return None

        descriptor = collection[-1]
        if not isinstance(descriptor,
                          pagefile.WindowsPagefileDescriptor):
            # If this does not involve the pagefile, we are done.
            return None

        pagefile_addr = descriptor.address
        pagefile_num = descriptor.pagefile_number

        # If we are in the process of resolving the pagefiles, break
        # re-entrancy.
        if self._resolving_pagefiles:
            return None

        self._resolving_pagefiles = True
        pagefiles = self.session.GetParameter("pagefiles")

        pagefile_name = None
        pf_struct_address = None
        try:
            pagefile_name, pf_struct_address = pagefiles[pagefile_num]
        except (KeyError, ValueError):
            pass

        except RuntimeError:
            # Sometimes we can't recover the name of the pagefile because it
            # is paged. We just take a guess here.
            pagefile_name = u"c:\\pagefile.sys"

        finally:
            self._resolving_pagefiles = False

        if not pf_struct_address:
            # We are unable to resolve pagefiles. Fall back to default
            # page file number for Virtual Store or user provided value.
            if pagefile_num == self.session.GetParameter("vspagefilenumber"):
                descriptor = WindowsCompressedMemoryDescriptor(pagefile_addr,
                                                               pagefile_num,
                                                               pte_value,
                                                               self.session)
                descriptor = self._compression.resolve(descriptor)
                self._add_descriptor(collection, descriptor)
                return None
        else:
            # We resolved pagefiles. Check if it is a virtual pagefile.
            try:
                pf_struct = self.session.profile._MMPAGING_FILE(
                    pf_struct_address)
                virtual_pagefile = bool(pf_struct.VirtualStorePagefile.v())
            except AttributeError:
                virtual_pagefile = False

            if virtual_pagefile:
                descriptor = WindowsCompressedMemoryDescriptor(pagefile_addr,
                                                               pagefile_num,
                                                               pte_value,
                                                               self.session)
                descriptor = self._compression.resolve(descriptor)
                self._add_descriptor(collection, descriptor)
                return None
            else:
                pte_addr = None
                if self.base_as_can_map_files and pagefile_name:
                    pte_addr = self.base.get_mapped_offset(pagefile_name,
                                                           pagefile_addr)
                return pte_addr

    def _add_descriptor(self, collection, descriptor):
        if collection is not None:
            if isinstance(descriptor, tuple):
                collection.add(*descriptor)
            else:
                collection.add(descriptor)

    def _describe_pdpte(self, collection, pdpte_addr, vaddr):
        """Describe processing of the PDPTE."""
        super()._describe_pdpte(collection, pdpte_addr, vaddr)
        pdpte_value = self.read_pte(pdpte_addr)
        pde_addr = self._describe_pagefile(collection, pdpte_value)

        if pde_addr is not None:
            pde_value = self.read_pte(pde_addr)
            self.describe_pde(collection, pde_addr, pde_value, vaddr)

    def _describe_pde(self, collection, pde_addr, vaddr):
        """Describe processing of the PDE."""
        super()._describe_pde(collection, pde_addr, vaddr)
        pde_value = self.read_pte(pde_addr)
        pte_addr = self._describe_pagefile(collection, pde_value)

        if pte_addr is not None:
            pte_value = self.read_pte(pte_addr)
            self.describe_pte(collection, pte_addr, pte_value, vaddr)

    def describe_proto_pte(self, collection, pte_addr, pte_value, vaddr):
        """Describe the analysis of the prototype PTE."""
        super().describe_proto_pte(collection, pte_addr, pte_value, vaddr)
        paddr = self._describe_pagefile(collection, pte_value)

        if paddr is not None:
            collection.add(intel.PhysicalAddressDescriptor, address=paddr)

    def describe_pte(self, collection, pte_addr, pte_value, vaddr):
        """Describe the initial analysis of the PTE."""
        super().describe_pte(collection, pte_addr, pte_value, vaddr)
        paddr = self._describe_pagefile(collection, pte_value)

        if paddr is not None:
            collection.add(intel.PhysicalAddressDescriptor, address=paddr)


class WindowsIA32CompressedPagedMemoryPae(WindowsCompressionMixin,
                                          pagefile.WindowsIA32PagedMemoryPae):
    """A Windows specific IA32PagedMemoryPae with compression."""

    __pae = True


class WindowsAMD64CompressedPagedMemory(WindowsCompressionMixin,
                                        pagefile.WindowsAMD64PagedMemory):
    """A windows specific AMD64PagedMemory with compression.

    Implements support for reading the pagefile if the base address space
    contains a pagefile and uses compression.
    """
