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


def b_tree_resolve(profile, **kwargs):
    b_tree = profile.Object(type_name="_B_TREE", profile=profile, **kwargs)

    if not bool(b_tree.Leaf.v()):
        return b_tree
    else:
        return profile.Object(type_name="_B_TREE_LEAF", profile=profile,
                              **kwargs)


win10_mem_comp_common_vtypes = {
    '_B_TREE_LEAF_NODE': [0x8, {
        'Key': [0x0, ['unsigned int']],
        'Value': [0x4, ['unsigned int']],
    }],
    '_ST_PAGE_RECORD': [None, {
        'Key': [0x0, ['unsigned int']],
        'CompressedSize': [0x4, ['unsigned short int']],
        'NextKey': [0x4, ['unsigned int']],
    }],
    '_SMKM': [None, {
        'StoreMetaDataArray': [0x0,
                               ['Array', dict(
                                   target="Pointer",
                                   count=32,
                                   target_args=dict(
                                       target='Array',
                                       target_args=dict(
                                           count=32,
                                           target="_SMKM_STORE_METADATA")))]]
    }],
    '_SM_GLOBALS': [None, {
        'SmkmStoreMgr': [0x0, ['_SMKM_STORE_MGR']]
    }]
}

win10_mem_comp_common_x86_vtypes = {
    '_B_TREE_NODE': [0x8, {
        'Key': [0x0, ['unsigned int']],
        'Child': [0x4, ['Pointer', dict(target=b_tree_resolve)]]
    }],
    '_B_TREE_LEAF': [None, {
        'Elements': [0x0, ['unsigned short int']],
        'Level': [0x2, ['unsigned char']],
        'Leaf': [0x3, ['unsigned char']],
        'LeftChild': [0x4, ['Pointer', dict(target=b_tree_resolve)]],
        'Nodes': [0x8, ['Array', dict(target='_B_TREE_LEAF_NODE',
                                      count=lambda x: x.Elements)]]
    }],
    '_B_TREE': [None, {
        'Elements': [0x0, ['unsigned short int']],
        'Level': [0x2, ['unsigned char']],
        'Leaf': [0x3, ['unsigned char']],
        'LeftChild': [0x4, ['Pointer', dict(target=b_tree_resolve)]],
        'Nodes': [0x8, ['Array', dict(target='_B_TREE_NODE',
                                      count=lambda x: x.Elements)]]
    }],
    '_ST_STORE': [None, {
        'StDataMgr': [0x38, ['_ST_DATA_MGR']]
    }],
    '_SMHP_CHUNK_METADATA': [None, {
        'ChunkPtrArray': [0x0,
                          ['Array', dict(target='Pointer',
                                         target_args=dict(
                                             target='Array',
                                             target_args=dict(
                                                 target='Pointer',
                                                 target_args=dict(
                                                     target='Void'))))]],
        'BitValue': [0x88, ['unsigned int']],
        'PageRecordsPerChunkMask': [0x8C, ['unsigned int']],
        'PageRecordSize': [0x90, ['unsigned int']],
        'ChunkPageHeaderSize': [0x98, ['unsigned int']],
    }],
    '_SMKM_STORE_METADATA': [0x14, {
        'SmkmStore': [0x0, ['Pointer', dict(target="_SMKM_STORE")]],
    }],
    '_SMKM_STORE_MGR': [None, {
        'Smkm': [0x0, ['_SMKM']],
        'KeyToStoreTree': [0xF4, ['Pointer', dict(target=('_B_TREE'))]]
    }],
}

win10_mem_comp_common_x64_vtypes = {
    '_B_TREE_NODE': [0x10, {
        'Key': [0x0, ['unsigned int']],
        'Value': [0x4, ['unsigned int']],
        'Child': [0x8, ['Pointer', dict(target=b_tree_resolve)]]
    }],
    '_B_TREE_LEAF': [None, {
        'Elements': [0x0, ['unsigned short int']],
        'Level': [0x2, ['unsigned char']],
        'Leaf': [0x3, ['unsigned char']],
        'LeftChild': [0x8, ['Pointer', dict(target=b_tree_resolve)]],
        'Nodes': [0x10, ['Array', dict(target='_B_TREE_LEAF_NODE',
                                       count=lambda x: x.Elements)]]
    }],
    '_B_TREE': [None, {
        'Elements': [0x0, ['unsigned short int']],
        'Level': [0x2, ['unsigned char']],
        'Leaf': [0x3, ['unsigned char']],
        'LeftChild': [0x8, ['Pointer', dict(target=b_tree_resolve)]],
        'Nodes': [0x10, ['Array', dict(target='_B_TREE_NODE',
                                       count=lambda x: x.Elements)]]
    }],
    '_SMHP_CHUNK_METADATA': [None, {
        'ChunkPtrArray': [0x0,
                          ['Array', dict(target='Pointer',
                                         target_args=dict(
                                             target='Array',
                                             target_args=dict(
                                                 target='Pointer',
                                                 target_args=dict(
                                                     target='Void'))))]],
        'BitValue': [0x108, ['unsigned int']],
        'PageRecordsPerChunkMask': [0x10C, ['unsigned int']],
        'PageRecordSize': [0x110, ['unsigned int']],
        'ChunkPageHeaderSize': [0x118, ['unsigned int']],
    }],
    '_ST_STORE': [None, {
        'StDataMgr': [0x50, ['_ST_DATA_MGR']]
    }],
    '_SMKM_STORE_METADATA': [0x28, {
        'SmkmStore': [0x0, ['Pointer', dict(target="_SMKM_STORE")]],
    }],
    '_SMKM_STORE_MGR': [None, {
        'Smkm': [0x0, ['_SMKM']],
        'KeyToStoreTree': [0x1C0, ['Pointer', dict(target=('_B_TREE'))]]
    }],

}

win10_mem_comp_x64_1903 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3E0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1848, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x19A8, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x86_1903 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x224, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1184, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x1254, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x64_1809 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3E0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1848, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x19A8, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x86_1809 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x224, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1184, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x1254, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x64_1803 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3E0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1848, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x19A8, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x86_1803 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x224, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1184, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x1254, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x64_1709 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3E0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1848, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x19A8, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x86_1709 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x224, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1184, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x1254, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x64_1703 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3D0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1828, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x1988, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x86_1703 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x220, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1174, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x1244, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x64_1607 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0xC0, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x320, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x328, ['unsigned int']],
        'RegionIndexMask': [0x32C, ['unsigned int']],
        'CompressionAlgorithm': [0x3D0, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x17A8, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x1918, ['Pointer', dict(target="_EPROCESS")]]
    }],
}

win10_mem_comp_x86_1607 = {
    '_ST_DATA_MGR': [None, {
        'PagesTree': [0x0, ['Pointer', dict(target=b_tree_resolve)]],
        'ChunkMetaData': [0x6C, ['_SMHP_CHUNK_METADATA']],
        'SmkmStore': [0x1C0, ['Pointer', dict(target="_SMKM_STORE")]],
        'RegionSizeMask': [0x1C4, ['unsigned int']],
        'RegionIndexMask': [0x1C8, ['unsigned int']],
        'CompressionAlgorithm': [0x220, ['unsigned short int']],
    }],
    '_SMKM_STORE': [None, {
        'StStore': [0x0, ['_ST_STORE']],
        'CompressedRegionPtrArray': [0x1124, ['Pointer', dict(
                                            target='Array',
                                            target_args=dict(
                                                target='Pointer',
                                                target_args=dict(
                                                        target='Void')))]],
        'OwnerProcess': [0x1204, ['Pointer', dict(target="_EPROCESS")]]
    }],
}


def initialize_win10_mem_compression(profile, build_number):
    amd64 = profile.metadata("arch") == "AMD64"

    if build_number in [14393, 15063, 16299, 17134, 17763, 18362]:
        profile.add_overlay(win10_mem_comp_common_vtypes)
        if amd64:
            profile.add_overlay(win10_mem_comp_common_x64_vtypes)
        else:
            profile.add_overlay(win10_mem_comp_common_x86_vtypes)

    if build_number == 14393:
        if amd64:
            profile.add_overlay(win10_mem_comp_x64_1607)
        else:
            profile.add_overlay(win10_mem_comp_x86_1607)

        return True
    elif build_number == 15063:
        if amd64:
            profile.add_overlay(win10_mem_comp_x64_1703)
        else:
            profile.add_overlay(win10_mem_comp_x86_1703)

        return True
    elif build_number == 16299:
        if amd64:
            profile.add_overlay(win10_mem_comp_x64_1709)
        else:
            profile.add_overlay(win10_mem_comp_x86_1709)

        return True
    elif build_number == 17134:
        if amd64:
            profile.add_overlay(win10_mem_comp_x64_1803)
        else:
            profile.add_overlay(win10_mem_comp_x86_1803)

        return True
    elif build_number == 17763:
        if amd64:
            profile.add_overlay(win10_mem_comp_x64_1809)
        else:
            profile.add_overlay(win10_mem_comp_x86_1809)

        return True
    elif build_number == 18362:
        if amd64:
            profile.add_overlay(win10_mem_comp_x64_1903)
        else:
            profile.add_overlay(win10_mem_comp_x86_1903)

        return True

    return False
