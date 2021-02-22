import os

from rekall.plugins.windows.modscan import PoolScanModuleFast
from rekall.plugins.windows import common
from rekall.plugins.windows import modules
from rekall.plugins.tools.exporter import Exporter

import os
import datetime


class ModMerge(common.PoolScannerPlugin):
    "모듈 아티팩트 통합 플러그인"

    name = "modmerge"

    table_header = [
        dict(name="offset", style="address"),
        dict(name="name", width=20),
        dict(name="base", style="address"),
        dict(name="size", style="address"),
        dict(name="file", width=60),
        dict(name="is_modules")
    ]

    __args = [
        dict(name='output_file',
             default=os.path.join(
                 '.', f'modmerge_{datetime.datetime.utcnow().timestamp()}.tsv'))
    ]
    
    scanner_defaults = dict(
        scan_kernel_nonpaged_pool=True
    )

    def collect(self):
        object_tree_plugin = self.session.plugins.object_tree()

        module_offset=set()
        modscan_offset=set()

        #Plugin : module 
        for module in modules.Modules.lsmod(self):
            module_offset.add(module.obj_offset)
        

        #Plugin : unloaded_modules
        unloaded_table = self.profile.get_constant_object(
            "MmUnloadedDrivers",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="_UNLOADED_DRIVER",
                    count=self.profile.get_constant_object(
                        "MmLastUnloadedDriver", "unsigned int").v(),
                    )
                )
            )
        # In Windows 10 this has moved to the MiState.
        if unloaded_table == None:
            mistate = self.profile.get_constant_object(
                "MiState", target="_MI_SYSTEM_INFORMATION")

            unloaded_table = mistate.multi_m(
                "UnloadedDrivers",
                "Vs.UnloadedDrivers"
            ).dereference_as(
                "Array",
                target_args=dict(
                    target="_UNLOADED_DRIVERS",
                    count=mistate.LastUnloadedDriver)
            )

        #Plugin : modscan
        exporter = Exporter(self.plugin_args.output_file)

        for run in self.generate_memory_ranges():
            scanner = PoolScanModuleFast(profile=self.profile,
                                         session=self.session,
                                         address_space=run.address_space)
            
            for pool_obj in scanner.scan(run.start, run.length):
                is_modules=''
                if not pool_obj:
                    continue
                
                ldr_entry = self.profile._LDR_DATA_TABLE_ENTRY(
                    vm=run.address_space, offset=pool_obj.obj_end)

                # Must have a non zero size.
                if ldr_entry.SizeOfImage == 0:
                    continue

                # Must be page aligned.
                if ldr_entry.DllBase & 0xFFF:
                    continue
                
                modscan_offset.add(ldr_entry.obj_offset)
                # modules.Modules.

                try:
                    if ldr_entry.obj_offset in module_offset:
                        is_exists_in_modules=True
                    else:
                        is_exists_in_modules=False
                except Exception as e:
                    is_exists_in_modules="error"

                modmerge_dict=dict(
                    dllname = ldr_entry.BaseDllName.v(vm=self.kernel_address_space),
                    dllsize = ldr_entry.SizeOfImage,
                    dllpath = ldr_entry.FullDllName.v(vm=self.kernel_address_space)
                )
                
                exporter.export_to_tsv(modmerge_dict.values())
                yield (ldr_entry.obj_offset,
                       ldr_entry.BaseDllName.v(vm=self.kernel_address_space),
                       ldr_entry.DllBase,
                       ldr_entry.SizeOfImage,
                       ldr_entry.FullDllName.v(vm=self.kernel_address_space),
                       is_exists_in_modules
                       )
                # print((ldr_entry.LoadTime.u))
        # print(int(os.get_terminal_size().columns/2) * "-")
        # print("[List of unloaded modules results]")
        # print(int(os.get_terminal_size().columns/2) * "-")

        for driver in unloaded_table:
            unload_dict=dict(
                dllname = driver.Name,
                dllsize = '',
                dllpath = ''
            )
            exporter.export_to_tsv(unload_dict.values())
            print(driver.Name,"\t\t",
            driver.StartAddress.v(),"\t",
            driver.EndAddress.v(),"\t",
            driver.CurrentTime)

        print(int(os.get_terminal_size().columns/2) * "-")
        print("[List of modules not included in modscan results]")
        print(module_offset.difference(modscan_offset))
        if (module_offset.difference(modscan_offset)) is None:
            print("Result not found")
        print(int(os.get_terminal_size().columns/2) * "-")
        # print("modules_length : ",len(module_offset))
        # print("modscan_length : ",len(modscan_offset))
        # print("modules: ",(module_offset))
        # print("modscan : ",(modscan_offset))
        # print(modscan_offset.difference(module_offset))