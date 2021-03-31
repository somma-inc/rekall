#
# @author       JeongPil, Lee(jeongpil@somma.kr)
# @date         2021/01/05 10:00 created.
# @copyright    (C)Somma,Inc. All rights reserved.
#
import csv
import os


class Exporter:
    def __init__(self, file_path: str):
        # 이전 파일이 있는 경우 무조건 지우고 새로 만든다.
        if os.path.exists(file_path) is True:
            os.remove(file_path)
        self.file_handle = open(file_path, 'w', encoding='utf-8', newline='')
        self.exporter = csv.writer(self.file_handle, delimiter='\t', quoting=csv.QUOTE_NONNUMERIC)

    def __del__(self):
        if hasattr(self, 'file_handle'):
            assert self.file_handle is not None
            self.file_handle.close()

    def export_to_tsv(self, data: list):
        self.exporter.writerow(data)

    def export_to_json(self, data: list):
        pass

    def export_to_csv(self, data: list):
        pass

    def export_to_data_frame(self, data: list):
        pass
