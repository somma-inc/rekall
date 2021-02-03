import csv

class OutputResult:
    "object 생성을 위한 기본 key가 필요합니다"
    def __init__(self, **kwargs):
        self.object=kwargs

    def make_tsv(self, filename):
        with open(filename+".tsv",'w', newline="") as f:
            w = csv.writer(f, delimiter='\t')
            for i in self.object.keys():
                w.writerow(self.object[i].values())

    def make_json(self, filename):
        pass

    def make_csv(self, filename):
        pass

    def make_data_frame(self, filename):
        pass

    