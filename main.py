import json
import os
rootdir = "Cuckoo Dataset"

#Get API CALLS FROM BEHAVIOR ANALYSIS
def get_json(path):
    with open(path, 'r') as f:
        data = json.load(f)
        behaviour = data['behavior']
        if 'apistats' in data['behavior']:
            for apicall in behaviour['apistats']:
                for api in behaviour['apistats'][apicall]:
                    print(api+",", end = ""),
    print("")

def get_static(path):
    with open(path,'r') as f:
        data = json.load(f)
        static = data['static']['pe_imports']

        for imports in static:
            for imports1 in imports['imports']:
                print(imports1['name'], end = ",")
    print()

def get_static_dll(path):
    with open(path,'r') as f:
        data = json.load(f)
        static = data['static']['pe_imports']
        for imports in static:
            print(imports['dll'], end = ",")
    print()

#get SHA1 of Given Sample
def get_hex(path):
    with open(path, 'r') as f:
        data = json.load(f)
        target = data['target']
        info = data['info']
        print(target['file']['sha1']+","+str(info['score'])+",", end = ""),

        #get_Result(target['file']['sha1'])
# Solve Problem get Process
def get_process(path):
    with open(path, 'r') as f:
        data = json.load(f)
        behaviour = data['behavior']
        for process in behaviour['processes']['process_name']:
            for proc in process:
                print(proc+",", end = ""),
    print()


for subdir, dirs, files in os.walk(rootdir):
    for file in files:
        if file =='report.json':
            path = os.path.join(subdir, file)
            get_hex(path)
            get_json(path)
            get_static(path)
            get_static_dll(path)
