import os
import json


def load_ssh_file(shell_file):
    """
    Function to read and parse a shell file containing a SHELL command and a control variable 
    if it should be exeuted as root.
    """
    cmds = []
    #shell_raw = (open(shell_file, 'r', encoding='utf8')).read()
    with open(shell_file, 'r', encoding='utf8') as shell_raw:
        for line in shell_raw:
            if not line.startswith('#'):
                if len(line.strip()) > 3:
                    cmd = line.rstrip().split(',')
                    cmd[1] = str2bool(cmd[1])
                    cmds.append(cmd)
    return cmds


def str2bool(v):
    return v.strip().lower() in ("yes", "true", "t", "1")


def load_replacement_file(path):
    replacementFile = {}
    dic_result = load_jsons_in_dic(path, loadAsText=False, fileType='.replacement')
    # We return one replacement value (there should be only one)
    for v in dic_result.values():
        replacementFile = v
    return replacementFile

def load_jsons_dic_as_text(path):
    JSONS = load_jsons_in_dic(path, True)
    return JSONS


def load_jsons_in_dic(path, loadAsText=False, fileType='.json'):
    # Validate if directory exists, otherwise return empty array
    JSONS = {}
    if os.path.exists(path):
        jsonsList = os.listdir(path)
        for j in jsonsList:
            if fileType in j:
                fileNameAsKey = j.replace(fileType, '')
                filePath = path + '/' + j
                if loadAsText:
                    json_txt = (open(filePath, 'r', encoding='utf8')).read()
                    JSONS[fileNameAsKey] = json_txt
                else:
                    json_raw = json.load(open(filePath, 'r'))
                    JSONS[fileNameAsKey] = json_raw
    return JSONS
