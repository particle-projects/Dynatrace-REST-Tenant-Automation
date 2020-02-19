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

def load_jsons_as_text(path):
    JSONS = load_jsons(path, True)
    return JSONS


def load_jsons(path, loadAsText=False):
    jsonsList = os.listdir(path)
    JSONS = []
    for j in jsonsList:
        if '.json' in j:
            filePath = path + '/' + j
            if loadAsText:
                json_txt = (open(filePath, 'r', encoding='utf8')).read()
                JSONS.append(json_txt)
            else:
                JSONS.append(json.load(open(filePath, 'r')))
    return JSONS