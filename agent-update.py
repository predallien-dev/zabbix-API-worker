# оставлю пока, не пропадать же коду

import fileinput
import sys

def replaceAll(file, searchExp, replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp, replaceExp)
        sys.stdout.write(line)

replaceAll('/etc/zabbix/zabbix_agentd.conf', '')
