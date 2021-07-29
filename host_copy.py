from pyzabbix import ZabbixAPI
from ZabbixWorker import ZabbixWorker


target_url = 'https://monitoring.dv.local/'
target_user='m.gerbersgagen'
target_password='KmPO6sssqVDk'

source_url = 'http://10.87.188.76/zabbix'
source_user = 'm.gerbersgagen'
source_password = 'KL29JPMe'

host_list = ['V01-14-TS02.dv.local']


def host_copy(groupid):
    for hostname in host_list:
        with ZabbixAPI(url=source_url, user=source_user, password=source_password) as zapi:
           original_host = zapi.host.get(
                filter={'host': hostname},
                selectGroups='extend',
                selectInterfaces='extend',
                selectMacros='extend'
            )[0]
           disable = zapi.host.update(
                hostid=original_host['hostid'],
                status=1,
                host=original_host['host'] + '-history',
                name=original_host['name'] + ' (history)'
            )
           with ZabbixAPI(url=target_url, user=target_user, password=target_password) as zapi:
                clone = zapi.host.create(
                    host=original_host['host'],
                    name=original_host['name'],
                    proxy_hostid=original_host['proxy_hostid'],
                    groups=[{'groupid': groupid}],
                    macros=original_host['macros'],
                    interfaces=[{'main': '1', 'type': '1', 'useip': '0', 'dns': original_host['interfaces'][0]['dns'],
                                 'port': '10050', 'bulk': '1', 'ip': '127.0.0.1'}])
                print('copy host ' + hostname)


print(host_copy(24))
