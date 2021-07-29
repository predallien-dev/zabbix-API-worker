# скрипт нуждается в дичайшей переделке, учитывая что теперь есть класс ZabbixWoker

from pyzabbix import ZabbixAPI

target_url = 'https://monitoring.dv.local/'
user='m.gerbersgagen'
password='KmPO6sssqVDk'

hostlist=['10575', '10576', '10577', '10578', '10579', '10580', '10581', '10582', '10583', '10584', '10585', '10586',
         '10587', '10588', '10589', '10590', '10591', '10592', '10593', '10594', '10595', '10596', '10597', '10598',
         '10599', '10600', '10601', '10602', '10603', '10604', '10605', '10606', '10607', '10608', '10609', '10610',
         '10611', '10612']
hostip= [
'10.87.188.51',
'172.18.255.62',
'172.18.255.63',
'172.18.255.64',
'172.18.255.65',
'10.87.188.52',
'172.18.255.34',
'172.18.255.35',
'172.18.255.36',
'172.18.255.37',
'172.18.255.68',
'172.18.255.69',
'172.18.255.57',
'172.18.255.58',
'172.18.255.59',
'172.18.255.60',
'172.18.255.61',
'172.18.255.66',
'172.18.255.67',
'10.87.188.49',
'10.87.188.50',
'172.18.255.38',
'172.18.254.22',
'172.18.254.21',
'172.18.253.5',
'172.18.253.6',
'172.18.253.7',
'172.18.253.8',
'172.18.255.52',
'172.18.255.51',
'172.18.255.50',
'172.18.255.49',
'172.18.255.48',
'172.18.255.47',
'172.18.255.46',
'172.18.255.45',
'172.18.255.70',
'172.18.255.66'
]


def get_hosts_id():
    groupid=input()
    with ZabbixAPI(url=target_url, user=user, password=password) as zapi:
        hostlist = zapi.host.get(groupids=groupid, output=['host'])
        ip_list = []
        i = 0
        while i < len(hostlist):
            ip_addr = hostlist[i].get('hostid')
            ip_list.append(ip_addr)
            i += 1
        return (ip_list)

def get_hosts_ips():
    with ZabbixAPI(url=target_url, user=user, password=password) as zapi:
        ip_retrieve = zapi.hostinterface.get(hostids=hostlist, output=['ip'])
        names_list = []
        i = 0
        while i < len(ip_retrieve):
            ip_addr = ip_retrieve[i].get('ip')
            names_list.append(ip_addr)
            i += 1
        return(names_list)


def bussiness():
    with ZabbixAPI(url=target_url, user=user, password=password) as zapi:
        i = 0
        while i < len(hostlist):
                SNMP_add = zapi.hostinterface.create(
                        dns='',
                        hostid=hostlist[i],
                        ip=hostip[i],
                        main='1',
                        port='161',
                        type='2',
                        useip='1',
                        details={
                            'version': '2',
                            'bulk': '1',
                            'community': 'public'
                        }

                    )
                i += 1

bussiness()
