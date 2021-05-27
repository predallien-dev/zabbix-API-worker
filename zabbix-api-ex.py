from pyzabbix.api import *

zapi = ZabbixAPI(url='https://monitoring.avilex.ru/zabbix/', user='m.gerbersgagen', password='Masterimargarit5*')
#groups = zapi.hostgroup.get(output=['itemid','name'])
#for group in groups:
#        print (group['groupid'],group['name'])

zapi.do_request()

)