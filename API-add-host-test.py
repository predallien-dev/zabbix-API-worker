from pyzabbix.api import ZabbixAPI

host_name = input('Enter hostname: ')
ip_addr = input('Enter IP address of new host: ' )

with  ZabbixAPI(url='https://monitoring.avilex.ru/zabbix/', user='m.gerbersgagen', password='*') as zapi:
    res = zapi.do_request(method="host.create", params= {
                          "host": host_name,
                          "interfaces": [
                              {
                                  "type": '1',
                                  "main": '1',
                                  "useip": '1',
                                  "ip": ip_addr,
                                  "dns": '',
                                  "port": '10050'}],
                          "groups": [
                              {"groupid": "214"}
                          ],
                      }
                      )
if res:
    print('Success')

