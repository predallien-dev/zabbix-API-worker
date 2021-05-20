# Это тест интеграцтии с гитхабом, не нужно его исполнять

from pyzabbix.api import ZabbixAPI

zapi = ZabbixAPI(url='https://monitoring.avilex.ru/zabbix', user='m.gerbersgagen', password='Masterimargarit5*')
res = zapi.do_request(method="host.create", params= {
                          "host": "testapi",
                          "interfaces": [
                              {
                                  "type": '1',
                                  "main": '1',
                                  "useip": '1',
                                  "ip": '192.168.10.252',
                                  "dns": '',
                                  "port": '10050'}],
                          "groups": [
                              {"groupid": "50"}
                          ],
                      }
                      )
print(res)
zapi.user.logout()
