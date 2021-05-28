from pyzabbix.api import ZabbixAPI

# создаем новый хост, без темплейтов с ручным вписыванием хостнейма и ip адреса

host_name = input('Enter hostname: ')
ip_addr = input('Enter IP address of new host: ' )

# нужно вписать url заббикс сервера, юзера и пасс
with ZabbixAPI(url='', user='m.gerbersgagen', password='*') as zapi:
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

