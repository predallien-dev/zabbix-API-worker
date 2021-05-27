from pyzabbix.api import ZabbixAPI

z = ZabbixAPI(url='https://monitoring.avilex.ru/zabbix', user='m.gerbersgagen', password='*')
z.do_request(method="host.create",params= {
        "host": "blablalbalba",
        "interfaces": [
            {
                "type": 1,
                "main": 1,
                "useip": 1,
                "ip": "192.168.10.252",
                "dns": "",
                "port": "10050"
            }
        ],
        "groups": [
            {
                "groupid": "50"
            }
        ],
        "templates": [
            {
                "templateid": "13865"
            }
        ],
    }
)
