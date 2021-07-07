from pyzabbix import ZabbixAPI

target_url = 'https://monitoring.dv.local/'
user='m.gerbersgagen'
password='KmPO6sssqVDk'


class ZabbixFramework():
    """Класс, реализующий ряд функций для удобной работы с Zabbix API"""

    # Функция принимает на вход номер группы и возвращает id всех хостов в этой группе
    def get_hosts_ids(self, groupid):
        with ZabbixAPI(url=target_url, user=user, password=password) as zapi:
            # get hostnames and ID's of hosts
            host_ids_and_names = zapi.host.get(groupids=groupid, output=['host'])
            host_list = []

            # from list of ID's and host, get hostid only
            for i in range(len(host_ids_and_names)):
                host_ids = host_ids_and_names[i].get('hostid')
                host_list.append(host_ids)
            return host_list


    # получаем имена хостов в группе 25.
    # Для этого, сперва выполняем кусок кода выше, потом добавляем в лист все имена хостов
    # получать сперва id необходимо по причине того, что хостнеймы в группе заббикс
    # просто так не отдает, только по id хоста

    def get_hosts_names(self, groupid):

            def get_hosts_ids(groupid):
                with ZabbixAPI(url=target_url, user=user, password=password) as zapi:
                    # get hostnames and ID's of hosts
                    host_ids_and_names = zapi.host.get(groupids=groupid, output=['host'])
                    host_list = []

                    # from list of ID's and host, get hostid only
                    for i in range(len(host_ids_and_names)):
                        host_ids = host_ids_and_names[i].get('hostid')
                        host_list.append(host_ids)
                    return host_list

            with ZabbixAPI(url=target_url, user=user, password=password) as zapi:
                # get hostnames and ID's of hosts
                host_ids_and_names = zapi.host.get(hostids=get_hosts_ids(groupid=groupid), output=['host'])
                host_list = []
                for i in range(len(host_ids_and_names)):
                    host_list.append(host_ids_and_names[i].get('host'))
                return host_list

    # начиная отсюда не тестировалось!
    # получаем ip хостов в группе 25
    def get_hosts_ips(self):
        with ZabbixAPI(url=target_url, user=user, password=password) as zapi:
            ip_retrieve = zapi.hostinterface.get(hostids=get_hosts_list(), output=['ip'])
            names_list = []
            i = 0
            while i < len(ip_retrieve):
                ip_addr = ip_retrieve[i].get('ip')
                names_list.append(ip_addr)
                i += 1
            return(names_list)

    # добавляем SNMP интерейс на всех хосты группы 25
    # SNMP ip = Agent IP

    def add_snmp(self):
        i = 0
        with ZabbixAPI(url=target_url, user=user, password=password) as zapi:
            while i < len(get_hosts_ips()):
                print(i)
                try:
                    snmp_add = zapi.hostinterface.create(
                            dns='',
                            hostid=get_hosts_list()[i],
                            ip=get_hosts_ips()[i],
                            main='0',
                            port='161',
                            type='2',
                            useip='1',
                            details={
                                'version': '2',
                                'bulk': '1',
                                'community': '($SNMP_COMMUNITY)'
                            }

                        )

                except:
                    snmp_add = zapi.hostinterface.create(
                        dns='',
                        hostid=get_hosts_list()[i],
                        ip=get_hosts_ips()[i],
                        main='1',
                        port='161',
                        type='2',
                        useip='1',
                        details={
                            'version': '2',
                            'bulk': '1',
                            'community': '($SNMP_COMMUNITY)'
                        }
                    )

                i += 1

    def add_template(self):

        with ZabbixAPI(url=target_url, user=user, password=password) as zapi:
            i = 0
            while i < len(get_hosts_list()):
                print(i)

                template = zapi.template.massadd(
                    templates=[{'templateid':'10256'}],
                    hosts=[{'hostid': get_hosts_list()[i]}]
                )
                i += 1


res = ZabbixFramework()
print(res.get_hosts_names(26))