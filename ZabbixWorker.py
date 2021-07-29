from pyzabbix import ZabbixAPI

# Добавляем список с кредами для мониторинга
ocod_new = ['https://monitoring.dv.local/', 'm.gerbersgagen', 'KmPO6sssqVDk']
ocod_old = ['http://10.87.188.76/zabbix', 'm.gerbersgagen', 'KL29JPMe']


class ZabbixWorker:

    """Класс, реализующий ряд функций для удобной работы с Zabbix API"""

    # Получаем все имена хостов в группе, номер которой передаем функции на вход.
    # Для этого, сперва вызываем функцию, которая достает id хоста, потом запрашиваем hostname, передавая id
    def get_hosts_ids(host_creds, groupid):
        with ZabbixAPI(url=host_creds[0], user=host_creds[1], password=host_creds[2]) as zapi:
            # get hostnames and ID's of hosts
            host_ids_and_names = zapi.host.get(groupids=groupid, output=['host'])
            host_list = []

            # from list of ID's and host, get hostid only
            for i in range(len(host_ids_and_names)):
                host_ids = host_ids_and_names[i].get('hostid')
                host_list.append(host_ids)
            return host_list

    def get_hosts_names(self, host_creds, groupid):
        ZabbixWorker.get_hosts_ids(host_creds, groupid)
        with ZabbixAPI(url=host_creds[0], user=host_creds[1], password=host_creds[2]) as zapi:
            host_ids_and_names = zapi.host.get(hostids=ZabbixWorker.get_hosts_ids(host_creds, groupid), output=['host'])
            host_list = []
            for i in range(len(host_ids_and_names)):
                host_list.append(host_ids_and_names[i].get('host'))
            return host_list


    # копирует хост с сервера sourse_host_creds на сервер target_host_creds
    # в файле откуда вызываем функцию должен быть определен массив с хостнеймами
    # серверов подлежащих копированию, target_grouip обязательный параметр, определяет в какую
    # группу хостов на целевом сервере скопируется хост


    def host_copy(self, sourse_host_creds, target_host_creds, host_list, target_groupid):
        for hostname in host_list:
            with ZabbixAPI(url=sourse_host_creds[0], user=sourse_host_creds[1], password=sourse_host_creds[2]) as zapi:
                original_host = zapi.host.get(
                    filter={'host': hostname},
                    selectGroups='extend',
                    selectInterfaces='extend',
                    selectMacros='extend'
                )[0]

                with ZabbixAPI(url=target_host_creds[0], user=target_host_creds[1],
                               password=target_host_creds[2]) as zapi:
                    clone = zapi.host.create(
                        host=original_host['host'],
                        name=original_host['name'],
                        proxy_hostid=original_host['proxy_hostid'],
                        groups=[{'groupid': target_groupid}],
                        macros=original_host['macros'],
                        interfaces=[
                            {'main': '1', 'type': '1', 'useip': '1', 'dns': '', 'port': '10050', 'bulk': '1',
                             'ip': original_host['interfaces'][0]['ip']}])
                    print('Copying host ' + hostname)
    #  добавляем хосты на указанный сервер, читая два файла,
    #  в одном hostnames, в другом ip

    def add_host(self, host_creds, groupid):

        hostnames = []
        iplist = []

        # итерируемся по двум листам, потом используем 1 строчки в качестве хостнейма
        # вторую строчку в качестве ip
        # скрипт работает только если используется IP, с DNS не работает
        with open('hostnames', 'r') as file:
            for line in file.readlines():
                hostnames.append(line.rstrip())
        with open ("iplist", 'r') as file:
            for line in file.readlines():
                iplist.append(line.rstrip())
        for i in range(len(hostnames)):
            with ZabbixAPI(url=host_creds[0], user=host_creds[1], password=host_creds[2]) as zapi:
                host_create = zapi.host.create(
                    host=hostnames[i],
                    groups=[{'groupid': groupid}],
                    interfaces=[
                        {'main':'1', 'type': '1', 'useip': '1', 'dns': '',
                         'port': '10050', 'bulk': '1',
                         'ip': iplist[i]}
                    ]
                )
    # считает количество хостов в группе, только и всего.

    def host_count(self, host_creds, groupid):
        with ZabbixAPI(url=host_creds[0], user=host_creds[1], password=host_creds[2]) as zapi:
            host_count = zapi.host.get(groupids=groupid, output=['host']
            )
        res = len([element for element in host_count if isinstance(element, dict)])
        return int(res)

