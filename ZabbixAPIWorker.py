from pyzabbix import ZabbixAPI
import asyncio
import re
import requests
import shutil
import urllib3

# перечень серверов, к которым будем коннектится
# формат кредов - [адрес сервер, логин, пароль]
server = ['https://URL_ADDRESS', 'username', 'password']


# синглтон для создания только одного соединения с заббиксом
class MetaSingleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(MetaSingleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class ZabbixAPIWorker(metaclass=MetaSingleton):
    # конструктор при вызове класса создает объект zapi для коннекта с сервером
    def __init__(self, host_creds):
        self.zapi = ZabbixAPI(host_creds[0])
        self.zapi.session.verify = False
        self.zapi.login(host_creds[1], host_creds[2])
        # иногда авторизация ломается и строки выше надо поменять вот на эту
        # self.zapi = ZabbixAPI(url=host_creds[0], user=host_creds[1], password=host_creds[2])

    # Return ID of host group, accept host group name
    def get_group_id_by_name(self, name):
        try:
            groupid = self.zapi.hostgroup.get(filter={'name': name})
            return groupid[0]['groupid']
        except Exception as e:
            print(f'Error while obtaining the group ID by name {name}: {e}')

    # Return hostgroup name, accept hostgroup ID
    def get_group_name_by_id(self, groupid):
        try:
            group = self.zapi.hostgroup.get(filter={'groupid': groupid})
            # check if group with given name exist
            if group:
                return group[0]['name']
            else:
                print(f'Группы с ID {groupid} не существует')
                return None
        except Exception as e:
            print(f'Error while obtaining the group ID by name {groupid}: {e}')
            return None

    # Return hostname, accept host id
    def get_host_name_by_id(self, hostid):
        try:
            host = self.zapi.host.get(hostids=hostid, output=['host'])
            if host:
                return host[0]['host']
            else:
                print(f'Host with ID {hostid} does not exist')
                return None
        except Exception as e:
            print(f'Error while obtaining the host name by ID {hostid}: {e}')
            return None

    # Return host id, accept hostname
    @staticmethod
    def get_host_id_by_name(name):
        try:
            return res.zapi.host.get(filter={'host': name})[0]['hostid']
        except Exception as e:
            print(f'Error while obtaining the ID by name {name}: {e}')

    '''Returns a list with the list of all hosts in the group, the ID of which is passed as input.
       If the names parameter is not specified, returns the ID.
       If the names parameter is specified - returns a list of host names in this group.
    '''
    def get_all_host_in_group(self, groupid, names=False):
        all_hosts = list()
        if names:
            names_list = self.zapi.host.get(groupids=groupid)
            # generating list with all host names
            all_hosts = [host['host'] for host in names_list]
        else:
            hostid_list = self.zapi.host.get(groupids=groupid)
            all_hosts = [host['hostid'] for host in hostid_list]
        return all_hosts

    '''
    Automatically create new hosts. Must specify the group ID to which the host will be added.
To use the method, two files are needed: 'hostnames' and 'iplist'.
The lines in the files should correspond to each other, i.e., the IP address should be on the first line of the 'iplist' file 
for the hostname of the host on the first line of the 'hostnames' file. The method can create hosts with either a DNS address 
or an IP, depending on the 'dns' flag. By default, hosts are created with an IP.
Also, specify the type of interface for the created host. Supported interfaces are agent and SNMP.
    '''

    @staticmethod
    def host_add(host_creds, groupid, method, dns=False):
        try:
            # Initialize lists for hosts and IP addresses
            hostnames = []
            iplist = []

            # Read host names from 'hostnames' file
            # and IP addresses from 'iplist' file
            with open('hostnames', 'r') as host_file, open('iplist', 'r') as ip_file:
                hostnames = [line.strip() for line in host_file.readlines()]
                iplist = [line.strip() for line in ip_file.readlines()]

            # Iterate through the lists of hosts and IP addresses
            for i in range(len(hostnames)):
                # Default interface settings
                interface_settings = {
                    'main': '1', 'type': '',
                    'useip': '1', 'dns': '', 'port': '',
                    'bulk': '1', 'details': {'version': '2', 'bulk': '1', 'community': '{$SNMP_COMMUNITY}'},
                    'ip': ''
                }

                # Set interface settings based on the method (agent or snmp)
                if method == 'agent':
                    interface_settings['type'] = '1'
                    interface_settings['port'] = '10050'
                    interface_settings['ip'] = iplist[i]

                elif method == 'snmp':
                    interface_settings['type'] = '2'
                    interface_settings['port'] = '161'
                    interface_settings['ip'] = iplist[i]

                # Set settings for DNS if dns flag is True
                if dns:
                    interface_settings['useip'] = '0'
                    interface_settings['dns'] = iplist[i]

                try:
                    # Create a host with the specified parameters
                    res.zapi.host.create(
                        host=hostnames[i],
                        groups=[{'groupid': groupid}],
                        interfaces=[interface_settings]
                    )
                    # Notify successful host addition
                    print(f'Host "{hostnames[i]}" with IP address {iplist[i]} successfully added ({method.upper()})')
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

    # Add hosts with inventory details.
    @staticmethod
    def host_add_with_inventory(groupid, method, dns=False):
        try:
            hostnames = []
            iplist = []
            seriallist = []
            locationlist = []

            # Read hostnames from file
            with open('hostnames', 'r') as file:
                hostnames = [line.strip() for line in file.readlines()]
            with open("iplist", 'r') as file:
                iplist = [line.strip() for line in file.readlines()]
            with open("serial_list", 'r') as file:
                seriallist = [line.strip() for line in file.readlines()]
            with open("location_list", 'r') as file:
                locationlist = [line.strip() for line in file.readlines()]

            for i in range(len(hostnames)):
                interface_data = {
                    'main': '1',
                    'port': '10050',
                    'bulk': '1',
                    'ip': iplist[i]
                }

                if dns:
                    interface_data['useip'] = '0'
                    interface_data['dns'] = iplist[i]
                    interface_data['ip'] = ''

                if method == 'agent':
                    interface_data['type'] = '1'
                elif method == 'snmp':
                    interface_data['type'] = '2'
                    interface_data['port'] = '161'
                    interface_data['details'] = {
                        'version': '2',
                        'bulk': '1',
                        'community': '{$SNMP_COMMUNITY}'
                    }

                res.zapi.host.create(
                    host=hostnames[i],
                    groups=[{'groupid': groupid}],
                    interfaces=[interface_data]
                )

                if method == 'agent':
                    interface_type = 'Agent'
                elif method == 'snmp':
                    interface_type = 'SNMP'

                interface_info = ' with ip address ' if not dns else ' with FQDN '
                print('Host "{host}"{info}{ip}" successfully added ({interface})'.format(
                    host=hostnames[i], info=interface_info, ip=iplist[i], interface=interface_type))

                res.zapi.host.update(
                    hostid=res.get_host_id_by_name(hostnames[i]),
                    inventory_mode=0,
                    inventory={'site_rack': locationlist[i], 'serialno_a': locationlist[i]}
                )

        except Exception as e:
            print(e)

    '''
    Copy host from the source_host_creds Zabbix to the target_hostcreds server.
    Host NAMES for copying are passed in the list 'host_list' when calling the function. 
    target_groupid is a required parameter.
    that specifies the group of hosts on the target server where the host will be copied.
    Suitable for copying a small group of hosts. The host's name and IP address are copied.
    KNOWN ISSUES: 
    - if a host has multiple interfaces, only one will be copied.
    - If a host has only a DNS name and no IP, it will cause an error.
    '''

    def host_copy(self, source_host_creds, host_list, target_host_creds, target_groupid):
        # Method for logging into another server using credentials different from the ones used during the initial login
        def zapi_login(host_creds):
            self.zapi = ZabbixAPI(host_creds[0])
            self.zapi.session.verify = False
            self.zapi.login(host_creds[1], host_creds[2])

        # Iterate through all hosts in list 'host_list'
        for hostname in host_list:
            try:
                # Display the host name being processed
                print('Copying hostname ' + hostname)

                # Login to the source server
                zapi_login(source_host_creds)
                original_server = ZabbixAPIWorker(source_host_creds)
                original_host = original_server.zapi.host.get(
                    filter={'host': hostname},
                    selectGroups='extend',
                    selectInterfaces='extend')

                # Check the interface type of the original host and copy it accordingly
                if original_host[0]['interfaces'][0]['type'] == '2':  # SNMP interface
                    zapi_login(target_host_creds)
                    self.zapi.host.create(
                        host=original_host[0]['host'],
                        name=original_host[0]['name'],
                        groups=[{'groupid': target_groupid}],
                        interfaces=[
                            {'main': '1', 'type': original_host[0]['interfaces'][0]['type'], 'useip': '1',
                             'dns': original_host[0]['interfaces'][0]['dns'],
                             'port': original_host[0]['interfaces'][0]['port'], 'bulk': '1',
                             'ip': original_host[0]['interfaces'][0]['ip'],
                             'details': {'version': original_host[0]['interfaces'][0]['details']['version'],
                                         'bulk': '1',
                                         'community': '{$SNMP_COMMUNITY}'}}])
                    print(f'Host {hostname} copied with SNMP interface')
                    self.zapi.user.logout()
                elif original_host[0]['interfaces'][0]['type'] == '1':  # Agent interface
                    zapi_login(target_host_creds)
                    self.zapi.host.create(
                        host=original_host[0]['host'],
                        name=original_host[0]['name'],
                        groups=[{'groupid': target_groupid}],
                        interfaces=[
                            {'main': '1', 'type': original_host[0]['interfaces'][0]['type'], 'useip': '1',
                             'dns': original_host[0]['interfaces'][0]['dns'],
                             'port': original_host[0]['interfaces'][0]['port'], 'bulk': '1',
                             'ip': original_host[0]['interfaces'][0]['ip']}])
                    print(f'Host {hostname} copied with Agent interface')
                elif original_host[0]['interfaces'][0]['type'] == '3':  # IPMI interface
                    zapi_login(target_host_creds)
                    self.zapi.host.create(
                        host=original_host[0]['host'],
                        name=original_host[0]['name'],
                        groups=[{'groupid': target_groupid}],
                        interfaces=[
                            {'main': '1', 'type': original_host[0]['interfaces'][0]['type'], 'useip': '1',
                             'dns': original_host[0]['interfaces'][0]['dns'],
                             'port': original_host[0]['interfaces'][0]['port'], 'bulk': '1',
                             'ip': original_host[0]['interfaces'][0]['ip']}])
                    print(f'Host {hostname} copied with IPMI interface')
                    self.zapi.user.logout()
            except Exception as e:
                print(e)
                pass

    # НУЖНО ТЕСТИРОВАТЬ
    # Добавляем SNMP интерфейс на хост
    # Method to add SNMP interface to host
    def snmp_add(self, host_creds):
        try:
            # Get list of host ids
            host_ids = list()

            for host_id in host_ids:
                # Check if SNMP interface already exists on the host, skip the host if it does
                snmp_exists = res.zapi.interface_get(host_creds=host_creds, hostid=host_id)
                print(f'Checking for SNMP interface on host {host_id}')

                if snmp_exists == 1:
                    print('SNMP interface already exists on the host, skipping')
                    continue
                else:
                    print('SNMP interface does not exist on the host, adding interface')
                    true_ip = self.zapi.get_ip(pob_new, hostid=host_id)
                    print('IP address: ' + true_ip)

                    # Create SNMP interface using retrieved IP
                    self.zapi.hostinterface.create(
                        dns='',
                        hostid=host_id,
                        ip=true_ip,
                        main='0',
                        port='161',
                        type='2',
                        useip='1',
                        details={
                            'version': '2',
                            'bulk': '1',
                            'community': 'public'
                        }
                    )
                    print('Interface added for host ' + host_id)
        except Exception as e:
            print(e)

    # Enable all hosts associated with a specific proxy. Takes full proxy name as input,
    # as it is displayed in the monitoring web interface.
    def enable_all_host_in_proxy(self, proxy_name):
        # Get hosts associated with the proxy and store them in a list, then iterate through the list and enable the hosts
        proxy_hosts = self.zapi.proxy.get(filter={'host': proxy_name}, selectHosts=['hostid'], output=['hostid'])

        # Generate a list of hostids of hosts associated with the proxy
        all_host_ids = [host['hostid'] for host in proxy_hosts[0]['hosts']]

        # Iterate through the list and enable each host
        for host_id in all_host_ids:
            self.zapi.host.update(hostid=host_id, status=0)
            print('Enabling host ' + host_id)

    # Disable hosts associated with a specific proxy. Everything is the same as in the method above, just in reverse.
    def disable_all_host_in_proxy(self, proxy_name):
        # Get hosts associated with the proxy and store them in a list, then iterate through the list and enable the hosts
        proxy_hosts = self.zapi.proxy.get(filter={'host': proxy_name}, selectHosts=['hostid'], output=['hostid'])

        # Generate a list of hostids of hosts associated with the proxy
        all_host_ids = [host['hostid'] for host in proxy_hosts[0]['hosts']]

        # Iterate through the list and enable each host
        for host_id in all_host_ids:
            self.zapi.host.update(hostid=host_id, status=1)
            print('Disabling host ' + host_id)

    # Remove templates from hosts in a specified group.
    # Takes group ID, server credentials, and template ID as input.
    # Example: res.templates_clear(1578, 27220) - clears all hosts in group 1578 from template with ID 27220
    def templates_clear(self, groupid, templateid):
        hosts = self.get_all_host_in_group(groupid, names=False)
        for host in hosts:
            try:
                self.zapi.host.update(hostid=host, templates_clear=[{'templateid': templateid}])
                print(f'Removing template {templateid} from host {host}')
            except Exception as e:
                print(e)

    # Add templates to hosts. Takes group ID and an array of template IDs as input.
    # IMPORTANT: Only the templates provided in the input array will be attached to the hosts. Any other templates previously attached will be removed.
    # Example: res.templates_add(14399, [27224, 27225, 27220]) - attach templates with IDs 27224, 27225, 27220 to the group 14399.
    def templates_add(self, groupid, templateids):
        group_name = res.get_group_name_by_id(groupid)
        print('Retrieving group {groupname}'.format(groupname=group_name))

        for host_id in self.get_all_hosts_in_group(groupid):
            print(f'Host {host_id}')
            self.zapi.host.update(hostid=host_id, templates=templateids)
            print(f'Attaching templates {templateids} to host {host_id}')

    # Disable all hosts with host IDs obtained from a list.
    def disable_hosts_from_list(self):
        # Retrieve host IDs from which is read from file
        host_ids_to_disable = []
        with open('host_ids_to_disable', 'r') as file:
            for line in file.readlines():
                host_ids_to_disable.append(line.strip())

        for host_id in host_ids_to_disable:
            self.zapi.host.update(hostid=host_id, status=1)
            print('Disabling host {hostid}'.format(hostid=host_id))

    # Enable all hosts with host IDs obtained from a list.
    def disable_hosts_from_list(self):
        # Retrieve host IDs from which is read from file
        host_ids_to_disable = []
        with open('host_ids_to_enable', 'r') as file:
            for line in file.readlines():
                host_ids_to_disable.append(line.strip())

        for host_id in host_ids_to_disable:
            self.zapi.host.update(hostid=host_id, status=0)
            print('Disabling host {hostid}'.format(hostid=host_id))

    # Count the number of problems on the server.
    def get_problem_count(self):
        # Retrieve the list of event IDs for problems and get the count
        problem_count = len(self.zapi.problem.get(output=['eventids']))
        return problem_count

    # выгружаем графики ICMP Ping с хостов, название которых передаем в файле graphs_hosts
    @staticmethod
    def get_graph(hostcreds):
        # метод логинится в заббикс и возвращает айдишник сессии
        def get_session_id():
            session = requests.Session()
            session.post(hostcreds[0], {
                'name': hostcreds[1],
                'password': hostcreds[2],
                'autologin': 1,
                'enter': 'Sign in'
            })
            return session.cookies.get_dict()['zbx_session']

        # метод возвращает ID итема с названием ICMP ping, график которого нам и нужен
        def item_get(hostname):
            itemids = res.zapi.item.get(host=hostname)
            # выцепляем ID итема c названием ICMP ping
            ping_item_id = [i['itemid'] for i in itemids if i['name'] == 'ICMP ping']
            return ping_item_id[0]

        # даты, за которые нужен график в формате гггг-мм-дд
        date_from = '2024-12-18'
        date_to = '2025-03-31'

        # построчно читаем файл graphs_hosts и добавляем эти строки в лист graphs
        graphs = list()
        with open('graphs_hosts', 'r') as file:
            for line in file.readlines():
                graphs.append(line.rstrip())
        # куки для хранения айдишника сессии
        cookies = {
            'zbx_session': get_session_id()
        }

        # для каждого хостнейма, скачиваем график, подсовывая ID сессии из соответствующего метода
        for item in graphs:
            # формируем ссылку для каждого хоста
            url = '{hostname}chart.php?from={date_from}&to={date_to}&itemids={itemid}&type=0&profileIdx=' \
                  'web.item.graph.filter&profileIdx2=89261&width=1607&height=200&_=vld58g0o&screenid='.format(
                hostname=hostcreds[0], date_from=date_from, date_to=date_to, itemid=item_get(hostname=item))
            response = requests.get(url, cookies=cookies, stream=True)
            # скачиваем график с каждого хоста, имя png файла будет равно имени хоста
            with open(item + '.png', 'wb') as out_file:
                shutil.copyfileobj(response.raw, out_file)
            del response
            print('График хоста {host} скачан'.format(host=item))

    # Забираем последнее значение метрики, название метрики задается в свойстве filter  метода get_last_metric
    def last_value(self, hostid):
        get_last_metric = self.zapi.item.get(hostids=hostid, filter={'name': 'Zabbix agent ping'})
        get_host_ip = self.zapi.hostinterface.get(hostids=hostid)
        get_host_ip_clear = get_host_ip[0]['ip']
        if len(get_last_metric) == 0:
            print(f'Host {res.get_host_name_by_id(hostid)}is unavailable')
        else:
            return ('{hostid}, {hostip}, Zabbix agent ping, {lastmetric}'.format(
                hostid=res.get_host_name_by_id(hostid), hostip=get_host_ip_clear,
                lastmetric=get_last_metric[0]['lastvalue']))

    # берем значения всех метрик из хоста
    def get_all_item_value(self, hostid):
        # забираем всю инфу о всех метриках на хосте
        get_all_items = self.zapi.item.get(hostids=hostid)
        # получаем ip хоста для дальнейшего вывода
        get_host_ip = self.zapi.hostinterface.get(hostids=hostid)[0]['ip']
        # для каждой метрики на хосте, формируем вывод на экран нужной инфы
        for item in get_all_items:
            if len(item) == 0:
                print('Host is unavailable, {hostname}'.format(hostname=res.get_host_name_by_id(hostid)))
            else:
                print('{hostid}, {hostip}, {item_name}, {lastvalue}'.format(
                    hostid=res.get_host_name_by_id(hostid), hostip=get_host_ip, item_name=item['name'],
                    lastvalue=item['lastvalue']))

    # Ищем на сервере пустые группы
    @staticmethod
    def get_empty_hostgroups(name, hostcreds):
        groupid = res.get_group_id_by_name(name)
        hostlist = res.get_all_host_in_group(hostcreds, groupid)
        if len(hostlist) == 0:
            print('Группа {name} пуста'.format(name=name))
        else:
            return len(hostlist)

    # удаляем хосты, айди которых перечислены в файле hostnames
    def host_delete(self):
        hostnames = []
        with open('hostnames', 'r') as file:
            for line in file.readlines():
                hostnames.append(line.rstrip())
        for i in range(len(hostnames)):
            try:
                self.zapi.host.delete(hostids=hostnames[i])
                print('Удален хост {hostid}'.format(hostid=hostnames[i]))
            except Exception as e:
                print(e)

    # Возвращает хостнеймы и ip недоступных хостов в группе, ID которой передается на вход
    # available = 2
    def get_disabled_hosts_in_group(self, hostcreds, groupid):
        all_host_in_group = res.get_all_host_in_group(hostcreds, groupid=groupid)
        for i in all_host_in_group:
            interface_info = self.zapi.hostinterface.get(hostids=i)
            if interface_info[0]['available'] == '2':
                groupname = res.get_group_name_by_id(groupid)
                hostname = res.get_host_name_by_id(i)
                ip = interface_info[0]['ip']
                message = print('{hostgroup},{hostname},{ip}'.format(hostgroup=groupname, hostname=hostname, ip=ip))
                return message

    # Принимает item id, возвращает название темплейта, в котором состоит итем
    @staticmethod
    def get_item_template(itemids):
        if len(res.zapi.template.get(itemids=itemids)) > 0:
            return res.zapi.template.get(itemids=itemids)[0]['host']
        else:
            msg = 'нет шаблона'
            return msg

    # Забираем информацию о хостах, темплейтах и метриках
    def get_info(self, groupid):
        # забираем ID всех хостов в группе
        all_hosts = res.get_all_host_in_group(groupid=groupid, names=False)
        # Забираем название группы, в которой хост находится
        get_host_group = res.get_group_name_by_id(groupid)
        # выводим инфу, пригодную к использованию в excel
        for i in all_hosts:
            # для каждого итема каждого хоста, выводим название; тип, айпи и порт интерфейса;
            # ключ и шаблон каждой метрики, триггеры
            get_interface = res.zapi.hostinterface.get(hostids=i)
            for j in res.zapi.item.get(hostids=i):
                item_name = j['name']
                item_key = j['key_']
                template_id = res.get_item_template(j['templateid'])
                # если на метрике нет триггера - не выводим инфу о триггере
                trigger_info = res.zapi.trigger.get(itemids=j['itemid'])
                if len(trigger_info) == 0:
                    print(
                        '{hostname}|{interface_type}|{interface_ip}|{interface_port}|{host_group}|{itemname}|{itemkey}|{templateid}'.format(
                            hostname=res.get_host_name_by_id(i),
                            interface_type=get_interface[0]['type'],
                            interface_ip=get_interface[0]['ip'],
                            interface_port=get_interface[0]['port'],
                            host_group=get_host_group,
                            itemname=item_name,
                            itemkey=item_key,
                            templateid=template_id))
                else:
                    # если на метрике есть триггер - выводим сообщение об этом
                    print(
                        '{hostname}|{interface_type}|{interface_ip}|{interface_port}|{host_group}|{itemname}|{itemkey}|{templateid}|{trigger_name}|{trigger_priority}'.format(
                            hostname=res.get_host_name_by_id(i),
                            interface_type=get_interface[0]['type'],
                            interface_ip=get_interface[0]['ip'],
                            interface_port=get_interface[0]['port'],
                            host_group=get_host_group,
                            itemname=item_name,
                            itemkey=item_key,
                            templateid=template_id,
                            trigger_name=trigger_info[0]['description'],
                            trigger_priority=trigger_info[0]['priority'])
                    )

    '''
    добавляем метрику в шаблон
    Возможные значения type:
    0 - Zabbix agent;
    2 - Zabbix trapper;
    3 - Simple check;
    5 - Zabbix internal;
    7 - Zabbix agent (active);
    9 - Web item;
    10 - External check;
    11 - Database monitor;
    12 - IPMI agent;
    13 - SSH agent;
    14 - TELNET agent;
    15 - Calculated;
    16 - JMX agent;
    17 - SNMP trap;
    18 - Dependent item;
    19 - HTTP agent;
    20 - SNMP agent;
    21 - Script.

    Возможные значения value_type:
    0 - numeric float;
    1 - character;
    2 - log;
    3 - numeric unsigned;
    4 - text.

    По умолчанию переодичность сбора данных составляет 60 секунд
    '''

    def add_item(self, hostid, type, value_type, ):
        try:
            # Читаем файлы и заносим их содержимое построчно в два листа
            item_name = []
            item_key = []
            with open('item_name', 'r') as file:
                for line in file.readlines():
                    item_name.append(line.rstrip())
            with open("item_key", 'r') as file:
                for line in file.readlines():
                    item_key.append(line.rstrip())
            # Получив два листа, один с названиями метрик, другой с ключем метрики, создаем метрики в шаблоне templateid
            for i in range(len(item_name)):
                template_name = self.zapi.template.get(templateids=hostid)[0]['host']
                print(f'Добавляем итем {item_name[i]} с ключем {item_key[i]} в шаблон {template_name}')
                res.zapi.item.create(hostid=hostid, name=item_name[i], key_=item_key[i], type=type,
                                     value_type=value_type,
                                     delay='60')
                trigger = res.zapi.trigger.create(description=f'Недоступен {item_name[i]}',
                                                  expression=f'{{{template_name}:{item_key[i]}.last()}}=0')
        except Exception as e:
            print(e)

    # Забираем айди всех групп на сервере
    def get_all_groups(self, hostcreds):
        groupid = list()
        get_host_group_id = res.zapi.hostgroup.get()
        for item in get_host_group_id:
            groupid.append(item['groupid'])
        return groupid

    @staticmethod
    def trigger_add():
        item_key = list()
        trigger_expression = list()
        # в файле item_key помещаем ключи метрик, к которым нужны триггеры
        with open('item_name', 'r') as file:
            for line in file.readlines():
                item_key.append(line.rstrip())
        with open("trigger_expression", 'r') as file:
            for line in file.readlines():
                trigger_expression.append(line.rstrip())

    # Передаем имя хоста и имя итема, возвращает айди итема
    @staticmethod
    def get_item_id_by_name(hostname, item_name):
        itemid = res.zapi.item.get(hostids=res.get_host_id_by_name(hostname), search={'name': item_name})
        return itemid[0]['itemid']

    # Возвращает ключ итема. Принимает имя хоста и название итема
    @staticmethod
    def get_item_key_by_name(hostname, item_name):
        item_key = res.zapi.item.get(hostids=res.get_host_id_by_name(hostname), search={'name': item_name})
        return item_key[0]['key_']

    # Ищем есть ли на сервере хосты с именами, которые берем из файла hostnames
    @staticmethod
    def host_search():
        host_list = list()
        # Открываем файл на чтение и заносим все строки как элементы листа host_list
        with open('hostnames', 'r') as file:
            for line in file.readlines():
                host_list.append(line.rstrip())
        for i in host_list:
            host_is_exist = res.zapi.host.get(filter={'host': i})
            if host_is_exist:
                print(f'Найден хост,{i}')
            else:
                print(f'Не найден хост,{i}')

    @staticmethod
    def add_user():
        add_user = res.zapi.user.create(
            username='admin',
            passwd='password',
            roleid='3',
            usrgrps=[{'usrgrpid': '<userid>'}]
        )
        return add_user

    # Возвращает массив с ip хостов, хостнеймы которых передаем в файле hostnames
    def get_interface_ip_from_hostid(self):
        hostnames = list()
        hostids = list()
        iplist = list()
        # добавляем в лист хостнеймы из файла
        with open('hostnames', 'r') as file:
            for line in file.readlines():
                hostnames.append(line.rstrip())
        # Добавляем в лист айдишников хостов
        for hostname in hostnames:
            print(hostname)
            hostids.append(res.get_host_id_by_name(hostname))
        # Для каждого айдишника забираем ip мейн интерфейса
        for host in hostids:
            iplist.append(res.zapi.hostinterface.get(hostids=host)[0]['ip'])
        return iplist

    # Переводит все хостнеймы в нижний регистр
    def update_host_lowercase(self, groupid):
        # забираем хосты из группы и переводим их в ловеркейс
        for host in res.get_all_host_in_group(groupid=groupid, names=False):
            try:
                # получаем имя хоста из его id и переводим его имя в lowercase
                host_name = res.get_host_name_by_id(host)
                host_name_lower = host_name.lower()
                res.zapi.host.update(hostid=host, host=host_name_lower)
                print('Меняем хостнейм хоста {hostname}'.format(hostname=host_name))
            except Exception as e:
                print(e)
                continue

    # Создаем группы на сервере, имена групп берем из файла hostnames
    def add_group(self):
        groupname = list()
        with open('hostnames', 'r') as file:
            for line in file.readlines():
                groupname.append(line.rstrip())
            for group in groupname:
                try:
                    res.zapi.hostgroup.create(name=group)
                except Exception as e:
                    print(e)
                    pass
            print(f'Добавлена группа {groupname}')

    # забирает значения макросов с хостом в группе, ID которой передаем на вход
    def get_macros(self, groupid):
        for hostid in res.get_all_host_in_group(groupid, names=False):
            macros = res.zapi.usermacro.get(hostids=hostid)
            if len(macros) > 0:
                print('{hostname} {snmp_value}'.format(hostname=res.get_host_name_by_id(hostid), snmp_value=macros))

    # Выводит в stdout инфу о хосте в формате (Имя хоста, ip хоста, группа хоста, прокси). Принимает id группы хостов
    def create_report(self, groupid):
        # саб метод, который принимает айди прокси и возвращает ее имя
        def get_proxy_name_by_id(proxy_id):
            return res.zapi.proxy.get(proxyids=proxy_id)[0]['host']

        hosts = res.get_all_host_in_group(groupid, names=False)
        # Забираем всю инфу о хосте чтоб два раза не вставать
        for host in hosts:
            host_info = res.zapi.host.get(hostids=host)
            host_name = host_info[0]['host']
            proxy_name = get_proxy_name_by_id(host_info[0]['proxy_hostid'])
            ip_address = res.zapi.hostinterface.get(hostids=host)[0]['ip']
            host_group = res.zapi.hostgroup.get(hostids=host)[0]['name']
            print(f'{host_name}, {ip_address}, {host_group}, {proxy_name}')

    # Делаем отчет по группе хостов по доступности по пингу
    def get_ping_down_host(self, groupid):
        # выводим те хосты, которые недоступны по пингу
        for host in res.get_all_host_in_group(groupid, names=False):
            try:
                get_host_info = res.zapi.host.get(selectInterfaces='extend', hostids=host)
                hostname = get_host_info[0]['host']
                ping_last_value = res.zapi.item.get(hostids=host, search={'key_': 'icmpping'})[0]['lastvalue']
                interface_available_agent = get_host_info[0]['available']
                interface_available_snmp = get_host_info[0]['snmp_available']
                interface_ip = get_host_info[0]['interfaces'][0]['ip']
                if interface_available_agent == '2' or interface_available_snmp == '2':
                    print(
                        f'{hostname}, {interface_ip},ping is {ping_last_value}, interface is {interface_available_agent}')
                else:
                    print(f'{hostname}, {interface_ip},ping is {ping_last_value}')
                print(get_host_info)
            except Exception as e:
                print(e)
                pass
	
	# версия метода выше, только для заббикс 6+
    def get_ping_down_host_zabbix6(self, groupid):

        # выводим те хосты, которые недоступны по пингу
        for host in res.get_all_host_in_group(groupid, names=False):
            try:
                get_host_info = res.zapi.host.get(filter={'hostid': host}, selectInterfaces='extend')
                hostname = get_host_info[0]['host']
                interface_ip = get_host_info[0]['interfaces'][0]['ip']
                interface_available = get_host_info[0]['interfaces'][0]['available']
                ping_last_value = res.zapi.item.get(hostids=host, search={'name': 'ICMP ping'})[0]['lastvalue']
                print(f'{hostname},{interface_ip}, ping is {ping_last_value}, interface is {interface_available}')
            except Exception as e:
                print(e)
                pass

    # Изменяем прокси для мониторинга хостов, имя которых передаем в файле hostnames
    def update_proxy_on_host(self, proxy_name):
        hostnames = list()
        with open('hostnames', 'r') as file:
            for line in file.readlines():
                hostnames.append(line.rstrip())

        # возвращает id прокси по ее имени
        def get_proxy_id(host):
            for proxy in res.zapi.proxy.get(output='extend'):
                if proxy['host'] == host:
                    return proxy['proxyid']

        # проходимся по хостам из файла и устанавливаем у них прокси, имя которой передаем на вход функции
        try:
            for host in hostnames:
                res.zapi.host.update(proxy_hostid=get_proxy_id(host=proxy_name), hostid=res.get_host_id_by_name(host))
                print(f'Меняем у хоста {host} прокси на {proxy_name}')
        except Exception as e:
            print(e)
            pass

    def snmp_add_common(self):
        # лист с именами хостов
        hostnames = list()
        hostids = list()
        # читаем файл, добавляем в лист ID хостов, беря имена из этого файла
        with open('hostnames', 'r') as file:
            for line in file.readlines():
                hostnames.append(line.rstrip())
            for host in hostnames:
                hostids.append(res.get_host_id_by_name(host))
            for i in hostids:
                # проверяем существует ли уже SNMP интерфейс, если существует - скипаем хост
                interfaces = self.zapi.hostinterface.get(hostids=i)
                print(f'Проверяем есть ли на хосте {res.get_host_name_by_id(i)} SNMP интефейс')
                for interface in interfaces:
                    is_snmp_exist = bool
                    if interface['type'] == '2':
                        is_snmp_exist = 'True'
                    else:
                        is_snmp_exist = 'False'
                if is_snmp_exist == 'True':
                    print('На хосте есть SNMP, скипаем')
                    continue
                else:
                    print('На хосте нет SNMP, добавляем интерфейс')
                    # добавляем SNMP интерфейс на хост, IP равен IP уже существующего интерфейса
                    host_ip = res.zapi.hostinterface.get(hostids=i)[0]['ip']
                    self.zapi.hostinterface.create(
                        dns='',
                        hostid=i,
                        # ip выцепляем из функции get_ip, передав ей на вход ID хоста
                        ip=host_ip,
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
                    print('Интерфейс добавлен на хост')

    # добавляем хост в группу target_group, принимает на вход IP хоста в файле hostnames
    def add_in_group(self, target_group):
        # лист для хранения id хостов
        idlist = list()
        # лист для хранения ip, забираемые на основе хостнейма
        iplist = list()

        with open('hostnames', 'r') as file:
            for line in file.readlines():
                iplist.append(line.rstrip())
        for ip in iplist:
            # по IP находим ID хоста, добавляем этот ID в
            try:
                idlist.append(self.zapi.hostinterface.get(filter={'ip': ip})[0]['hostid'])
            except Exception as e:
                print(f'Не найден адрес {ip}')
                continue
        # теперь, когда в массиве idlist хранятся id всех хостов, которые нам нужны, делаем бизнес
        for host in idlist:
            grouplist = list()
            # инфа о группах
            groups = self.zapi.host.get(hostids=host, selectGroups='extend')[0]['groups']
            for groupid in groups:
                grouplist.append(groupid['groupid'])
            # в листе grouplist у нас сейчас массив id всех групп, в которых состоит хост
            # нам нужно добавить в этот массив target_group, в которую мы хотим добавить хост
            grouplist.append(target_group)
            print(f'Добавляем хост {res.get_host_name_by_id(host)} в группы {grouplist}')
            groupid_data = [{'groupid': grouplist} for grouplist in grouplist]
            # формируем структуру данных вида [{'groupid'}:id1, {'groupid'}:id2]
            res.zapi.host.update(hostid=host, groups=groupid_data)
            # print(groupid_data)

    # Убираем шаблоны с хоста и вешаем их же. Таким образом, удаляем всю историю по хосту
    def template_replace(self, templateid):
        hostnames = list()
        idlist = list()
        template_list = list()
        with open('hostnames', 'r') as file:
            for line in file.readlines():
                hostnames.append(line.rstrip())
        for host in hostnames:
            idlist.append(res.get_host_id_by_name(host))
        for hostid in idlist:
            for template in res.zapi.template.get(hostids=hostid, output='extend'):
                # убираем все шаблоны с хоста
                template_list.append(template['templateid'])
                print(f"Удаляем с хоста {hostid} шаблон {template['name']}")
                self.zapi.host.update(hostid=hostid, templates_clear=[{'templateid': template['templateid']}])
                # возвращаем их назад
            self.zapi.host.update(hostid=hostid, templates=templateid)
            print(f"Цепляем на хост {hostid} шаблоны {templateid}")

    # Получаем отчет о доступности интерфейсов по переданой группе в формате "имя хоста, ip, состояние"
    def get_availablity_report(self, groupid):
        for host in res.get_all_host_in_group(groupid=groupid):
            try:
                interfaces = [i for i in res.zapi.hostinterface.get(hostids=host) if i['type'] == '2']
                hostname = res.get_host_name_by_id(interfaces[0]['hostid'])
                ip = interfaces[0]['ip']
                state = interfaces[0]['available']
                print(f'{hostname},{ip},{state}')
            except Exception as e:
                print(e)

    # Меняем SNMP комьюнити у хостов
    def snmp_community_change(self, hostcreds):
        # забираем все хосты в группе с SNMP интерфейсом
        group_names = list()
        target_group_names = list()
        target_group_id = list()
        for group in res.zapi.hostgroup.get():
            group_names.append(group['name'])
        for host in group_names:
            if "МФЦ/Цент" in host:
                target_group_names.append(host)
        # в листе target_group_names получили список групп, в которых нужно поменять комьюнити
        print('Вычисляем ID нужных групп...')
        for group in target_group_names:
            target_group_id.append(res.get_group_id_by_name(group))
        for group in target_group_id:
            print(f'Берем группу {res.get_group_name_by_id(group)}')
            for host in res.get_all_host_in_group(group, names=False):
                interface_info = self.zapi.hostinterface.get(hostids=host)
                for interface in interface_info:
                    if interface['type'] == '2':
                        # кладем в переменную нужный нам id интерфейса, у которого будем менять комьюнити
                        interfaceid_info = interface['interfaceid']
                        print(f'Меняем snmp community у хоста {host}')
                        res.zapi.hostinterface.update(interfaceid=interfaceid_info,
                                                      details={'community': '{$SNMP_COMMUNITY}'})

    def update_inventory(self):
        seriallist = []
        locationlist = []
        hostnames = []
        with open('hostnames', 'r') as file:
            for line in file.readlines():
                hostnames.append(line.rstrip())
        with open("serial_list", 'r') as file:
            for line in file.readlines():
                seriallist.append(line.rstrip())
        with open("location_list", 'r') as file:
            for line in file.readlines():
                locationlist.append(line.rstrip())
        for i in range(len(seriallist)):
            res.zapi.host.update(hostid=res.get_host_id_by_name(hostnames[i]),
                                 inventory_mode=0,
                                 inventory={'site_rack': locationlist[i], 'serialno_a': seriallist[i]}
                                 )
            print(f'Включаем инвентарь у хоста {res.get_host_id_by_name(hostnames[i])}')

    # переводит описания триггеров в шаблонах на русский язык
    def translate_trigger_comment(self):
        import translators as ts
        from langdetect import detect
        # забираем только триггеры, которые находится в шаблонах и только не отдискаверенные
        trigger_dict = self.zapi.trigger.get(output=['comments'])

        def contains_russian(text):
            # проверяем, содержит ли строка хотя бы один символ русского алфавита
            return bool(re.search('[а-яА-Я]', text))

        for trigger in trigger_dict:
            # если описание пустое или содержит хоть один русский символ - скипаем
            if not trigger['comments'] or contains_russian(trigger['comments']):
                continue
            try:
                trigger_comment = str(trigger['comments'])
                lang = detect(trigger_comment)
                # на всякий случай проверяем является ли язык русским или болгарским
                if lang =='ru' or lang=='bg':
                    continue
                translated_comment = ts.translate_text(query_text=trigger['comments'],from_language='en',to_language='ru',translator='yandex')
                print(f"Меняем описание у триггера {trigger['triggerid']} c {trigger['comments']} на {translated_comment}")
                # делаем бизнес, меняем описание триггера на переведенное
                res.zapi.trigger.update(triggerid=trigger['triggerid'], comments=translated_comment)
            except Exception as e:
                print(e)

    def group_create(self):
        create_group = res.zapi.hostgroup.create(name='testgroup')
        return create_group['groupids'][0]

    # проверяем существует ли хост группа на сервере
    def group_is_exist(self, name):
        try:
            group = self.zapi.hostgroup.get(filter={'name': name})[0]['groupid']
            return True
        except Exception as e:
            return False

    # принимает имя шаблона, возвращает его id
    def get_template_id_by_name(self, template_name):
        return res.zapi.template.get(output='templateid', filter={'host': template_name})[0]


# использование методов
res = ZabbixAPIWorker(server)

# пример использования
#print(res.snmp_community_change())