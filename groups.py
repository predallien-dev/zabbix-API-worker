from ZabbixWorker import *

'''
Метод раскидывает школьные хосты по группам на основании их имени
'''

# создаем экземпляр класса, где хранятся функции для работы
res = ZabbixWorker()
groupname_list = list()
hostnames = list()


# получаем список всех хостов на сервере
def get_all_hosts(host_creds):
    print('Получаем список всех хостов на сервере...')
    with ZabbixAPI(url=host_creds[0], user=host_creds[1], password=host_creds[2]) as zapi:

        get_all_hosts = zapi.host.get(output=['host'])
        for each_host in get_all_hosts:
            hostnames.append(each_host['host'])


# Получаем имена всех групп на сервере
def make_group_name_list():
    print('Получаем список всех групп на сервере...')
    # берем все группы на сервере и получаем их ID и имена
    group_list = res.get_groups(pob_new)
    # объявляем лист, который будет хранить имена всех групп

    # добавляем в лист groupname_list только имена всех групп на сервере и возвращаем этот лист
    for i in group_list:
        groupname_list.append(i['name'])
    return groupname_list


# метод берет хостнейм, который передаешь ей на входе, отрезает от него номер школы
def get_hostgroup_from_host(hostname):
    # задаем сепараторы

    print('Получаем ' + hostname)
    sep_list = ['APC', 'DC', 'FS', 'GW', 'HV', 'MMPAN', 'PROXY', 'KSC', 'KVM']
    # генерим сепараторы для sw оборудования
    for i in range(1, 12):
        sw_value = 'SW' + str(i)
        # добавляем их в список оборудования
        sep_list.append(sw_value)
        # скажем что имя, которое нужно отдать на выходе = имя хоста, например 'SCH-64-1-APC.zao.obr.mos.ru'
    return_name = hostname
    # начинаем идти по всем сепараторам
    for sep in sep_list:
        # пытаемся убрать часть строки используя сепаратор
        parsed_name = hostname.partition(sep)[0]
        # если сепаратор подошел и строка стала короче, выдаем новую строку на выходе функции
        if parsed_name < return_name:
            # убираем последний символ "-"
            return_name = parsed_name[:-1]

    return return_name


# метод, добавляющий хост в группу. На входе получает хостнейм и группу
def add_host_in_group(host_creds, hostname, groupid):
    with ZabbixAPI(url=host_creds[0], user=host_creds[1], password=host_creds[2]) as zapi:
        group_add = zapi.hostgroup.massadd(
            groups=[{'groupid': groupid}],
            hosts=[{'hostid': hostname}])
    return group_add


# метод, возвращающий hostid переданного ему хоста
def get_hosts(host_creds, hostname):
    with ZabbixAPI(url=host_creds[0], user=host_creds[1], password=host_creds[2]) as zapi:
        host = zapi.host.get(

            filter={'host': hostname},
            output=['hostid']
        )
    return host[0].get('hostid')


# метод, ищущий переданную ему группу в списке групп groupname_list и в случае её нахождения возвращающий ID группы
def groupsearch(groupname, host_creds):
    if groupname in groupname_list:

        with ZabbixAPI(url=host_creds[0], user=host_creds[1], password=host_creds[2]) as zapi:
            gotcha = zapi.hostgroup.get(
                filter={'name': groupname},
                output='groupid'
            )
    else:
        return False
    return gotcha[0].get('groupid')


# метод, возвращающий хосты, которые состоят только в одной группе
def single_group_host(host_creds):
    # объявляем лист, где буду хранится одинокие хосты
    single_group_host = list()
    with ZabbixAPI(url=host_creds[0], user=host_creds[1], password=host_creds[2]) as zapi:
        single_host = zapi.host.get(
            
        )


# делаем бизнес
# получаем все хосты с сервера
get_all_hosts(pob_new)
# получаем все группы с сервера
make_group_name_list()

#print(hostnames.index('SCH-1501-7-SW1.cao.obr.mos.ru'))


# для каждого хоста, отрезаем кусок и смотрим в какой он группе
try:
    for each_host in hostnames[10125:]:
        group_name_from_host = get_hostgroup_from_host(each_host)
        # из выражения сверху мы получили название группы где должен быть хост
        # теперь в списке всех групп ищем совпадение названия
        if groupsearch(group_name_from_host, pob_new):
            groupid = groupsearch(group_name_from_host, pob_new)
            hostid = get_hosts(pob_new, each_host)
            add_host_in_group(pob_new, hostid, groupid)
            print('{hostname} добавлен в группу {groupid}'.format(hostname=each_host, groupid=groupid))
except Exception as e:
    print(e)
    pass
