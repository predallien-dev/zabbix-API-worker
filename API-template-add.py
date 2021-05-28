from pyzabbix.api import ZabbixAPI

# цепляем один темплейт на всю группу хостов
# нужно будет ввести вручную id целевой группы хостов и id темплейта, который хотим назначить

url='https://monitoring.avilex.ru/zabbix/'

host_group_id = input('Enter group id: ')
template_id = input('Enter template id: ')

# обращаю внимание на user и password
with ZabbixAPI(url=url, user='m.gerbersgagen', password='') as zapi:

    all_hosts_ids = zapi.host.get(output='host', groupids=host_group_id)
    zapi.do_request('template.massadd',

                {
                    'templates':
                        {
                            'templateid': template_id
                        },
                    'hosts': all_hosts_ids,
                }
                    )

