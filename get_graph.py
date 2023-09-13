from pyzabbix import ZabbixAPI

# перечень серверов, к которым будем коннектится
server = ['https://URL_ADDRESS', 'username', 'password']

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
			date_from = '2023-04-01'
			date_to = '2023-06-30'

			# построчно читаем файл graphs_hosts и добавляем эти строки в лист graphs
			graphs = list()
			with open('graphs_hosts', 'r') as file:
				for line in file.readlines():
					graphs.append(line.rstrip())
			# куки для хранения айдишника сессии
			cookies = {
				'zbx_session': get_session_id()
			}

			# для каждого хостнейма, скачиваем график, подсовывая айдишник сессии из соответствующего метода
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


res = ZabbixAPIWorker()
res.get_
