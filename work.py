from ZabbixWorker import *

# клиент для класса ZabbixWorker

res = ZabbixWorker()

res.add_host(office, 182, method=1, dns=False)