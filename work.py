from ZabbixWorker import *

# клиент для класса ZabbixWorker

res = ZabbixWorker()


print(res.add_host(office,248,method=2))