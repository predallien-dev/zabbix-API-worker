import requests as req
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

while True:

    resp = req.get( url='https://avilex.ru/')
    print(resp.status_code)
    time.sleep(60)




