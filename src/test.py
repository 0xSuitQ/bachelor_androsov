import requests
r = requests.get("http://44.220.178.201:8080/", verify=False)
print(r.status_code, r.text)
