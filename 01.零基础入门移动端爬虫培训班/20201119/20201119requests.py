import requests
r = requests.get('http://httpbin.org/ip')
print(r.text)

proxy = {"http":"socks5://127.0.0.1:1080","https":"socks5://127.0.0.1:1080"}
r2 =requests.get('http://httpbin.org/ip',proxies =proxy)
print(r2.text)