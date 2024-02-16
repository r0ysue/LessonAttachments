import time

import execjs
import requests

with open("0808.js") as f:
    code = f.read()
ctx = execjs.compile(code)
print(ctx.call("encrypt", "20101628427047641"))

def getdata(start):
    headers = {
        'Connection': 'keep-alive',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'DTA Chrome/91.0.4472.77',
        'Content-Type': 'application/json;charset=UTF-8',
        'Origin': 'http://www.dtasecurity.cn:30080',
        'Referer': 'http://www.dtasecurity.cn:30080/',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    }
    timestamp = time.time()
    size = 10
    sign = ctx.call("encrypt", str(start) + str(size) + str(timestamp))
    data = {"start": start, "size": size, "sign": sign, "timestamp": timestamp}

    response = requests.post('http://www.dtasecurity.cn:35555/202107get_data', headers=headers, json=data, verify=False)
    return response.json()

if __name__ == '__main__':

    sumlist = []
    for i in range(5):
        result = getdata(i * 10)
        for item in result.get("data"):
            sumlist.append(item.get("data"))
    print(sum(sumlist))
