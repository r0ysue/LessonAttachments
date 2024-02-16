import json

import requests
import execjs

with open("waterSecurity.js", "r") as f:
    waterSecurity = f.read()
ctx = execjs.compile(waterSecurity)


def getdata():
    headers = {
        'Connection': 'keep-alive',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'http://yc.wswj.net',
        'Referer': 'http://yc.wswj.net/',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    }
    rawdata = {
        "name": "SelectRainMapData",
        "btime": "202108192200",
        "etime": "202108192300",
        "rainlevel": "A:10,25,50,100",
        "isoline": "N",
        "heatRange": 50,
        "stcdtype": "1,0,0,0,0,0",
        "fresh": 0,
        "points": ""
    }
    data_str = json.dumps(rawdata, ensure_ascii=False, separators=(",", ":"))
    data = ctx.call("encodeparams", data_str)
    data = json.loads(data)
    response = requests.post('http://61.191.22.196:5566/AHSXX/service/PublicBusinessHandler.ashx', headers=headers, data=data, verify=False)
    data = response.json().get("data")
    return data


if __name__ == '__main__':
    data = getdata()
    decoderesult = ctx.call("decoderesult", data)
    print(decoderesult)
