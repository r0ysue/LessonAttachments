import requests

headers = {
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
    'Params': 'oT64bDAlAwDXED0/z2ga1ToBnOh81V9JTFynWutluPEj6LdluRnFbl1WWWuXJM0Y',
    'Accept': 'application/json, text/plain, */*',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
    'Origin': 'http://www.dtasecurity.cn:30080',
    'Referer': 'http://www.dtasecurity.cn:30080/',
    'Accept-Language': 'zh-CN,zh;q=0.9',
}

response = requests.get('http://www.dtasecurity.cn:35555/20210803', headers=headers, verify=False)
print(response.text)
