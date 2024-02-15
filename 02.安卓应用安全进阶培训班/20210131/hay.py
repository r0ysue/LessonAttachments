from hashlib import md5
import requests
import base64
import binascii
import re
from Crypto.Cipher import AES
import json 
 

## aes 加密/解密
class AESECB:
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_ECB
        self.bs = 16  # block size
        self.PADDING = lambda s: s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
    def encrypt(self, text):
        generator = AES.new(self.key, self.mode)  # ECB模式无需向量iv
        crypt = generator.encrypt(self.PADDING(text))
        crypted_str = base64.b64encode(crypt)
        result = crypted_str.decode()
        return result

    def decrypt(self, text):
        generator = AES.new(self.key, self.mode)  # ECB模式无需向量iv
        text += (len(text) % 4) * '='
        decrpyt_bytes = base64.b64decode(text)
        meg = generator.decrypt(decrpyt_bytes)
        # 去除解码后的非法字符
        try:
            result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f\n\r\t]').sub('', meg.decode())
        except Exception:
            result = '解码失败，请重试!'
        return result


import time



# if __name__ == '__main__':

if __name__ == '__main__':
 
    a = AESECB("8648754518945235")
    print(a.encrypt('1'))
    print(a.decrypt(a.encrypt('1')))

    ctl = "index"
    act = "index"
    signqt = md5(("550904&*5978846()"+ctl+"+_"+act+"@!@###@").encode('utf8')).hexdigest()
    timeqt = str(round(time.time() * 1000))
    headers = {"X-JSL-API-AUTH": "sha1|1611928510|693SMeR0H|8fe0b019e47e9d09be043ce85f0e7cf0582b50f2"}
    body = {
        "screen_width":"1440",
        "screen_height":"2392",
        "sdk_type":"android",
        "sdk_version_name":"1.3.0",
        "sdk_version":"2020031801",
        "ctl":ctl,
        "act":act,
        "signqt":signqt,
        "timeqt":timeqt
    }

    requestDATA = a.encrypt(str(body));
    url = "http://hhy2.hhyssing.com:46451/mapi/index.php?requestData="+requestDATA+"i_type=1&ctl="+ctl+"&act"+act;
    rsp = requests.post(url,headers= headers);
    result = json.loads(rsp.text).get("output")
    d = AESECB("7489148794156147")
    print(d.decrypt(result));

