import frida
import json
import time
import uuid
import base64
import re
from Crypto.Cipher import AES

def my_message_handler(message, payload):
    print(message)
    print(payload)
    if message["type"] == "send":
        print(message["payload"])
        #image = re.findall("(-?\d+)", message["payload"])
        image = message["payload"]
        intArr = []
        for m in image:
            ival = int(m)
            if ival < 0:
                ival += 256
            intArr.append(ival)
        bs = bytes(intArr)

        image_key = base64.decodebytes(bytes('svOEKGb5WD0ezmHE4FXCVQ==', encoding='utf8')) # 图片解密key
        print(image_key)
        iv = base64.decodebytes(bytes('4B7eYzHTevzHvgVZfWVNIg==', encoding='utf8'))  # 图片解密iv
        print(iv)

        cipher = AES.new(image_key, AES.MODE_CBC, iv)
        text_decrypted = cipher.decrypt(bs)
        def unpad(s): return s[0:-s[-1]]
        de = unpad(text_decrypted)        

        fileName = str(uuid.uuid1()) + ".jpg"
        f = open(fileName, 'wb')
        f.write(de)
        f.close()


device = frida.get_usb_device()
target = device.get_frontmost_application()
session = device.attach(target.pid)
# 加载脚本
with open("20201031hook.js") as f:
    script = session.create_script(f.read())
script.on("message", my_message_handler)  # 调用错误处理

script.load()


# 脚本会持续运行等待输入
input()
