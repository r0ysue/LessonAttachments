import frida
import json
import time
import uuid
import base64
import re

def my_message_handler(message, payload):
    print(message)
    print(payload)
    if message["type"] == "send":
        
        #image = re.findall("(-?\d+)", message["payload"])
        image = message["payload"]
        print(image)

        intArr = []
        for m in image:
            ival = int(m)
            if ival < 0:
                ival += 256
            intArr.append(ival)  
        bs = bytes(intArr)

        fileName = str(uuid.uuid1()) + ".jpg"
        f = open(fileName,'wb')
        f.write(bs)
        f.close()
        
device = frida.get_usb_device()
target = device.get_frontmost_application()
session = device.attach(target.pid)
# 加载脚本
with open("20201030hook.js") as f:
    script = session.create_script(f.read())
script.on("message" , my_message_handler) #调用错误处理

script.load()


# 脚本会持续运行等待输入
input()
