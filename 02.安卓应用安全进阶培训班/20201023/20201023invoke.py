import time
import frida
from flask import Flask, jsonify, request
import json

def my_message_handler(message , payload): #定义错误处理
	print(message)
	print(payload)


# 连接安卓机上的frida-server
#device = frida.get_device_manager().add_remote_device("192.168.0.3:8888")
#device = frida.get_device_manager().add_remote_device("118.126.66.193:58888")
device = frida.get_device_manager().add_remote_device("118.126.66.193:48888")

# 启动`demo01`这个app
pid = device.spawn(["com.example.demoso1"])
device.resume(pid)
time.sleep(1)
session = device.attach(pid)
# 加载脚本
with open("20201023hookandinvoke.js") as f:
    script = session.create_script(f.read())
script.on("message" , my_message_handler) #调用错误处理
script.load()

print(script.exports.fridamethod01("roysue"))
print(script.exports.fridamethod02("47fcda3822cd10a8e2f667fa49da783f"))

# 脚本会持续运行等待输入
#input()


app = Flask(__name__)


@app.route('/encrypt', methods=['POST'])#url加密
def encrypt_class():
    data = request.get_data()
    json_data = json.loads(data.decode("utf-8"))
    postdata = json_data.get("data")
    print(postdata)
    res = script.exports.fridamethod01(postdata)
    return res
 
 
@app.route('/decrypt', methods=['POST'])#data解密
def decrypt_class():
    data = request.get_data()
    json_data = json.loads(data.decode("utf-8"))
    postdata = json_data.get("data")
    res = script.exports.fridamethod02(postdata)
    return res
 
 
 
if __name__ == '__main__':
    app.run()