# -*- coding: utf-8 -*-
from __future__ import print_function

import frida
import time

device = frida.get_usb_device()
#device = frida.get_device_manager.add_remote_device("192.168.0.2:8888")

pid = device.spawn(["com.android.settings"])
device.resume(pid)
time.sleep(1)

#session = frida.attach("mousepad")
session = device.attach(pid)
script = session.create_script("""\
rpc.exports = {
  hello: function () {
    return 'Hello';
  },
  failPlease: function () {
    return 'oops';
  }
};
""")
script.load()
api = script.exports
print("api.hello() =>", api.hello())
print('api.fail_please()',api.fail_please())
