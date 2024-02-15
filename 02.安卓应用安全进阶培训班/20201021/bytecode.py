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
#session = device.attach(pid)

system_session = device.attach(0)
bytecode = system_session.compile_script(name="bytecode-example", source="""\
rpc.exports = {
  listThreads: function () {
    return Process.enumerateThreadsSync();
  }
};
""")

session = device.attach(pid)
script = session.create_script_from_bytes(bytecode)
script.load()
api = script.exports
print("api.list_threads() =>", api.list_threads())
