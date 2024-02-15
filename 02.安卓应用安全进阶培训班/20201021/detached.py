# -*- coding: utf-8 -*-
from __future__ import print_function

import sys

import frida
import time

def on_detached():
    print("on_detached")

def on_detached_with_reason(reason):
    print("on_detached_with_reason:", reason)

def on_detached_with_varargs(*args):
    print("on_detached_with_varargs:", args)

device = frida.get_usb_device()
#device = frida.get_device_manager.add_remote_device("192.168.0.2:8888")

pid = device.spawn(["com.android.settings"])
device.resume(pid)
time.sleep(1)

#session = frida.attach("mousepad")
session = device.attach(pid)
#session = frida.attach("Twitter")
print("attached")
session.on('detached', on_detached)
session.on('detached', on_detached_with_reason)
session.on('detached', on_detached_with_varargs)
sys.stdin.read()
