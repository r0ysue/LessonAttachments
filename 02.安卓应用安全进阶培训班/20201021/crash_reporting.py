# -*- coding: utf-8 -*-
from __future__ import print_function

import sys

import frida


def on_process_crashed(crash):
    print("on_process_crashed")
    print("\tcrash:", crash)

def on_detached(reason, crash):
    print("on_detached()")
    print("\treason:", reason)
    print("\tcrash:", crash)

device = frida.get_usb_device()
device.on('process-crashed', on_process_crashed)
session = device.attach("com.android.settings")
session.on('detached', on_detached)
print("[*] Ready")
sys.stdin.read()
