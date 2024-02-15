# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import frida


device = frida.get_usb_device()

channel = device.open_channel("tcp:27042")
print("Got channel:", channel)

welcome = channel.read(512)
print("Got welcome message:", welcome)

channel.write_all(b"whoami")
reply = channel.read(512)
print("Got reply:", reply)

channel.close()
print("Channel now:", channel)
