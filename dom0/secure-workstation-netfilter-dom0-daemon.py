#!/usr/bin/env python

import os
import socket
import sys

HOST = 'localhost'
PORT = 10293

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.sendall(os.environ['QREXEC_REMOTE_DOMAIN'] + '\n')
s.sendall(sys.stdin.read())
s.send('\x00')
b = s.recv(1)
if ord(b) == 1:
    print("Accept")
else:
    print("Deny")
s.close()
