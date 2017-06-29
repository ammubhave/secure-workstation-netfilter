#!/usr/bin/env python

# import os
import struct
import socket
import subprocess
import sys

HOST = 'localhost'
PORT = 10293

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
# s.sendall(os.environ['QREXEC_REMOTE_DOMAIN'] + '\n')
srcip, dstip = sys.stdin.read().strip().split()


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


srcip = int2ip(int(srcip))
dstip = int2ip(int(dstip))

vmname = "<none>"
for line in subprocess.check_output(['/usr/bin/qvm-ls',
                                     '--raw-data', 'name', 'ip']).splitlines():
    name, ip = line.split('|')
    if ip == srcip:
        vmname = name
        break
s.sendall('%s %s\x00' % (vmname, dstip))
b = s.recv(1)
if ord(b) == 1:
    print("Accept")
else:
    print("Deny")
s.close()
