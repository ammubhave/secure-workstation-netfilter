#!/usr/bin/env python

import subprocess
import time

while True:
    s = ''
    with open('/sys/class/secure-workstation-netfilter/prompt') as f:
        s = f.read()
    if s == '':
        time.sleep(1)
    else:
        subprocess.Popen(['/usr/lib/qubes/qrexec-client-vm dom0 '
                          'qubes.SecureWorkstationNetfilter ' + s], shell=True)
        print(s)
