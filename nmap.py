from optparse import OptionParser
parser=OptionParser()
parser.add_option("-t","--target",dest="ip",help="SET IP [site]")
(options,aegs)=parser.parse_args()
info='''
scan port in pc
PORT SCANNER
with
======================
    NMAP
    By ADAM ZAYENE         
======================
'''
print(info)
from socket import socket , AF_INET , SOCK_STREAM
so=socket(AF_INET,SOCK_STREAM)
ch=""
ip=input("donner votre ip:    ")  
fin=int(input("donner lim pour scan:     "))
info2='''
======================
PORT\tSTATE\tSERVICES         
======================
'''
print(info2)
for ports in range(1,fin):
    so=socket(AF_INET,SOCK_STREAM)
    so.settimeout(0.1)
    try:
        con=so.connect((ip,ports))
        if con==None:
            f=open("scan_open_port.txt","a")
            f.write(ip+"\n")
            ch=ch+"/"+str(ports)
            f.write(str(ports)+"\n")
            f.close
            print(ports," \tOPEN\t")
    except Exception:
        print(ports," \tCLOSE\t")
print(ch)