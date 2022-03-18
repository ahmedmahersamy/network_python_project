#!/usr/bin/python3.10

import sys
import socket
import pyfiglet
import re
import sys
import smtplib
import subprocess
from struct import *


#import nmap

ascii_banner = pyfiglet.figlet_format("Welcome To Network's Guy")
print(ascii_banner)
ipAddress = ""
minPortNum = 0
maxPortNum = 1024
portsRange = []
scanType = 'TCP'

def userInput():
    flag = True
    global ipAddress,portsRange,scanType,maxPortNum,minPortNum
    while flag:
        try:
            ipAddress  = input("Please Enter The Target's IP <x.x.x.x> : ")
            ip_add_pattern = re.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
            
            if ip_add_pattern.search(ipAddress):
                print(f"{ipAddress} is a valid ip address")
            else:
                print("Invalid IP Address")
                continue
            
            minPortNum = input("Please Enter The Start Of The Ports Range (Default 0): ")
            if minPortNum != '':
                try:
                    minPortNum = int(minPortNum)
                except ValueError:
                    print("Invalid Port Number.Using The Default 0")
                    minPortNum = 0
            else:
                print("Using The Default 0")
                minPortNum = 0
                
            maxPortNum = input("Please Enter The End Of The Ports Range (Default 1024): ")
            if maxPortNum != '':
                try:
                    maxPortNum = int(maxPortNum)
                except ValueError:
                    print("Invalid Port Number.Using The Default 1024")
                    maxPortNum = 1024
            else:
                print("Using The Default 1024")
                maxPortNum = 1024

            
            scanInType = input("Please Choose a Scan Type (Default TCP) :\n1)TCP(T)\n2)UDP(U)\n3)Both(B) \n>>>> ")
            try:
                
                if scanInType.isdecimal():
                    if int(scanInType) == 1:
                        scanType = 'TCP'
                    elif int(scanInType) == 2:
                        scanType = 'UDP'
                    elif int(scanInType) == 3:
                        scanType = 'TCP & UDP'
                    else:
                        print("Invalid Option. Using The Default Scan Type (TCP)")
                        scanType = 'TCP'
                        
                elif scanInType == '' :
                    print("Using The Default Scan Type (TCP)")
                    scanType = 'TCP'
                elif scanInType.lower() == 't':
                    scanType = 'TCP'
                elif scanInType.lower() == 'u':
                    scanType = 'UDP'
                elif scanInType.lower() == 'b':
                    scanType = 'TCP & UDP'
                else:
                    print("Invalid Option. Using The Default Scan Type (TCP)")
                    scanType = 'TCP'
                    
            except Exception as e:
                print("Error in Scan Type")
                print(e)
                print(type(e))
            flag = False
            
        except Exception as e:
            print(e)
            print(type(e))
    portsRange = list(range(int(minPortNum),int(maxPortNum)+1))
    print(f"Scanning Target {ipAddress} {scanType} Ports {minPortNum}-{maxPortNum}")
    

#userInput()
def unknownport():
    s = socket.socket()
    port = 12345
    s.bind(('', port)) 
    print ("socket binded to %s" %(port))
    s.listen(5)    
    print ("socket is listening")  
    while True:
        c, addr = s.accept()    
        print ('Got connection from', addr[0] )
        subprocess.call(["iptables", "-A", "INPUT", "-s", addr[0], "-j", "DROP"]) #Block IP
        a= smtplib.SMTP('smtp.gmail.com', 587)
        a.starttls()
        a.login("Mohamad.hasan.aziz@gmail.com", "aoaydeewhjxuvrtu")
        message = "Alert Connection Attempt to unknown port\nIp address : "+addr[0]
        a.sendmail("Mohamad.hasan.aziz@gmail.com", "mohamadaziz1362@gmail.com", message)
        a.quit()
        s.close()
        break   
#unknownport()

def sniffer():
    
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# receive a packet
    while True:
        packet = s.recvfrom(65565)  
        #packet string from tuple
        packet = packet[0]
        #take first 20 characters for the ip header
        ip_header = packet[0:20]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        #version_ihl = iph[0]
        #version = version_ihl >> 4
        #ihl = version_ihl & 0xF
        #iph_length = ihl * 4
        #ttl = iph[5]
        #protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        #d_addr = socket.inet_ntoa(iph[9]);
        print(s_addr)
        subnetregex=re.compile(r'(192\.168\.10\.)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        if subnetregex.search(s_addr):
            print("Valid traffic")
        else:
            print("Alert IP from outside the subnet detected") 

sniffer()

    
    








"""Using Argparse"""
'''
#!/usr/bin/python

import argparse
from socket import *



def ShowBanner(ports,sock): 
                           try:
                             if ports == "80":
                            sock.send("GET HTTP/1.1  \r\n")
                     else:
                        sock.send(" \r\n ")
                        results = sock.recv(4096)   
                                print "[+] Service: " + str(results) + "\n"
                           except:
                                print "[+] Service Unavailable!\n"


          

def tcpScan(targetIp,targetPort):
                         print "Port Scan Initiated on: " + targetIp + "\n" 
            
                         try: 
                    sock = socket(AF_INET,SOCK_STREAM)
                    sock.connect((targetIp,int(targetPort)))
                            print "[+] TCP Port: " +str(targetPort) + " Open"
                            ShowBanner(targetPort,sock)     
                          
                         except:
                             print "[+] TCP Port: " +str(targetPort) + " CLOSED\n"

                         finally:
                               sock.close()

def udpScan(targetIp,targetPort):
       try:
          consock = socket(AF_INET,SOCK_DGRAM)
          consock.connect((targetIp,targetPort))
          print "[+] UDP Port Open: " + str(targetPort)
          ShowBanner(targetPort,consock)
       except:
          print "[+] UDP port closed: " + str(targetPort)
          


def checkType(ip,port,isUdp):
     for ports in port:
         if not(isUdp):
            tcpScan(ip,int(ports))
         else:
            udpScan(ip,int(ports))
       
  


def main():
    print "Welcome To TCP Port Scanner!\n"
    try:
     parser = argparse.ArgumentParser("TCP Scanner")
     parser.add_argument("-a","--address",type=str,help="Enter the ip address to scan")
     parser.add_argument("-p","--port",type=str,help="Enter The port to scan")
     parser.add_argument("-u","--udp",action="store_true")
     args = parser.parse_args()
     ipaddress = args.address
     port = args.port.split(',')
     isUdp = args.udp
    
     checkType(ipaddress,port,isUdp)
     
    except:
     print "[+] No Arugments Supplied\n example: python portscanner.py -a 192.168.43.224 -p 21,22,80"
    
main()
'''

"""nmap_port_scanner.py"""

'''
#!/usr/bin/env python3
#Use these commands in Kali to install required software:
#  sudo apt install python3-pip
#  pip install python-nmap

# Import nmap so we can use it for the scan
import nmap
# We need to create regular expressions to ensure that the input is correctly formatted.
import re

# Regular Expression Pattern to recognise IPv4 addresses.
ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# Regular Expression Pattern to extract the number of ports you want to scan. 
# You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
# Initialising the port numbers, will be using the variables later on.
port_min = 0
port_max = 65535

# This port scanner uses the Python nmap module.
# You'll need to install the following to get it work on Linux:
# Step 1: sudo apt install python3-pip
# Step 2: pip install python-nmap


# Basic user interface header
print(r"""______            _     _  ______                 _           _ 
|  _  \          (_)   | | | ___ \               | |         | |
| | | |__ ___   ___  __| | | |_/ / ___  _ __ ___ | |__   __ _| |
| | | / _` \ \ / / |/ _` | | ___ \/ _ \| '_ ` _ \| '_ \ / _` | |
| |/ / (_| |\ V /| | (_| | | |_/ / (_) | | | | | | |_) | (_| | |
|___/ \__,_| \_/ |_|\__,_| \____/ \___/|_| |_| |_|_.__/ \__,_|_|""")
print("\n****************************************************************")
print("\n* Copyright of David Bombal, 2021                              *")
print("\n* https://www.davidbombal.com                                  *")
print("\n* https://www.youtube.com/davidbombal                          *")
print("\n****************************************************************")

open_ports = []
# Ask user to input the ip address they want to scan.
while True:
    ip_add_entered = input("\nPlease enter the ip address that you want to scan: ")
    if ip_add_pattern.search(ip_add_entered):
        print(f"{ip_add_entered} is a valid ip address")
        break

while True:
    # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning 
    # all the ports is not advised.
    print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
    port_range = input("Enter port range: ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

nm = nmap.PortScanner()
# We're looping over all of the ports in the specified range.
for port in range(port_min, port_max + 1):
    try:
        # The result is quite interesting to look at. You may want to inspect the dictionary it returns. 
        # It contains what was sent to the command line in addition to the port status we're after. 
        # For in nmap for port 80 and ip 10.0.0.2 you'd run: nmap -oX - -p 89 -sV 10.0.0.2
        result = nm.scan(ip_add_entered, str(port))
        # Uncomment following line and look at dictionary
        # print(result)
        # We extract the port status from the returned object
        port_status = (result['scan'][ip_add_entered]['tcp'][port]['state'])
        print(f"Port {port} is {port_status}")
    except:
        # We cannot scan some ports and this ensures the program doesn't crash when we try to scan them.
        print(f"Cannot scan port {port}.")
'''
"""port_scanner_regex.py """
'''
#!/usr/bin/env python3
# The socket module in Python is an interface to the Berkeley sockets API.
import socket
# We need to create regular expressions to ensure that the input is correctly formatted.
import re

# Regular Expression Pattern to recognise IPv4 addresses.
ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# Regular Expression Pattern to extract the number of ports you want to scan. 
# You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
# Initialising the port numbers, will be using the variables later on.
port_min = 0
port_max = 65535

# This script uses the socket api to see if you can connect to a port on a specified ip address. 
# Once you've successfully connected a port is seen as open.
# This script does not discriminate the difference between filtered and closed ports.


open_ports = []
# Ask user to input the ip address they want to scan.
while True:
    ip_add_entered = input("\nPlease enter the ip address that you want to scan: ")
    if ip_add_pattern.search(ip_add_entered):
        print(f"{ip_add_entered} is a valid ip address")
        break

while True:
    # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning all 
    # the ports is not advised.
    print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
    port_range = input("Enter port range: ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

# Basic socket port scanning
for port in range(port_min, port_max + 1):
    # Connect to socket of target machine. We need the ip address and the port number we want to connect to.
    try:
        # Create a socket object
        # You can create a socket connection similar to opening a file in Python. 
        # We can change the code to allow for domain names as well.
        # With socket.AF_INET you can enter either a domain name or an ip address 
        # and it will then continue with the connection.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # You want to set a timeout for the socket to try and connect to the server. 
            # If you make the duration longer it will return better results. 
            # We put it at 0.5s. So for every port it scans it will allow 0.5s 
            # for a successful connection.
            s.settimeout(0.5)
            # We use the socket object we created to connect to the ip address we entered 
            # and the port number. If it can't connect to this socket it will cause an 
            # exception and the open_ports list will not append the value.
            s.connect((ip_add_entered, port))
            # If the following line runs then then it was successful in connecting to the port.
            open_ports.append(port)

    except:
        # We don't need to do anything here. If we were interested in the closed ports we'd put something here.
        pass

# We only care about the open ports.
for port in open_ports:
    # We use an f string to easily format the string with variables so we don't have to do concatenation.
    print(f"Port {port} is open on {ip_add_entered}.")
'''
"""
#!/usr/bin/python3.10

import sys
import socket
import pyfiglet


ascii_banner = pyfiglet.figlet_format("Port Scanner")
print(ascii_banner)


ip = '127.0.0.1'
#ip = socket.gethostbyname(host)

open_ports =[] 

ports = range(1, 65535)


def probe_port(ip, port, result = 1): 
  try: 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    sock.settimeout(0.0001) 
    r = sock.connect_ex((ip, port))
    print("Scanning Port ",port)
    if r == 0: 
      result = r 
    sock.close() 
  except Exception as e: 
    pass 
  return result


for port in ports: 
    sys.stdout.flush() 
    response = probe_port(ip, port) 
    if response == 0: 
        open_ports.append(port) 
    

if open_ports: 
  print ("Open Ports are: ") 
  print (sorted(open_ports)) 
else: 
  print ("Looks like no ports are open :(")
"""

"""

from socket import *
import time
startTime = time.time()

if __name__ == "__main__":
    target = input('enter host for scanning:')
    t_IP = gethostbyname(target)
    print('Starting scan on host: ', t_IP)

    for i in range(50, 500):
        s = socket(AF_INET, SOCK_STREAM)

        conn = s.connect_ex((t_IP, i))
        if (conn == 0):
            print('Port %d: OPEN' % (i,))
        s.close()
print("time taken:", time.time() - startTime)
"""
'''NETWORK SCANNER'''
"""
#!/usr/bin/python3

from scapy.all import *

interface = "eth0"
ip_range = "10.10.0.0/16"
broadcastMac = "ff:ff:ff:ff:ff:ff"

packet = Ether(dst=broadcastMac)/ARP(pdst = ip_range) 

ans, unans = srp(packet, timeout =2, iface=interface, inter=0.1)

for send,receive in ans:
        print (receive.sprintf(r"%Ether.src% - %ARP.psrc%"))  
"""
"""
#!/usr/bin/python3.10
import requests
from bs4 import BeautifulSoup
import socket
import sys


print("\nWelcome To Our Port Scanner\n")
targetMachine = input("Please Enter The IP of The Target Machine <x.x.x.x> : ")
minPortRange = input("Please Enter Your Minimum Port's Number : ")
maxPortRange = input("Please Enter Your Maximum Port's Number : ")
portsRange = list(range(int(minPortRange),int(maxPortRange)+1))
#print(portsRange)

print("\nInitiating Scanning...")
print("Scanning Target ",targetMachine," From Port ",minPortRange," To ",maxPortRange)

try:
    for port in portsRange:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        status = s.connect_ex((targetMachine,port))
        print("Scanning Port ",port,"...")

        if status == 0:
            print("Port {} is Open".format(port))
        else:
            print("port {} is Closed".format(port))
        s.close()

except KeyboardInterrupt:
        print("\n Exiting Program !!!!")
        sys.exit()
except socket.error:
        print("\ Server not responding !!!!")
        sys.exit()
"""
