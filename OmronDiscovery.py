#! /usr/bin/env python3
'''
	Copyright 2022 Pentastic

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.

        This should work on Linux using Python3
        Add a link local ip to your pc beforehand (sudo ip a a 169.254.240.100/16 dev [nic]). Should automate this in next version
        
'''
import socket, os, subprocess

_iTimeout = 2

def getAddresses():
    interfaces=[]
    if os.name == 'nt': # This should work on Windows
        proc=subprocess.Popen("ipconfig | FINDSTR \"IPv4 Address Subnet\" | FINDSTR /V \"IPv6\"",shell=True,stdout=subprocess.PIPE)
        allines=proc.stdout.readlines()
        for i in range(0,len(allines),2):
            ip = allines[i].split(b':')[1].rstrip().lstrip()
            mask = allines[i+1].split(b':')[1].rstrip().lstrip()
            interfaces.append((ip.decode(), mask.decode(), None))
    else: # And this on any Linux
        proc=subprocess.Popen("ip address | grep inet | grep -v \"127.0.0.1\" | grep -v \"inet6\"", shell=True, stdout=subprocess.PIPE)
        for interface in proc.stdout.readlines():
            int_parts = interface.lstrip().split(b' ')
            ip = int_parts[1].split(b'/')[0]
            cidr = int(int_parts[1].split(b'/')[1])
            bcidr = (cidr*'1'+(32-cidr)*'0')
            mask = str(int(bcidr[:8],2)) + '.' + str(int(bcidr[8:16],2)) + '.' + str(int(bcidr[16:24],2)) + '.' + str(int(bcidr[24:],2))
            intname = int_parts[len(int_parts)-1].rstrip()
            interfaces.append((ip.decode(),mask,intname))
    return interfaces

def send_only(s, ip, port, string):
    data = bytes.fromhex(string.replace(' ',''))
    s.sendto(data, (ip, port))

def recv_only(s):
    data, addr=s.recvfrom(1024)
    return data, addr

def recvOnly(s):
    data, addr = s.recvfrom(1024)
    return data, addr

def getDevices(sSrcIP, bSrcDev, iTimeout):
    print('[*] Scanning for Devices')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(iTimeout)
    if os.name == 'nt': sock.bind((sSrcIP,0))
    else: sock.setsockopt(socket.SOL_SOCKET, 25, bSrcDev)
    
    data='80000700fffe006a00012768'
    send_only(sock, '169.254.255.255', 9600, data)
    receivedData = []
    while True:
        try: receivedData.append(recv_only(sock))
        except: break
    sock.close()

    arrDevices=[]
    for data in receivedData:
        data,ip=data
        ## Retrieve Type
        sType = data[34:47].decode()
        sVers = data[54:59].decode()
        arrDevices.append({'IP':ip[0],'TYPE':sType,'VERS':sVers})
    return arrDevices

### MAIN ###
## Select Adapter, IP does not have to be in the same subnet
i=1
arrInterfaces=getAddresses()
for interface in arrInterfaces:
    print(('[{}] {} / {}'.format(i, interface[0], interface[1])))
    i+=1
print('[Q] Quit now')
if i>2: answer=input('Please select the adapter [1]: ')
else: answer=str(i-1)
if answer.lower()=='q': exit()
if answer=='' or not answer.isdigit() or int(answer)>=i: answer=1
sSrcAddr = arrInterfaces[int(answer)-1][0]
bSrcDev = arrInterfaces[int(answer)-1][2]

print('[*] Sending the discovery packet and waiting {} seconds for answers...'.format(_iTimeout))
arrDevices=getDevices(sSrcAddr, bSrcDev, _iTimeout)
for arrDevice in arrDevices:
    print('[+] Found Omron device at IP address {}, Controller Model {}, Controller Version {}'.format(arrDevice['IP'], arrDevice['TYPE'], arrDevice['VERS']))
if len(arrDevices) == 0: print('[-] Too bad, no devices found')
input('Press Enter To Close')
exit(0)
