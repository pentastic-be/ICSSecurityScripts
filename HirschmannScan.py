#! /usr/bin/env python3
'''
	Copyright 2023 Photubias(c)

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

        This should work on Linux & Windows
        
        File name HirschmannScan.py
        written by @tijldeneut

        --- Hirschmann Scanner ---
        It uses the same scanning packets as used in the HiDiscovery tool
'''
import os, time, sys, re
from subprocess import Popen, PIPE
from ctypes import CDLL, POINTER, Structure, c_void_p, c_char_p, c_ushort, c_char, c_long, c_int, c_ubyte, byref, create_string_buffer
from ctypes.util import find_library

##### Classes
class sockaddr(Structure):
    _fields_ = [("sa_family", c_ushort),
                ("sa_data", c_char * 14)]
class pcap_addr(Structure):
    pass
pcap_addr._fields_ = [('next', POINTER(pcap_addr)),
                      ('addr', POINTER(sockaddr)),
                      ('netmask', POINTER(sockaddr)),
                      ('broadaddr', POINTER(sockaddr)),
                      ('dstaddr', POINTER(sockaddr))]

class pcap_if(Structure):
    pass
pcap_if._fields_ = [('next', POINTER(pcap_if)),
                    ('name', c_char_p),
                    ('description', c_char_p),
                    ('addresses', POINTER(pcap_addr)),
                    ('flags', c_int)]
class timeval(Structure):
    pass
timeval._fields_ = [('tv_sec', c_long),
                    ('tv_usec', c_long)]
class pcap_pkthdr(Structure):
    _fields_ = [('ts', timeval),
                ('caplen', c_int),
                ('len', c_int)]

##### Initialize Pcap
if os.name == 'nt':
    try:
        os.chdir('C:/Windows/System32/Npcap')
        _lib = CDLL('wpcap.dll')
    except:
        print('Error: WinPcap/Npcap not found!')
        print('Please download here: https://nmap.org/npcap/')
        input('Press [Enter] to close')
        exit(1)
else:
    pcaplibrary = find_library('pcap')
    if pcaplibrary == None or str(pcaplibrary) == '':
        print('Error: Pcap library not found!')
        print('Please install with: e.g. apt install libpcap0.8')
        input('Press [Enter] to close')
        exit(1)
    _lib = CDLL(pcaplibrary)

## match DLL function to list all devices
pcap_findalldevs = _lib.pcap_findalldevs
pcap_findalldevs.restype = c_int
pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
## match DLL function to open a device: char *device, int snaplen, int prmisc, int to_ms, char *ebuf
##  snaplen - maximum size of packets to capture in bytes
##  promisc - set card in promiscuous mode?
##  to_ms   - time to wait for packets in miliseconds before read times out
##  errbuf  - if something happens, place error string here
pcap_open_live = _lib.pcap_open_live
pcap_open_live.restype = POINTER(c_void_p)
pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
## match DLL function to send a raw packet: pcap device handle, packetdata, packetlength
pcap_sendpacket = _lib.pcap_sendpacket
pcap_sendpacket.restype = c_int
pcap_sendpacket.argtypes = [POINTER(c_void_p), POINTER(c_ubyte), c_int]
## match DLL function to close a device
pcap_close = _lib.pcap_close
pcap_close.restype = None
pcap_close.argtypes = [POINTER(c_void_p)]
## match DLL function to get error message
pcap_geterr = _lib.pcap_geterr
pcap_geterr.restype = c_char_p
pcap_geterr.argtypes = [POINTER(c_void_p)]
## match DLL function to get next packet
pcap_next_ex = _lib.pcap_next_ex
pcap_next_ex.restype = c_int
pcap_next_ex.argtypes = [POINTER(c_void_p), POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_ubyte))]


_iTimeout = 5

def status(sMsg):
    sys.stderr.write(sMsg)
    sys.stderr.flush()

def getAllInterfaces():
    def addToArr(array, adapter, ip, mac, device, winguid):
        if len(mac) == 17: # When no or bad MAC address (e.g. PPP adapter), do not add
            array.append([adapter, ip, mac, device, winguid])
        return array

    # Returns twodimensional array of interfaces in this sequence for each interface:
    # [0] = adaptername (e.g. Ethernet or eth0)
    # [1] = Current IP (e.g. 192.168.0.2)
    # [2] = Current MAC (e.g. ff:ee:dd:cc:bb:aa)
    # [3] = Devicename (e.g. Intel 82575LM, Windows only)
    # [4] = DeviceGUID (e.g. {875F7EDB-CA23-435E-8E9E-DFC9E3314C55}, Windows only)
    interfaces=[]
    if os.name == 'nt': # This should work on Windows
        proc=Popen("getmac /NH /V /FO csv | FINDSTR /V disconnected", shell=True, stdout=PIPE)
        for interface in proc.stdout.readlines():
            intarr = interface.decode().split(',')
            adapter = intarr[0].replace('"','')
            devicename = intarr[1].replace('"','')
            mac = intarr[2].replace('"','').lower().replace('-',':')
            winguid = intarr[3].replace('"','').replace('\n', '').replace('\r', '')[-38:]
            proc = Popen('netsh int ip show addr "' + adapter + '" | FINDSTR /I IP', shell=True, stdout=PIPE)
            try: ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', proc.stdout.readlines()[0].decode(errors='ignore').replace(' ',''))[0]
            except: ip = ''
            interfaces=addToArr(interfaces, adapter, ip, mac, devicename, winguid)

    else: # And this on any Linux
        #proc=Popen("for i in `ifconfig -a | grep \"Link encap:\" | awk '{print $1}'`;do echo \"$i `ifconfig $i | sed 's/inet addr:/inet addr: /' | grep \"inet addr:\" | awk '{print $3}'` `ifconfig $i | grep HWaddr | awk '{print $5}'`\" | sed '/lo/d';done", shell=True, stdout=PIPE)
        proc=Popen("for i in $(ip address | grep -v \"lo\" | grep \"default\" | cut -d\":\" -f2 | cut -d\" \" -f2);do echo $i $(ip address show dev $i | grep \"inet \" | cut -d\" \" -f6 | cut -d\"/\" -f1) $(ip address show dev $i | grep \"ether\" | cut -d\" \" -f6);done", shell=True, stdout=PIPE)
        for interface in proc.stdout.readlines():
            intarr = interface.decode().split(' ')
            if len(intarr)<3: continue ## Device has no MAC address, L2 scanning not an option
            interfaces = addToArr(interfaces, intarr[0], intarr[1], intarr[2].replace('\n',''), '', '')

    return interfaces

## Listing all NPF adapters and finding the correct one that has the Windows Devicename (\Device\NPF_{GUID})
def findMatchingNPFDevice(windevicename):
    alldevs = POINTER(pcap_if)()
    bufErrbuf = create_string_buffer(256)
    if pcap_findalldevs(byref(alldevs), bufErrbuf) == -1:
        print('Error in pcap_findalldevs: %s\n' % bufErrbuf.value)
        exit(1)
    pcapdevices = alldevs.contents
    while pcapdevices:
        if str(pcapdevices.description) == windevicename: return pcapdevices.name
        if pcapdevices.next: pcapdevices = pcapdevices.next.contents
        else: pcapdevices = False
    return

def sendRawPacket(bNpfdevice, bData):
    def createPacket(bData):
        arrByteArr = (c_ubyte * len(bData))()
        b = bytearray()
        b.extend(bData)
        for i in range(0,len(bData)): arrByteArr[i] = b[i]
        return arrByteArr

    ## Get packet as a bytearray
    arrBytePacket = createPacket(bData)

    ## Send the packet
    bufErrbuf = create_string_buffer(256)
    handlePcapDev = pcap_open_live(bNpfdevice, 65535, 1, 1000, bufErrbuf) ## Device, max packet size, promiscuous mode, time limit in ms, buffer for errors
    if not bool(handlePcapDev):
        print('\nError: Please use sudo!\n')
        #else: print('\nUnable to open the adapter. %s is not supported by Pcap\n' % interfaces[int(answer - 1)][0])
        exit(1)

    if pcap_sendpacket(handlePcapDev, arrBytePacket, len(arrBytePacket)) != 0:
        print('\nError sending the packet: %s\n' % pcap_geterr(handlePcapDev))
        exit(1)

    pcap_close(handlePcapDev)
    return arrBytePacket

## Receive packets, expect device to receive on, src mac address + ethertype to filter on and timeout in seconds
def receiveRawPackets(bNpfdevice, iTimeout, sProtId, stopOnResponse=False):
    arrReceivedRawData = []
    bufErrbuf = create_string_buffer(256)
    handlePcapDev = pcap_open_live(bNpfdevice, 65535, 1, 1000, bufErrbuf) ## Device, max packet size, promiscuous mode, time limit in ms, buffer for errors
    if not bool(handlePcapDev):
        print('\nUnable to open the adapter. {} is not supported by Pcap\n'.format(bNpfdevice))
        exit(1)

    ptrHeader = POINTER(pcap_pkthdr)()
    ptrPktData = POINTER(c_ubyte)()
    iReceivedpacket = pcap_next_ex(handlePcapDev, byref(ptrHeader), byref(ptrPktData))
    ## Regular handler, loop until told otherwise (or with timer)
    flTimer = time.time() + int(iTimeout)
    i = 0
    while iReceivedpacket >= 0:
        iTimeleft = int(round(flTimer - time.time(), 0))
        if not stopOnResponse: status('Received packets: %s, time left: %i  \r' % (str(i), iTimeleft))
        if iTimeleft <= 0: break ## PCAP networkstack timeout elapsed or regular timeout
        lstRawdata = ptrPktData[0:ptrHeader.contents.len]

        if bytearray(lstRawdata[20:22]).hex() == sProtId: 
            arrReceivedRawData.append(lstRawdata)
            if stopOnResponse: break

        ## Load next packet
        iReceivedpacket = pcap_next_ex(handlePcapDev, byref(ptrHeader), byref(ptrPktData))
        i += 1
    pcap_close(handlePcapDev)
    return arrReceivedRawData

def reverseByte(xInputData): ## Will return input b'12345678' as b'78563412' and '12345678' as '78563412'
    if isinstance(xInputData, bytes): return b''.join([xInputData[x:x+2] for x in range(0,len(xInputData),2)][::-1])
    else: return ''.join([xInputData[x:x+2] for x in range(0,len(xInputData),2)][::-1])

def getLLCHeader(sDSAP = 'SNAP', sSSAP = 'SNAP', sControlField = '03', sOrgCode = '008063', sProtId = '01fd'): # 008063 == "Richard Hirschmann Gm"
    # DSAP = Dest Service Access Point: represents the logical addresses of the receiver(s), indicates individual or group addr
    # SSAP = Src Service Access Point: represents the logical addresses of the creator, indicates it is a command or response PDU (Protocol Data Unit)
    # ControlField = determines specific PDU and control functions, comes in three types, each with different formats:
    #       I = Information; 7 bit Sender Sequence Number + Receiver Sequence Number
    #       S = Supervisory; Receiver Ack Sequence Number and 2 bit S-field for RNR (Receiver Not Ready), RR (Reciever Ready) or REJ (Reject)
    #       U = Unnumbered; Generic Control, usually a 8-bit M-field to indicate type of PDU; sometimes 16bit
    # The rest is variable and is the User Data, e.g. Organizational Codes (24bit) and Protocol Id's (16bit)
    bData = b''
    bData += b'\xaa' if sDSAP == 'SNAP' else b'\x00'
    bData += b'\xaa' if sSSAP == 'SNAP' else b'\x00'
    bData += bytes.fromhex(sControlField)
    bData += bytes.fromhex(sOrgCode)
    bData += bytes.fromhex(sProtId)
    return bData

def getDevices(bNpfdevice, bPacket1, bPacket2, _iTimeout, sProtId):
    print('[*] Scanning for Devices')
    arrBytePacket1 = sendRawPacket(bNpfdevice, bPacket1)
    print('[+] Packet 1 has been sent ({} bytes)'.format(str(len(arrBytePacket1))))
    arrBytePacket2 = sendRawPacket(bNpfdevice, bPacket2)
    print('[+] Packet 2 has been sent ({} bytes)'.format(str(len(arrBytePacket2))))

    ## Receiving packets as bytearr (88cc == LDP, 8892 == device PN_DCP)
    print('\n[+] Receiving packets over {} seconds ...\n'.format(str(_iTimeout)))
    receivedDataArr = receiveRawPackets(bNpfdevice, _iTimeout, sProtId)
    print()
    print('\n[!] Saved {} responses'.format(str(len(receivedDataArr))))
    print()
    return receivedDataArr

def parseProduct(bData):
    return bData[8:].split(b'\x00')[0].decode(errors='none')

def parseData(bData):
    arrData = bData.split(b'\x00\x01')
    sIP = sNetmask = sGateway = ''
    bIP = arrData[-4][-14:-10]
    bNetmask = arrData[-4][-10:-6]
    bGateway = arrData[-4][-6:-2]
    sName = arrData[-3][:-2].decode(errors='none')
    for i in range (0, len(bIP)): sIP += str(int(bIP[i:i+1].hex(), 16)) + '.'
    if len(sIP) > 0: sIP = sIP[:-1]
    for i in range (0, len(bNetmask)): sNetmask += str(int(bNetmask[i:i+1].hex(), 16)) + '.'
    if len(sNetmask) > 0: sNetmask = sNetmask[:-1]
    for i in range (0, len(bGateway)): sGateway += str(int(bGateway[i:i+1].hex(), 16)) + '.'
    if len(sGateway) > 0: sGateway = sGateway[:-1]
    return sIP, sNetmask, sGateway, sName

def selectInterface():
    print('[!] Loading interfaces')
    arrInterfaces = getAllInterfaces()
    if len(getAllInterfaces()) > 1:
        for iNr, arrInterface in enumerate(arrInterfaces): 
            print('[{}] {} has {} ({})'.format(str(iNr + 1), arrInterface[2], arrInterface[1], arrInterface[0]))
        print('[Q] Quit now')
        sAnswer1 = input('Please select the adapter [1]: ')
        if sAnswer1 == 'q': sys.exit()
        if sAnswer1 == '' or not sAnswer1.isdigit() or int(sAnswer1) > len(arrInterfaces): sAnswer1 = 1
    else:
        sAnswer1 = 1

    ## Create vars
    sAdapter = arrInterfaces[int(sAnswer1) - 1][0]                  # eg: 'Ethernet 2'
    sMacaddr = arrInterfaces[int(sAnswer1) - 1][2].replace(':', '') # eg: 'ab58e0ff585a'
    sWinguid = arrInterfaces[int(sAnswer1) - 1][4]                  # eg: '{875F7EDB-CA23-435E-8E9E-DFC9E3314C55}'
    if os.name == 'nt': sAdapter = r'\Device\NPF_' + sWinguid
    bNpfdevice = sAdapter.encode()
    return bNpfdevice, sMacaddr

def buildDiscoveryPackets(sMacaddr):
    print('[+] Building packets')
    bDestMac = bytes.fromhex('0180632fff0a') ## RichardH
    bLLCHeader = getLLCHeader() ## LLC header

    bData1 = bLLCHeader + bytes.fromhex('0001000a02000007000000000000000000000000000000000000000000000000000000000000')
    bDataLen1 = bytes.fromhex(reverseByte(hex(len(bData1))[2:]).zfill(4))
    bPacket1 = bDestMac + bytes.fromhex(sMacaddr) + bDataLen1 + bData1

    bData2 = bLLCHeader + bytes.fromhex('0001000a05000407000700000000000000000000000000000000000000000000000000000000')
    bDataLen2 = bytes.fromhex(reverseByte(hex(len(bData2))[2:]).zfill(4))
    bPacket2 = bDestMac + bytes.fromhex(sMacaddr) + bDataLen2 + bData2
    return bPacket1, bPacket2

def parseResponses(arrResponses):
    arrDevices = []
    arrMac = []
    for arrDevice in arrResponses:
        bData = bytearray(arrDevice)
        dctDevice = {'mac':'', 'ip':'', 'netmask':'', 'gateway':'', 'name':'', 'product':''}
        sProduct = None
        sMac = bData[6:12].hex()
        bData = bData[22:]
        ## Hirschmann or LANCOM Systems GmbH, Wuerselen are in the product packet
        #if bData[-10:] == b'Hirschmann' or bData[-10:] == b' Wuerselen': sProduct = parseProduct(bData)
        if b'Hirschmann'in bData or b'LANCOM' in bData: sProduct = parseProduct(bData)
        else: sIP, sNetmask, sDGW, sName = parseData(bData)
        
        if sMac not in arrMac: 
            # New device
            arrMac.append(sMac)
            dctDevice['mac'] = sMac
            if sProduct: dctDevice['product'] = sProduct
            elif sName: 
                dctDevice['ip'] = sIP
                dctDevice['netmask'] = sNetmask
                dctDevice['gateway'] = sDGW
                dctDevice['name'] = sName
            arrDevices.append(dctDevice)
        else:
            # Device exists, edit
            for i in range(len(arrDevices)):
                if arrDevices[i]['mac'] == sMac:
                    if sProduct: arrDevices[i]['product'] = sProduct
                    elif sName: 
                        arrDevices[i]['ip'] = sIP
                        arrDevices[i]['netmask'] = sNetmask
                        arrDevices[i]['gateway'] = sDGW
                        arrDevices[i]['name'] = sName

    if(len(arrDevices) == 0): exit()
    return arrDevices

def signalDevice(dctDevice, bNpfdevice, sSrcMacaddr):
    ## Building the packet
    bDestMac = bytes.fromhex(dctDevice['mac'])
    bLLCHeader = getLLCHeader()
    sData = '0001' # UNK
    sData += '0008' # Full datalength in bytes
    sData += '0600' # Length of instruction
    sData += '0001' # Instruction "FLASH"
    bData = bytes.fromhex(sData)
    bDataLen1 = bytes.fromhex(reverseByte(hex(len(bLLCHeader + bData))[2:]).zfill(4))
    bPacket = bDestMac + bytes.fromhex(sSrcMacaddr) + bDataLen1 + bLLCHeader + bData

    ## Sending, the device will flash for about 3 seconds for each send packet
    print("\n"+'[!] Signaling device for about 6 seconds {}, ({}, {}) --###'.format(dctDevice['name'], dctDevice['product'], dctDevice['ip']))
    sendRawPacket(bNpfdevice, bPacket)
    time.sleep(3)
    sendRawPacket(bNpfdevice, bPacket)
    time.sleep(3)
    return

def editDevice(dctDevice, bNpfdevice, sSrcMacaddr):
    def sendAndReceiveEditDevice(bNpfdevice, bData):
        sendRawPacket(bNpfdevice, bData)
        bResponse = receiveRawPackets(bNpfdevice, _iTimeout, '01fd', stopOnResponse=True)
        bResponse = bytearray(bResponse[0][14+8:])
        if not bResponse[4:4+4].hex() == '04010007': 
            print('[-] Received invalid response')
            return
        if bResponse[8:8+2].hex() == '0000': print('[+] Success, device is changed')
        else: print('[-] Failed, error code: {}'.format(bResponse[8:8+4].hex()))
        return
    print("\n Editing device {}, ({}, {}, DGW: {})".format(dctDevice['name'], dctDevice['ip'], dctDevice['netmask'], dctDevice['gateway']))
    ## Getting the goods
    sName = input('Please enter the new Name [{}] : '.format(dctDevice['name']))
    if sName == '': sName = dctDevice['name']
    sIP = input('Please enter the new IP address [{}] : '.format(dctDevice['ip']))
    if sIP == '': sIP = dctDevice['ip']
    sSNM = input('Please enter the new Netmask [{}] : '.format(dctDevice['netmask']))
    if sSNM == '': sSNM = dctDevice['netmask']
    sDGW = input('Please enter the new Gateway [{}] : '.format(dctDevice['gateway']))
    if sDGW == '': sDGW = dctDevice['gateway']
    sNewName = ''.join([hex(ord(x))[2:].zfill(2) for x in sName])
    sNewIP = ''.join([hex(int(x))[2:].zfill(2) for x in sIP.split('.')])
    sNewSNM = ''.join([hex(int(x))[2:].zfill(2) for x in sSNM.split('.')])
    sNewDGW = ''.join([hex(int(x))[2:].zfill(2) for x in sDGW.split('.')])

    ## Building the packet
    sData = '0001' # UNK
    sData += hex(len(sName) + 30)[2:].zfill(4) # Full datalength in bytes (which is 31bytes + name length)
    sData += '0400' # Length of instruction
    sData += '00071202' # Instruction "change properties"
    sData += '00010000' # UNK
    sData += sNewIP
    sData += sNewSNM
    sData += sNewDGW
    sData += hex(len(sName) + 4)[2:].zfill(2) # Remaining datalength
    sData += '060001' # UNK
    sData += sNewName
    bData = bytes.fromhex(sData)

    bDestMac = bytes.fromhex(dctDevice['mac'])
    bLLCHeader = getLLCHeader()
    bDataLen1 = bytes.fromhex(reverseByte(hex(len(bLLCHeader + bData))[2:]).zfill(4))
    bPacket = bDestMac + bytes.fromhex(sSrcMacaddr) + bDataLen1 + bLLCHeader + bData

    ## Sending
    print("\n"+'[!] Editing device {}, ({}, {}) --###'.format(dctDevice['name'], dctDevice['product'], dctDevice['ip']))
    sendAndReceiveEditDevice(bNpfdevice, bPacket)
    return

### MAIN ###
print('''
[*****************************************************************************]
                   This script works on both Linux and Windows
                   
                           --- Hirschmann Scanner ---
    It will perform a Layer2 discovery scan (LLC) for Hirschmann devices,
                            then list their info
                Note: it takes 2 distinct packages to get all the info                        

______________________/-> Created By Tijl Deneut(c) <-\_______________________
[*****************************************************************************]''')
## Select Adapter, IP does not have to be in the same subnet
bNpfdevice, sSrcMacaddr = selectInterface()

## Get Raw Data
## Start building discovery packets
bPacket1, bPacket2 = buildDiscoveryPackets(sSrcMacaddr)

## Send both packets and receive
arrResponses = getDevices(bNpfdevice, bPacket1, bPacket2, _iTimeout, '01fd') ## 01fd to identify responses

## Parse list
arrDevices = parseResponses(arrResponses)

## Show devices
print('      ###--- DEVICELIST ---###')
print('    #Name#, #Product# (#IP#, #Subnetmask#, #Gateway#)')
i = 1
for dctDevice in arrDevices:
    sToPrint = '[{}] {}, {} ({}, {}, {})'.format(i, dctDevice['name'], dctDevice['product'], dctDevice['ip'], dctDevice['netmask'], dctDevice['gateway'])
    print(sToPrint)
    i += 1
print('[Q] Quit now')
sAnswer = input('Please select the device [1]: ')
if sAnswer.lower() == 'q': exit()
if sAnswer == '' or not sAnswer.isdigit() or int(sAnswer)>=i: sAnswer=1
dctDevice = arrDevices[int(sAnswer)-1]
print("\n"+'###-- Working with device {}, ({}, {}) --###'.format(dctDevice['name'], dctDevice['product'], dctDevice['ip']))
print('[?] What to do?')
print('[F] Flash the led (signaling)')
print('[E] Edit the network settings')
print('[Q] Quit now')
sAnswer2 = input('Please select what you want to do [Q]: ').lower()
if sAnswer2 == '': sAnswer2 = 'q'
if sAnswer2 == 'q': exit()
elif sAnswer2 == 'f': signalDevice(dctDevice, bNpfdevice, sSrcMacaddr)
elif sAnswer2 == 'e': editDevice(dctDevice, bNpfdevice, sSrcMacaddr)
