#! /usr/bin/env python3
r'''
    Copyright 2026 Photubias(c)

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

    File name omronScan.py
    written by Photubias
    Modified by Pentastic with link local functionality when ip is unknown
    
    This script uses UDP for discovery, but TCP for data transfer
'''
import socket, os, subprocess, hashlib, time, datetime, random, atexit

iDPort = 9600
iResponsePort = 1506
iTimeout = 2
iBuffer = 4096

# ------------------------
# LINK‑LOCAL SUPPORT
# ------------------------

_linklocal_ip = None
_linklocal_nic = None

def _gen_linklocal():
    """Generate a random link‑local 169.254.x.x address"""
    return f"169.254.{random.randint(1,254)}.{random.randint(1,254)}"

def _assign_linklocal(nic):
    """Try assigning a random link‑local address to the NIC"""
    global _linklocal_ip, _linklocal_nic
    for _ in range(20):
        ip = _gen_linklocal()
        try:
            subprocess.check_call(f"sudo ip addr add {ip}/16 dev {nic}", shell=True)
            _linklocal_ip = ip
            _linklocal_nic = nic
            return ip
        except subprocess.CalledProcessError:
            continue
    return None

def _remove_linklocal():
    """Cleanup the link‑local IP on exit"""
    global _linklocal_ip, _linklocal_nic
    if _linklocal_ip and _linklocal_nic:
        subprocess.call(f"sudo ip addr del {_linklocal_ip}/16 dev {_linklocal_nic}", shell=True)

atexit.register(_remove_linklocal)

# ------------------------
# ORIGINAL SCRIPT FUNCTIONS
# ------------------------

def getLocalInterfaces():
    interfaces=[]
    if os.name == 'nt':
        proc=subprocess.Popen(r'ipconfig | FINDSTR "IPv4 Address Subnet" | FINDSTR /V "IPv6"',shell=True,stdout=subprocess.PIPE)
        allines=proc.stdout.readlines()
        for i in range(0,len(allines),2):
            ip = allines[i].split(b':')[1].rstrip().lstrip()
            mask = allines[i+1].split(b':')[1].rstrip().lstrip()
            interfaces.append((ip.decode(),mask.decode()))
    else:
        proc=subprocess.Popen(r'ip address | grep inet | grep -v "127.0.0.1" | grep -v "inet6"', shell=True, stdout=subprocess.PIPE)
        for interface in proc.stdout.readlines():
            int_parts = interface.lstrip().split(b' ')
            ip = int_parts[1].split(b'/')[0]
            cidr = int(int_parts[1].split(b'/')[1])
            bcidr = (cidr*'1'+(32-cidr)*'0')
            mask = str(int(bcidr[:8],2)) + '.' + str(int(bcidr[8:16],2)) + '.' + str(int(bcidr[16:24],2)) + '.' + str(int(bcidr[24:],2))
            intname = int_parts[len(int_parts)-1].rstrip().decode()
            interfaces.append((ip.decode(),mask,intname))
    return interfaces

def scanNetwork(lstAdapter, iDPort, iSPort):
    oSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    oSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    oSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    oSock.settimeout(iTimeout)
    oSock.bind((lstAdapter[0], iSPort))

    if not os.name == 'nt':
        bSrcDev = lstAdapter[2]
        if isinstance(bSrcDev, str):
            bSrcDev = bSrcDev.encode()
        oSock.setsockopt(socket.SOL_SOCKET, 25, bSrcDev)

    print('Sending the discovery packets and waiting ' + str(iTimeout) + ' seconds for answers...')
    sendOnly(oSock, '169.254.255.255', iDPort, bytes.fromhex('80000700fffe008500012768'))

    lstReceivedData = []
    while True:
        try: lstReceivedData.append(recvOnly(oSock))
        except: break
    return lstReceivedData

def sendOnly(oSock, sIP, iPort, bData):
    oSock.sendto(bData, (sIP, iPort))

def recvOnly(oSock):
    bResponse, tAddr = oSock.recvfrom(iBuffer)
    return bResponse, tAddr

def sendAndRecv(oSock, sIP, iPort, bData):
    sendOnly(oSock, sIP, iPort, bData)
    return recvOnly(oSock)[0]

def sendAndRecvTCP(oSock, bData):
    oSock.send(bData)
    return oSock.recv(iBuffer)

def parseData(bResp):
    def fromhex(bByte): return hex(bByte)[2:].zfill(2)
    ip = netmask = mac = token = serial = pcode = ''
    ip = '.'.join((str(bResp[23]), str(bResp[22]), str(bResp[21]), str(bResp[20])))
    netmask = '.'.join((str(bResp[27]), str(bResp[26]), str(bResp[25]), str(bResp[24])))
    mac = ':'.join((fromhex(bResp[32]), fromhex(bResp[33]), fromhex(bResp[34]), fromhex(bResp[35]), fromhex(bResp[36]), fromhex(bResp[37])))
    token = bResp[16:20].hex()
    pcode = str(bResp[16])
    serialp1 = str(bResp[19])
    serialp2 = str(int(int((bResp[18:19] + bResp[17:18]).hex(),16)/1000))
    serialp3 = bResp[17]
    if int((bResp[18:19] + bResp[17:18]).hex(), 16) % 1000  >= 500: serialp3 += 0x100
    serialp4 = bResp[16]
    serial = '{}{}-{}-{}'.format(serialp1,serialp2,str(serialp3).zfill(4),serialp4)
    return ip, netmask, mac, token, serial, pcode

def toHex(iData, iLength):
    return hex(iData)[2:].zfill(iLength)

def intFromHex(bData):
    return int(bData,16)

def getServerNodeAddress(oSock, sIP, iDPort):
    bHeader = b'FINS'
    bDataToSend = b'\x00'*4 + b'\x00'*4 + b'\x00'*4
    bRequestAddress = bHeader + bytes.fromhex(toHex(len(bDataToSend),8)) + bDataToSend
    bResp = sendAndRecvTCP(oSock, bRequestAddress)
    if bResp[:4] != b'FINS':
        print('[-] Error: TCP/{} is not a (real) Omron device, full answer:\n{}'.format(iDPort, bResp))
        return False
    bData = bResp[8:]
    bCommand, bError, bClientNodeAddress, bServerNodeAddress = bData[:4], bData[4:8], bData[8:12], bData[12:16]
    return bServerNodeAddress

def createFINSHeader(bCommand, bServerNodeAddress):
    bDataToSend = b'\x00\x00\x00\x02' + b'\x00'*4
    bDataToSend += b'\x80' + b'\x00' + b'\x02'
    bDataToSend += b'\x00' + bServerNodeAddress[3:] + b'\x00' + b'\x00' + b'\x00' + b'\xef' + b'\x05' + bCommand
    return bDataToSend

def verifyResponse(bResponseData):
    if bResponseData[:4] != b'FINS':
        print('[-] Error: TCP/{} is not a (real) Omron device, full answer:\n{}'.format(iDPort, bResponseData))
        return False
    bData = bResponseData[16+12:]
    bResponseCode = bData[:2]
    if bResponseCode == b'\x21\x08': print('[-] Response Code: Data cannot be changed (0x2108)')
    elif bResponseCode == b'\x22\x01': print('[-] Response Code: The mode is wrong (executing) (0x2201)"')
    elif bResponseCode == b'\x10\x04': print('[-] Response Code: Format Error, Command not recognized (0x1104)"')
    elif bResponseCode == b'\x11\x06': print('[-] Response Code: Program Missing (0x1106)')
    elif bResponseCode == b'\x11\x01': print('[-] Response Code: Parameter error: Area Classification missing (0x1101)')
    elif bResponseCode != b'\x00\x00': print('[-] Response Code: Unknown Error (0x{})'.format(bResponseCode.hex()))
    if bResponseCode == b'\x00\x00': return True
    else: return False

def readControllerStatus(sIP, iDPort):
    dctMode = {0:'DEBUG',2:'MONITOR',4:'RUN'}
    oSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    oSock.settimeout(iTimeout)
    oSock.connect((sIP, iDPort))
    bServerNodeAddress = getServerNodeAddress(oSock, sIP, iDPort)
    if not bServerNodeAddress: return
    bCommandCode = b'\x06\x01'
    bDataToSend = createFINSHeader(bCommandCode, bServerNodeAddress)
    bPacket = b'FINS' + bytes.fromhex(toHex(len(bDataToSend),8)) + bDataToSend
    bResp = sendAndRecvTCP(oSock, bPacket)
    if not verifyResponse(bResp): return
    bData = bResp[16+12+2:]
    bStatusFlags = bData[:1]
    bMode = bData[1:1+1]
    bFatalErrorDataFlags = bData[2:2+2]
    bNonFatalErrorDataFlags = bData[4:4+2]
    bMessageFlags = bData[6:6+2]
    bErrorCode = bData[8:8+2]
    sMessage = bData[10:].decode().strip()
    sStatus = ''.join(format(byte, '08b') for byte in bStatusFlags)
    sCPUStatus = 'Normal' if sStatus[0] == '0' else 'Standby'
    sBattery = 'No Battery' if sStatus[5] == '0' else 'Present'
    sFlashMemAccess = 'Not Writing' if sStatus[6] == '0' else 'Writing'
    sProgramStatus = 'Stop; User program stopped' if sStatus[7] == '0' else 'Run; User program executed'
    sProgramMode = dctMode[int(bMode.hex(),16)]
    print(f'    CPU Status:              {sCPUStatus}')
    print(f'    Program Status:          {sProgramStatus}')
    print(f'    Battery Status:          {sBattery}')
    print(f'    Flash Memory Access:     {sFlashMemAccess}')
    print(f'    Current Mode:            {sProgramMode}')
    if bFatalErrorDataFlags != b'\x00\x00': print(f'    Some Error Flags found:  {bFatalErrorDataFlags.hex()}')
    if sMessage: print(f'    Message was returned:    {sMessage}')
    return sProgramMode

def setProgramMode(sMode,sIP,iDPort):
    bCommandCode = b'\x04\x01'
    bProgramNumber = b'\xff\xff'
    dctMode = {'PROGRAM':1,'MONITOR':2,'RUN':4}
    if not sMode in dctMode:
        print(f'[-] Mode {sMode} does not exist')
        return
    print(f'[+] Sending command to change mode to {sMode}')
    oSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    oSock.settimeout(iTimeout)
    oSock.connect((sIP, iDPort))
    bServerNodeAddress = getServerNodeAddress(oSock, sIP, iDPort)
    if not bServerNodeAddress: return
    bDataToSend = createFINSHeader(bCommandCode, bServerNodeAddress) + bProgramNumber + dctMode[sMode].to_bytes(1, 'big')
    bPacket = b'FINS' + bytes.fromhex(toHex(len(bDataToSend),8)) + bDataToSend
    bResp = sendAndRecvTCP(oSock, bPacket)
    if not verifyResponse(bResp): return
    print(f'[+] Mode successfully changed to {sMode}')
    return

def stopCPU(sIP,iDPort):
    bCommandCode = b'\x04\x02'
    print(f'[+] Sending STOP command')
    oSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    oSock.settimeout(iTimeout)
    oSock.connect((sIP, iDPort))
    bServerNodeAddress = getServerNodeAddress(oSock, sIP, iDPort)
    if not bServerNodeAddress: return
    bDataToSend = createFINSHeader(bCommandCode, bServerNodeAddress)
    bPacket = b'FINS' + bytes.fromhex(toHex(len(bDataToSend),8)) + bDataToSend
    bResp = sendAndRecvTCP(oSock, bPacket)
    if not verifyResponse(bResp): return
    print(f'[+] Stop successfully executed')
    input('    Press [Enter] to return to the menu')
    return

def readControllerData(sIP, iDPort):
    dctMemCard = {0:'No Mem Card',1:'SPRAM',2:'EPROM',3:'EEPROM'}
    oSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    oSock.settimeout(iTimeout)
    oSock.connect((sIP, iDPort))
    bServerNodeAddress = getServerNodeAddress(oSock, sIP, iDPort)
    if not bServerNodeAddress: return
    bCommandCode = b'\x05\x01'
    bDataToSend = createFINSHeader(bCommandCode, bServerNodeAddress)
    bDataToSend += b'\x00'
    bPacket = b'FINS' + bytes.fromhex(toHex(len(bDataToSend),8)) + bDataToSend
    bResp = sendAndRecvTCP(oSock, bPacket)
    if not verifyResponse(bResp): return
    bData = bResp[16+12:]
    bControllerModel, bControllerVersion, bSystemUse, bAreaData = bData[2:2+20], bData[22:22+20], bData[42:42+40], bData[82:]
    sControllerModel = bControllerModel.split(b'\x00')[0].decode()
    sControllerVersion = bControllerVersion.split(b'\x00')[0].decode()
    sSystemUse = bSystemUse.split(b'\x00')[0].decode()
    if sSystemUse: print(f'    System Use: {sSystemUse}')
    iProgramAreaSize = int(bAreaData[:2].hex(),16)
    iIOMSize = int(bAreaData[2:2+1].hex(),16)
    iNoDMWords = int(bAreaData[3:3+2].hex(),16)
    iTimerCounterSize = int(bAreaData[5:5+1].hex(),16)
    iExpansionDMSize = int(bAreaData[6:6+1].hex(),16)
    iNoOfSteps = int(bAreaData[7:7+2].hex(),16)
    iMemCardType = int(bAreaData[9:9+1].hex(),16)
    iMemCardSize = int(bAreaData[10:10+2].hex(),16)
    print('[+] Response Code: Normal completion (0x0000)')
    print(f'    Controller Model:        {sControllerModel}')
    print(f'    Controller Version:      {sControllerVersion}')
    print(f'    Program Area Size:       {iProgramAreaSize}')
    print(f'    IOM Size:                {iIOMSize}')
    print(f'    No of DM Words:          {iNoDMWords}')
    print(f'    Timer/Counter Size:      {iTimerCounterSize}')
    print(f'    Expansion DM Size:       {iExpansionDMSize}')
    print(f'    No of Steps/Transitions: {iNoOfSteps}')
    if iMemCardType in dctMemCard:
        print(f'    Memory Card:             {dctMemCard[iMemCardType]}')
        if not iMemCardType == 0: print(f'    Memory Card Size:        {iMemCardSize}')
    else: print(f'    Memory Card:             Unknown type of Mem Card ({iMemCardType})')
    input('Press [Enter] to return to the menu')
    return

def getProgramViaTCP(sIP, iDPort, sFilename):
    sFilename = sFilename+datetime.datetime.now().strftime('%Y%m%d-%M%H%S')+'.bin'
    bCommandCode = b'\x03\x06'
    bProgramNumber = b'\xff\xff'
    iBufferSize = 512
    iOffsetWord = 0
    print(f'[+] Attempting to read program from {sIP} via TCP/{iDPort}')
    oSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    oSock.settimeout(iTimeout)
    oSock.connect((sIP, iDPort))
    bServerNodeAddress = getServerNodeAddress(oSock, sIP, iDPort)
    if not bServerNodeAddress: return
    boolDone = False
    bProgramData = b''
    while not boolDone:
        bDataToSend = createFINSHeader(bCommandCode, bServerNodeAddress) + bProgramNumber + iOffsetWord.to_bytes(4, 'big') + iBufferSize.to_bytes(2, 'big')
        bPacket = b'FINS' + bytes.fromhex(toHex(len(bDataToSend),8)) + bDataToSend
        bResp = sendAndRecvTCP(oSock, bPacket)
        if bProgramData == b'' and not verifyResponse(bResp): return
        try: boolDone = bResp[10]>=0x80
        except: boolDone = True
        bData = bResp[12:]
        bProgramData += bData
        iOffsetWord += iBufferSize

    oHash = hashlib.md5()
    oHash.update(bProgramData)
    open(sFilename,'wb').write(bProgramData)
    print(f'[+] Written file {sFilename}, size {len(bProgramData)} bytes, MD5 checksum: {oHash.hexdigest()}')
    input('    Press [Enter] to return to the menu')
    return

def readFilenames(sIP, iDPort):
    bCommandCode = b'\x22\x01'
    bDiskNr = b'\x80\x00'
    iFilePosition = 0
    iNrOfFiles = 1
    iDirectoryLength = 0
    bAbsoluteDirPath = b''
    print(f'[+] Attempting to read a filename from {sIP} via TCP/{iDPort}')
    oSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    oSock.settimeout(iTimeout)
    oSock.connect((sIP, iDPort))
    bServerNodeAddress = getServerNodeAddress(oSock, sIP, iDPort)
    if not bServerNodeAddress: return
    bDataToSend = createFINSHeader(bCommandCode, bServerNodeAddress) + bDiskNr + iFilePosition.to_bytes(2, 'big') + iNrOfFiles.to_bytes(2, 'big') + iDirectoryLength.to_bytes(2, 'big') + bAbsoluteDirPath
    bPacket = b'FINS' + bytes.fromhex(toHex(len(bDataToSend),8)) + bDataToSend
    bResp = sendAndRecvTCP(oSock, bPacket)
    print(bResp)
    if not verifyResponse(bResp): return
    return

def manageController(sIP, iDPort):
    while True:
        sMode = readControllerStatus(sIP, iDPort)
        sAns = input('[?] Set specific state or invert the mode? [s/i/Q] : ').lower()
        if sAns == 's':
            sAns2 = input(' [?] Select state: Program, Monitor or Run? [p/m/r/Q] : ').lower()
            if sAns2 == 'p': setProgramMode('PROGRAM',sIP,iDPort)
            elif sAns2 == 'm': setProgramMode('MONITOR',sIP,iDPort)
            elif sAns2 == 'r': setProgramMode('RUN',sIP,iDPort)
        elif sAns == 'i':
            if sMode != 'RUN': setProgramMode('RUN',sIP,iDPort)
            elif sMode == 'RUN': setProgramMode('MONITOR',sIP,iDPort)
        else: break
        print('   Refreshing in 3 seconds')
        time.sleep(3)
    return

def parseDiscovery(bData):
    sType = bData[34:47].decode()
    sVers = bData[54:59].decode()
    sBuild = bData[59:].strip(b'\x00').decode()
    return sType, sVers, sBuild

def main():
    i=1
    arrInterfaces = getLocalInterfaces()
    for interface in arrInterfaces:
        print((f'[{i}] {interface[0]} / {interface[1]} / {interface[2] if len(interface)>2 else "N/A"}'))
        i+=1
    print('[Q] Quit now')

    if i>2: answer=input('Select NIC to auto-configure link-local [1]: ')
    else: answer=str(i-1)
    if answer.lower()=='q': exit()
    if answer=='' or not answer.isdigit() or int(answer)>=i: answer=1

    selected = arrInterfaces[int(answer)-1]
    nic_name = selected[2] if len(selected)>2 else None
    if not nic_name:
        print('[-] Cannot assign link-local: NIC not found')
        exit()
    print(f'[+] Assigning link-local IP on {nic_name}...')
    linklocal_ip = _assign_linklocal(nic_name)
    if not linklocal_ip:
        print('[-] Failed to assign link-local IP')
        exit()
    print(f'[+] Assigned link-local IP: {linklocal_ip}')

    receivedData = scanNetwork((linklocal_ip, '255.255.0.0', nic_name), iDPort, iResponsePort)
    print(f'Got {len(receivedData)} response(s):')
    lstDevices = []
    os.system('cls' if os.name == 'nt' else 'clear')
    print('      ###--- DEVICELIST ---###')
    print('    #IP#, #Type# (#Version#, #Build#)')
    i = 1
    for lstData in receivedData:
        bData,lstIP = lstData
        sType, sVers, sBuild = parseDiscovery(bData)
        lstDevices.append({'IP':lstIP[0],'TYPE':sType,'VERS':sVers,'BUILD':sBuild})
        sToPrint = '[{}] {}, {} ({}, {})'.format(i, sType, lstIP[0], sVers, sBuild)
        print(sToPrint)
        i+=1
    print('[Q] Quit now')
    sAnswer = input('Please select the device [1]: ')
    if sAnswer.lower() == 'q': exit()
    if sAnswer == '' or not sAnswer.isdigit() or int(sAnswer)>=i: sAnswer=1
    dctDev = lstDevices[int(sAnswer)-1]
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('\n###-- Working with device {}, ({}, {}) --###'.format(dctDev['TYPE'], dctDev['VERS'], dctDev['IP']))
        print('[?] What to do (TCP)?')
        print('[L] List information and change CPU status (RUN Mode)')
        print('[R] Read more detailed information')
        print('[U] Receive (Upload) Program from PLC')
        print('[S] Stop PLC CPU')
        print('[Q] Quit now')
        sAnswer2 = input('Please select what you want to do [Q]: ').lower()
        if sAnswer2 == '': sAnswer2 = 'q'
        if sAnswer2 == 'q': exit()
        elif sAnswer2 == 'l': manageController(dctDev['IP'], iDPort)
        elif sAnswer2 == 'r': readControllerData(dctDev['IP'], iDPort)
        elif sAnswer2 == 'u': getProgramViaTCP(dctDev['IP'], iDPort, 'PLCProgram')
        elif sAnswer2 == 's': stopCPU(dctDev['IP'],iDPort)
    return

if __name__ == '__main__':
    main()
    exit(0)
                    
