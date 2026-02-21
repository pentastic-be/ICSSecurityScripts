#!/usr/bin/env python3
from scapy.all import *
import socket
import binascii
from collections import defaultdict
import subprocess

DEST_MAC = "01:80:63:2f:ff:0a"

# Hirschmann discovery frames
DISCOVERY_GENERAL = bytes.fromhex("0001000a020000070000")
DISCOVERY_MODEL   = bytes.fromhex("0001000a050004070007")

HIRSCHMANN_OUI = 0x008063
HIRSCHMANN_PID = 0x01FD

devices = defaultdict(dict)

# -------------------------------
# Interface selection
# -------------------------------
def choose_interface():
    interfaces = get_if_list()
    print("\nAvailable interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    idx = int(input("\nSelect interface number: "))
    return interfaces[idx]

# -------------------------------
# Build discovery frame
# -------------------------------
def build_frame(iface, payload):
    src_mac = get_if_hwaddr(iface)
    length = 3 + 5 + len(payload)
    return (
        Dot3(dst=DEST_MAC, src=src_mac, len=length)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        / SNAP(OUI=HIRSCHMANN_OUI, code=HIRSCHMANN_PID)
        / Raw(load=payload)
    )

# -------------------------------
# Parse Hirschmann response payload
# -------------------------------
def parse_payload(src_mac, data):
    # Frame 1: general info (hostname, IP, MAC)
    if data[2:4] == b"\x00\x38":
        mac = ":".join(f"{b:02x}" for b in data[12:18])
        devices[src_mac]["mac"] = mac
        ip = socket.inet_ntoa(data[24:28])
        mask = socket.inet_ntoa(data[28:32])
        gw = socket.inet_ntoa(data[32:36])
        devices[src_mac]["ip"] = ip
        devices[src_mac]["netmask"] = mask
        devices[src_mac]["gateway"] = gw
        idx = data.find(b"\x0d\x06\x00\x01")
        if idx != -1:
            hostname = data[idx+4:].split(b"\x00")[0].decode(errors="ignore")
            devices[src_mac]["hostname"] = hostname

    # Frame 2: model info
    elif data[2:4] == b"\x00\x2c":
        idx = data.find(b"\x05\x01")
        if idx != -1:
            length = data[idx+2]
            model = data[idx+3:idx+3+length].decode(errors="ignore")
            devices[src_mac]["model"] = model

# -------------------------------
# Handle sniffed Hirschmann frame
# -------------------------------
def handle_response(pkt):
    if not pkt.haslayer(SNAP):
        return
    snap = pkt[SNAP]
    if snap.OUI != HIRSCHMANN_OUI or snap.code != HIRSCHMANN_PID:
        return
    if not pkt.haslayer(Raw):
        return
    src_mac = pkt.src
    raw_data = bytes(pkt[Raw].load)
    print(f"\nReceived Hirschmann frame from {src_mac}")
    print("Raw:", binascii.hexlify(raw_data).decode())
    parse_payload(src_mac, raw_data)

# -------------------------------
# SNMP check using OS snmpget
# -------------------------------
def check_snmp_os(ip, community):
    try:
        cmd = [
            "snmpget",
            "-v2c",
            "-c", community,
            "-Oqv",
            "-t", "1",
            "-r", "0",
            ip,
            "1.3.6.1.2.1.1.1.0"  # sysDescr
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return True
    except FileNotFoundError:
        print("snmpget command not found. Please install net-snmp.")
    except Exception as e:
        print(f"SNMP check error for {ip} community {community}: {e}")
    return False

# -------------------------------
# Print discovery results
# -------------------------------
def print_devices():
    print("\n\n===== Discovery Result =====")
    for mac, info in devices.items():
        print("\n---------------------------------")
        print(f"Source MAC     : {mac}")
        print(f"Hostname       : {info.get('hostname', 'N/A')}")
        print(f"Model          : {info.get('model', 'N/A')}")
        print(f"IP             : {info.get('ip', 'N/A')}")
        print(f"Netmask        : {info.get('netmask', 'N/A')}")
        print(f"Gateway        : {info.get('gateway', 'N/A')}")
        print(f"SNMP public    : {info.get('snmp_public', False)}")
        print(f"SNMP private   : {info.get('snmp_private', False)}")
        print("---------------------------------")

# -------------------------------
# Main
# -------------------------------
def main():
    iface = choose_interface()
    print(f"\nSending Hirschmann discovery on {iface}...\n")

    # Send both discovery frames
    sendp(build_frame(iface, DISCOVERY_GENERAL), iface=iface, verbose=False)
    sendp(build_frame(iface, DISCOVERY_MODEL), iface=iface, verbose=False)

    # Capture responses for 5 seconds
    sniff(iface=iface, timeout=5, prn=handle_response, store=False)

    # Perform SNMP checks using OS snmpget
    print("\nChecking SNMP communities on discovered devices...")
    for mac, info in devices.items():
        ip = info.get("ip")
        if not ip:
            print(f"No IP found for device {mac}, skipping SNMP check")
            continue
        print(f"\nChecking device {mac} at IP {ip} for SNMP...")
        info["snmp_public"] = check_snmp_os(ip, "public")
        info["snmp_private"] = check_snmp_os(ip, "private")

    print_devices()

if __name__ == "__main__":
    main()

