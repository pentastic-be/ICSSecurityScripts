#!/usr/bin/env python3
from scapy.all import *
import socket
import binascii
from collections import defaultdict

DEST_MAC = "01:80:63:2f:ff:0a"

DISCOVERY_GENERAL = bytes.fromhex("0001000a020000070000")
DISCOVERY_MODEL   = bytes.fromhex("0001000a050004070007")

HIRSCHMANN_OUI = 0x008063
HIRSCHMANN_PID = 0x01FD

devices = defaultdict(dict)


# -------------------------------------------------
# Interface selection
# -------------------------------------------------

def choose_interface():
    interfaces = get_if_list()

    print("\nAvailable interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")

    idx = int(input("\nSelect interface number: "))
    return interfaces[idx]


# -------------------------------------------------
# Build frame
# -------------------------------------------------

def build_frame(iface, payload):
    src_mac = get_if_hwaddr(iface)
    length = 3 + 5 + len(payload)

    return (
        Dot3(dst=DEST_MAC, src=src_mac, len=length)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        / SNAP(OUI=HIRSCHMANN_OUI, code=HIRSCHMANN_PID)
        / Raw(load=payload)
    )


# -------------------------------------------------
# Block parser
# -------------------------------------------------

def parse_payload(src_mac, data):

    # Frame 1 (general info)
    if data[2:4] == b"\x00\x38":

        # MAC (fixed offset)
        mac = ":".join(f"{b:02x}" for b in data[12:18])
        devices[src_mac]["mac"] = mac

        # IP block
        ip = socket.inet_ntoa(data[24:28])
        mask = socket.inet_ntoa(data[28:32])
        gw = socket.inet_ntoa(data[32:36])

        devices[src_mac]["ip"] = ip
        devices[src_mac]["netmask"] = mask
        devices[src_mac]["gateway"] = gw

        # Hostname (find ASCII after 0d06 0001)
        idx = data.find(b"\x0d\x06\x00\x01")
        if idx != -1:
            hostname = data[idx+4:].split(b"\x00")[0].decode(errors="ignore")
            devices[src_mac]["hostname"] = hostname

    # Frame 2 (model info)
    elif data[2:4] == b"\x00\x2c":

        # find 0501 block
        idx = data.find(b"\x05\x01")
        if idx != -1:
            length = data[idx+2]
            model = data[idx+3:idx+3+length].decode(errors="ignore")
            devices[src_mac]["model"] = model


# -------------------------------------------------
# Response handler
# -------------------------------------------------

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


# -------------------------------------------------
# Print result
# -------------------------------------------------

def print_devices():
    print("\n\n===== Discovery Result =====")

    for mac, info in devices.items():
        print("\n---------------------------------")
        print(f"Source MAC : {mac}")
        print(f"Hostname   : {info.get('hostname', 'N/A')}")
        print(f"Model      : {info.get('model', 'N/A')}")
        print(f"IP         : {info.get('ip', 'N/A')}")
        print(f"Netmask    : {info.get('netmask', 'N/A')}")
        print(f"Gateway    : {info.get('gateway', 'N/A')}")
        print("---------------------------------")


# -------------------------------------------------
# Main
# -------------------------------------------------

def main():
    iface = choose_interface()

    print(f"\nSending Hirschmann discovery on {iface}...\n")

    sendp(build_frame(iface, DISCOVERY_GENERAL), iface=iface, verbose=False)
    sendp(build_frame(iface, DISCOVERY_MODEL), iface=iface, verbose=False)

    sniff(
        iface=iface,
        timeout=5,
        prn=handle_response,
        store=False
    )

    print_devices()


if __name__ == "__main__":
    main()


