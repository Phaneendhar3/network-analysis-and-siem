import subprocess
import re
import ipaddress
import socket
from typing import List,Dict

def get_active_ip() -> str:
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8",80))
        return s.getsockname()[0]
    finally:
        s.close()

def detect_network() -> str:
    active_ip=get_active_ip()
    result=subprocess.run(
        ["ipconfig"],
        capture_output=True,
        text=True
    )
    ip=None
    mask=None
    found=False
    for line in result.stdout.splitlines():
        line=line.strip()
        if "IPv4 Address" in line and active_ip in line:
            ip=active_ip
            found=True
        if found and "Subnet Mask" in line:
            mask=line.split(":")[-1].strip()
            break
    if not ip or not mask:
        raise RuntimeError("Unable to detect local network")
    # network=ipaddress.IPv4Network(f"{ip}/{mask}",strict=False)
    # return str(network)
    real_network=ipaddress.IPv4Network(f"{ip}/{mask}",strict=False)
    if real_network.prefixlen<24:
        optimized_network=ipaddress.IPv4Network(
            f"{real_network.network_address}/24",
            strict=False
        )
    else:
        optimized_network=real_network
    return str(optimized_network)

def discover_devices() -> List[Dict]:
    network=detect_network()
    result=subprocess.run(
        ["nmap","-sn","-PR",network], #nmap -sn network #taking time, scale this for enterprise networks
        capture_output=True,
        text=True
    )
    devices=[]
    current_device={}
    for line in result.stdout.splitlines():
        line=line.strip()
        if line.startswith("Nmap scan report for"):
            if current_device:
                devices.append(current_device)
                current_device={}
            ip=line.split()[-1]
            current_device["ip"]=ip
            current_device["status"]="online"
        elif line.startswith("MAC Address:"):
            mac_match=re.search(
                r"MAC Address:\s([0-9A-F:]+)\s\((.+)\)",
                line
            )
            if mac_match:
                current_device["mac"]=mac_match.group(1)
                current_device["vendor"]=mac_match.group(2)
    if current_device:
        devices.append(current_device)
    for d in devices:
        d.setdefault("mac","Unknown")
        d.setdefault("vendor","Unknown")
    return devices

#main
if __name__=="__main__":
    devices=discover_devices()
    for d in devices:
        print(d)

def normalize_os(os_guess:str)->str:
    os_guess=os_guess.lower()
    if "android" in os_guess:
        return "Android"
    if "windows" in os_guess:
        return "Microsoft Windows"
    if "openwrt" in os_guess:
        return "OpenWrt (Embedded Linux)"
    if "linux" in os_guess:
        return "Linux / Embedded Linux"
    if "router" in os_guess or "camera" in os_guess or "aruba" in os_guess:
        return "Network / Embedded Device"
    return "Unknown"

def detect_os(ip:str)->str:
    result=subprocess.run(
        ["nmap","-O","--osscan-guess",ip],
        capture_output=True,
        text=True
    )
    raw_os=""
    for line in result.stdout.splitlines():
        if line.startswith("OS details:"):
            # return line.replace("OS details:","").strip()
            raw_os=line.replace("OS details:","").strip()
            break
    if not raw_os:
        for line in result.stdout.splitlines():
            if line.startswith("Aggressive OS guesses:"):
                raw_os=line.replace("Agressive OS guesses:","").strip()
                break
    # for line in result.stdout.splitlines():
    #     if line.startswith("Aggressive OS guesses:"):
    #         return line.replace("Aggressive OS guesses:","").strip()+"(guessed)"
    if not raw_os:
        return "Unknown"
    return normalize_os(raw_os)