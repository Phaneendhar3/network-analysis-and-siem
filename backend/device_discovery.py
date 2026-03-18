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

def get_os_risk(os_name:str)->dict:
    os_name=os_name.lower()
    if 'windows' in os_name:
        return {"risk_level":"High","risk_score":8}
    if 'android' in os_name:
        return {'risk_level':"Medium",'risk_score':6}
    if 'linux' in os_name:
        return {'risk_level':'Medium','risk_score':5}
    if 'embedded' in os_name or 'network' in os_name:
        return {'risk_level':'High','risk_score':9}
    return {'risk_level':"Low",'risk_score':2}

def scan_open_ports(ip:str)->list:
    result=subprocess.run(
        ["nmap","-Pn","--min-rate","1000",ip],
        capture_outpu=True
        text=True
    )
    open_ports=[]
    for line in result.stdout.splitlines():
        line=line.strip()
        if "/tcp" in line and "open" in line:
            port=int(line.split("/")[0])
            open_ports.append(port)
    return open_ports

def get_port_risk(open_ports:list)->dict:
    risk_score=0
    reasons=[]
    risky_ports={
        21:("FTP",2),
        22:("SSH",1),
        23:("Telnet",4),
        80:("HTTP",1),
        443:("HTTPS",0),
        445:("SMB",4),
        3389:("RDP",4),
        3306:("MySQL",3),
        5900:("VNS",3)
    }
    for port in open_ports:
        if port in risky_ports:
            service,score=risky_ports[port]
            risk_score+=score
            reasons.append(f"{service} port {port} open")
    if risk_score>=7:
        level="High"
    elif risk_score>=3:
        level="Medium"
    else:
        level="Low"
    return {
        "port_risk_score":risk_score,
        "port_risk_level":level,
        "port_reasons":reasons
    }

def analyze_device_risk(ip:str,os_name:str)->dict:
    os_risk=get_os_risk(os_name)
    open_ports=scan_open_ports(ip)
    port_risk=get_port_risk(open_ports)
    final_score=os_risk["risk_score"]+port_risk["port_risk_score"]
    if final_score>=12:
        final_level='Critical'
    elif final_score>=8:
        final_level='High'
    elif final_score>=4:
        final_level='Medium'
    else:
        final_level='Low'
    return {
        'open_ports':open_ports,
        'os_risk':os_risk,
        'port_risk':port_risk,
        'final_risk_score':final_score,
        'final_risk_level':final_level
    }

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