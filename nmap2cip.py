#!/bin/python

#!/bin/bash
#sudo nmap -oX "nmap-out.xml" -sV -T5 --max-hostgroup=10 --max-parallelism=10 -A -sS $1

from collections import namedtuple, defaultdict

DELIMITER_LENGTH = 50
UNKNOWN = "<UNKNOWN>"
INDENT = "    "

import argparse
import xml.etree.ElementTree as ET

OS = namedtuple("OS", ["name", "confidence"])
Service = namedtuple("Service", ["port", "protocol", "product", "version"])
SSHPublicKey = namedtuple("SSHPublicKey", ["fingerprint", "type"])

def check_none(string):
    return UNKNOWN if string is None else string

def print_host_info(element_tree):
    for c, host in enumerate(element_tree.findall("host")):
        
        # Get IP and MAC addresses
        ip_address, mac_address = None, None
        
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                ip_address = addr.get("addr")
            elif addr_type == "mac":
                mac_address = addr.get("addr")
                
        hostnames = host.find("hostnames")
        hostname = None
    
        # Get hostname
        if hostnames:
            hostname = hostnames.find('hostname')
            if hostname is not None:
                hostname = hostname.get('name')
                
        # Get operating system
        os_element = host.find('os')
        os_max_count, os_count = 3, 0
        os_names = []
        if os_element is not None:
            for osmatch in os_element.findall("osmatch"):
                os_names.append(OS(
                    osmatch.get("name"),
                    osmatch.get("accuracy")
                ))
                os_count += 1
                if os_count >= os_max_count:
                    break
            
        # Get services
        services = []
        ssh_public_keys = defaultdict(list)
        for port in host.findall('.//port'):
            service = port.find('service')
            if service is not None:
                services.append(Service(
                        port.get("portid"), 
                        port.get("protocol"),
                        service.get("product"),
                        service.get("version")
                ))
                
            # Get ssh public keys
            for script in port.findall(".//script"):
                if script.get("id") != "ssh-hostkey":
                    continue
                
                for table in script.findall("table"):
                    fingerprint, algo = None, None
                    for el in table.findall("elem"):
                        k = el.get("key")
                        if k == "type":
                            algo = el.text
                        elif k == "fingerprint":
                            fingerprint = el.text
                        if fingerprint is not None and algo is not None:
                            break
                    ssh_public_keys[port.get("portid")].append(SSHPublicKey(
                        fingerprint,
                        algo
                    ))
                

        # Print the gathered information
        print(f"[Host {c + 1}]".center(DELIMITER_LENGTH, "="))
        print()
        
        print(f"Hostname: {check_none(hostname)}")
        
        
        print("OS:")
        if len(os_names) <= 0:
            print(f"{INDENT}> {UNKNOWN}")
        else:
            for c, i in enumerate(os_names):
                print(f"{INDENT}[{c + 1}] {i.name} ({i.confidence}%)")
        
        print(f"MAC: {check_none(mac_address)}, IPv4: {check_none(ip_address)}")
        
        if len(services) > 0:
            print("Services:")
            for service in services:
                print(f"{INDENT}- {service.port}/{service.protocol} {'' if service.product is None else ': ' + service.product} {'' if service.version is None else '(' + service.version + ')'}")
        
        if len(ssh_public_keys) > 0:
            print("SSH public keys:")
            for port, values in ssh_public_keys.items():
                print(f"- port: {port}")
                for key in values:
                    print(f"{INDENT}> {key.fingerprint} ({key.type})")
        
        print()
        
    print("=" * DELIMITER_LENGTH)
    
def print_postscript(element_tree):
    print()
    print("> POSTSCRIPT OUTPUT <")
    print()
    for postscript in element_tree.findall("postscript"):
        for script in postscript.findall("script"):
            print(script.get("output"))


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    
    args = parser.parse_args()
    
    tree = ET.parse(args.filename)
    root = tree.getroot()
    
    print_host_info(root)
    print_postscript(root)
    