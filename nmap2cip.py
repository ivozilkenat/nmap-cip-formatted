#!/bin/python

#!/bin/bash
#sudo nmap -oX "nmap-out.xml" -sV -T5 --max-hostgroup=10 --max-parallelism=10 -A -sS $1

from collections import namedtuple, defaultdict
import argparse
import xml.etree.ElementTree as ET

DELIMITER_LENGTH = 50
UNKNOWN = "<UNKNOWN>"
INDENT = "    "

IP = namedtuple("IP", ["address", "type"])
OS = namedtuple("OS", ["name", "confidence"])
Service = namedtuple("Service", ["port", "protocol", "product", "version"])
SSHFingerprint = namedtuple("SSHFingerprint", ["fingerprint", "type"])


class HostSystem:
    def __init__(
            self, 
            hostname = None, 
            ip_addresses = None, 
            mac_address = None, 
            os_guesses = None,
            services = None,
            ssh_fingerprints = None 
        ) -> None:
        
        self.hostname = hostname
        self.ip_addresses = ip_addresses
        self.mac_address = mac_address
        self.os_guesses = os_guesses
        self.services = services
        self.ssh_fingerprints = ssh_fingerprints
        self.ssh_fingerprints_raw = {fprint for fprints in self.ssh_fingerprints.values() for fprint in fprints}
        
    def same_host(self, other: object) -> bool:
        "Assumptions: both hosts use same encrpytion algorithms"
        return any(fprint in other.ssh_fingerprints_raw  for fprint in self.ssh_fingerprints_raw) 
     
    def merge_with(self, other_host):
        # TODO: correct assumption, that no new services can be found?
        
        self.ip_addresses += other_host.ip_addresses
     
    def _str_add_hostname(self):
        return f"Hostname: {check_none(self.hostname)}\n"
    
    def _str_add_os(self):
        output = ""
        output += "OS:"
        
        if len(self.os_guesses) <= 0:
            output += f" {UNKNOWN}\n"
        else:
            output += "\n"
            for c, i in enumerate(self.os_guesses):
                output += f"{INDENT}[{c + 1}] {i.name} ({i.confidence}%)\n"
        return output
    
    def _str_add_addresses(self):
        output = ""
        output += f"MAC: {check_none(self.mac_address)}\n"
        output += f"IPs:"
        
        if len(self.ip_addresses) <= 0:
            output += f" {UNKNOWN}\n"
        else:
            output += "\n"
            for ip in self.ip_addresses:
                output += f"{INDENT}- {ip.address} ({ip.type})\n"
        return output

    def _str_add_services(self):
        output = ""
        if len(self.services) > 0:
            output += "Services:\n"
            for service in self.services:
                output += f"{INDENT}- {service.port}/{service.protocol} {'' if service.product is None else ': ' + service.product} {'' if service.version is None else '(' + service.version + ')'}\n"
        return output
        
    def _str_add_fingerprints(self):
        output = ""
        if len(self.ssh_fingerprints) > 0:
            output += "SSH public keys:\n"
            for port, values in self.ssh_fingerprints.items():
                output += f"- port: {port}\n"
                for key in values:
                    output += f"{INDENT}> {key.fingerprint} ({key.type})\n"   
        return output
    
    def __str__(self) -> str:
        output = ""
        
        output += self._str_add_hostname()
        output += self._str_add_os()
        output += self._str_add_addresses()
        output += self._str_add_services()
        output += self._str_add_fingerprints()
                    
        return output.rstrip()
    

def check_none(string):
    return UNKNOWN if string is None else string

def get_hosts_from(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    
    hosts = []
    
    for host in root.findall("host"):
    
        # Get IP and MAC addresses
        ip_address, mac_address = None, None
        
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type in ("ipv4", "ipv6"):
                ip_address = IP(addr.get("addr"), addr_type)
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
                    ssh_public_keys[port.get("portid")].append(SSHFingerprint(
                        fingerprint,
                        algo
                    ))
                
        hosts.append(HostSystem(
            hostname=hostname,
            ip_addresses=[ip_address],
            mac_address=mac_address,
            os_guesses=os_names,
            services=services,
            ssh_fingerprints=ssh_public_keys
        ))
        
    postscript_out = None
    for postscript in root.findall("postscript"):
        for script in postscript.findall("script"):
            postscript_out = script.get("output")
        
    return hosts, postscript_out

def print_hosts(hosts):
    for c, host in enumerate(hosts):
        print(f"[Host {c + 1}]".center(50, "="))
        print()
        print(host)
        print()
    
    print("=" * DELIMITER_LENGTH)
    
def print_postscript(postscript):
    print()
    print("> POSTSCRIPT OUTPUT <")
    print()
    print(postscript)

def merge_ipv4_ipv6(hosts_ipv4, hosts_ipv6):
    hosts = hosts_ipv4
    
    for host6 in hosts_ipv6:
        matched = False
        for host4 in hosts_ipv4:
            if host4.same_host(host6):
                host4.merge_with(host6)
                matched = True
                break
        if not matched:
            hosts.append(host6)
        
    return hosts

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument('filenameIPv4')
    parser.add_argument('filenameIPv6')
    
    args = parser.parse_args()
    
    hosts_ipv4, postscript_out_ipv4 = get_hosts_from(args.filenameIPv4)
    hosts_ipv6, postscript_out_ipv6 = get_hosts_from(args.filenameIPv6)
    
    merged_hosts = merge_ipv4_ipv6(hosts_ipv4, hosts_ipv6)
    
    print_hosts(merged_hosts)
    
    print_postscript(postscript_out_ipv4)
    print_postscript(postscript_out_ipv6)