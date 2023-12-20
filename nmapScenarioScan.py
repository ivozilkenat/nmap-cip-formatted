#!/bin/python

import subprocess
import argparse
import netifaces as ni
import ipaddress

def check_rcode(return_code, message):
    if return_code != 0:
        print(f"[Error - Code: {return_code}] {message}")
        exit(return_code)

def to_CIDR(ip, netmask):
    # Create an IPv4 interface using the IP address and netmask
    interface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
    # Return the CIDR notation
    return interface

def get_ip_and_prefix(ifname):
    addrs = ni.ifaddresses(ifname)
    addr_data = addrs[ni.AF_INET][0]
    interface = ipaddress.IPv4Interface(f"{addr_data['addr']}/{addr_data['netmask']}") 
    return str(interface.ip), interface.network.prefixlen # Not nice

def possible_router_addresses(ip, nmask):
    addresses = list()
    ip_split = ip.split(".")
    block_index = nmask // 8
    ip_base = ".".join(ip_split[:block_index]) + ".{}.1"
    
    for i in range(256):
        addresses.append(ip_base.format(i))
        
    return addresses

def scan_network(ip, nmask, output_file_name="namp-out"):
    command = f'sudo nmap -oX "{output_file_name}.xml" -sV -T4 --max-hostgroup=10 --max-parallelism=10 -A -sS {to_CIDR(ip, nmask)}  '
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True
    )
    check_rcode(result.returncode, result.stderr)

def scan_for_routers(ip, nmask, output_file_name="nmap-router-out"):
    tmp_file_name = "possible_router_ips.txt"
    addresses = possible_router_addresses(ip, nmask)
    
    with open(tmp_file_name, "w") as f:
        for a in addresses:
            f.writelines([a + "\n" for a in addresses])
    
    command = f'sudo nmap -oX "{output_file_name}.xml" -T4 --max-hostgroup=10 --max-parallelism=10 -iL {tmp_file_name}'
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True
    )
    check_rcode(result.returncode, result.stderr)
    
    
if __name__ == "__main__":
    ROUTER_PREFIX_GUESS = 16 
    assert ROUTER_PREFIX_GUESS % 8 == 0
    
    NMAP_LOCAL_IPV4_FILE = "nmap-out-local-ipv4"
    
    parser = argparse.ArgumentParser()
    parser.add_argument("interface")
    
    args = parser.parse_args()
    
    
    
    ip, local_prefix_len = get_ip_and_prefix(args.interface)
    # scan_network(ip, local_prefix_len)
    scan_for_routers(ip, ROUTER_PREFIX_GUESS)
    # scan local ip v4
    # scan_network(ip, local_prefix_len, NMAP_LOCAL_IPV4_FILE)
    
    
    # check for routers
        #compose file of possible addresses for performance (tmp)
    
    # scan local v6