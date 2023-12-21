#!/bin/python

# THIS SCRIPT IS AN ABOMINATION IN TERMS OF SOFTWARE DESIGN AND WAS CREATED UNDER IMMENSE TIME PRESSURE

import subprocess
import argparse
import netifaces as ni
import ipaddress
import xml.etree.ElementTree as ET
import sys

import nmap2cip

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
    command = f'sudo nmap -oX "{output_file_name}" -sV -T4 --max-hostgroup=10 --max-parallelism=10 -A -sS {to_CIDR(ip, nmask)}'
    result = subprocess.run(
        command, text=True, shell=True
    )
    check_rcode(result.returncode, result.stderr)

def scan_network_file(filename, output_file_name="file-nmap-out"):
    command = f'sudo nmap -oX "{output_file_name}" -sV -T4 --max-hostgroup=10 --max-parallelism=10 -A -sS -iL {filename}'
    result = subprocess.run(
        command, text=True, shell=True
    )
    check_rcode(result.returncode, result.stderr)

def scan6_local(interface, output_file_name="scan6-out"):
    command = f'scan6 -i {interface} -L > {output_file_name}'
    result = subprocess.run(
        command, text=True, shell=True
    )
    check_rcode(result.returncode, result.stderr)

def scan_for_routers(ip, nmask, output_file_name="nmap-router-out"):
    tmp_file_name = "possible_router_ips.txt"
    possible_addresses = possible_router_addresses(ip, nmask)
    addresses = list()
    
    with open(tmp_file_name, "w") as f:
        f.writelines([a + "\n" for a in possible_addresses])
    
    scan_network_file(tmp_file_name, output_file_name)
    
    tree = ET.parse(tmp_file_name)
    root = tree.getroot()
    
    for host in root.findall("host"):
    
        # Get IP and MAC addresses
        
        
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                addresses.append(addr.get("addr"))
                continue
    
    return addresses

def scan_evaluation(target_filename, src_filename_ipv4, src_filename_ipv6 = None):
    with open(target_filename, "w") as f:
        original_stdout = sys.stdout
        sys.stdout = f
        
        nmap2cip.print_data_eval(src_filename_ipv4, src_filename_ipv6)
        
        sys.stdout = original_stdout
                
if __name__ == "__main__":
    ROUTER_PREFIX_GUESS = 16 
    assert ROUTER_PREFIX_GUESS % 8 == 0
    
    NMAP_OUT_FILE_BASE = "nmap-out-{}.xml"
    DATA_EVAL_FILE_BASE = "nmap-eval-{}.txt"
    SCAN6_OUT_FILE_BASE = "scan6-out.txt"
    
    parser = argparse.ArgumentParser()
    parser.add_argument("interface")
    
    
    args = parser.parse_args()
    # scan local ip v4
    ip, local_prefix_len = get_ip_and_prefix(args.interface)
    
    nmap_out_file_name_ipv4 = NMAP_OUT_FILE_BASE.format("local-ipv4")
    nmap_out_file_name_ipv6 = NMAP_OUT_FILE_BASE.format("local-ipv6")
    
    scan_network(ip, local_prefix_len, NMAP_OUT_FILE_BASE.format("local-ipv4")) # TEST
    # scan ipv 6    
    scan6_local(args.interface, SCAN6_OUT_FILE_BASE)
    
    # eval data
    scan_evaluation(
        DATA_EVAL_FILE_BASE.format("local-ipv4"), 
        nmap_out_file_name_ipv4, 
        nmap_out_file_name_ipv6
    )
    
    # check for different networks
    router_ips = scan_for_routers(ip, ROUTER_PREFIX_GUESS) # TEST
    for r_ip in router_ips:
        if r_ip == ip:
            continue
        nmap_out_file_name = NMAP_OUT_FILE_BASE.format(ip)
        scan_network(r_ip, ROUTER_PREFIX_GUESS, nmap_out_file_name)
        
        # eval data here
        scan_evaluation(DATA_EVAL_FILE_BASE.format(r_ip), nmap_out_file_name)
