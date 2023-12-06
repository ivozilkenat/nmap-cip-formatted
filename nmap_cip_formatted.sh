#!/bin/bash

# Arg1: Target network

./basic_nmap_ipv4_xml.sh $1
python nmap2cip.py ./nmap-out.xml > nmap-out-formatted.txt