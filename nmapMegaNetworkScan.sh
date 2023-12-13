#!/bin/bash

TARGET_NETWORK_IPv4=$1
TARGET_NETWORK_IPv6=$2

INTERFACE=${3:-"eth1"}

SCAN_OUT="scan6-out-$TARGET_NETWORK_IPv6.txt"
OUT_IPv4="nmap-out-$TARGET_NETWORK_IPv4.xml"
OUT_IPv6="nmap-out-$TARGET_NETWORK_IPv6.xml"

FILE_OUT="mega-scan-$OUT_IPv4-$OUT_IPv6-out.txt"

sudo scan6 -i $INTERFACE -L > $SCAN_OUT

sudo nmap -oX $OUT_IPv4 -sV -T5 --max-hostgroup=10 --max-parallelism=10 -A -sS $1

sudo nmap -6 -iL $SCAN_OUT -oX $OUT_IPv6 -sV -T5 --max-hostgroup=10 --max-parallelism=10 -A -sS $1

python ./nmap2cip.py $OUT_IPv4 $OUT_IPv6 > $FILE_OUT