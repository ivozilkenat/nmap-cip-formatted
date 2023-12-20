#!/bin/bash

# Scan outside of local network (in scenario </64) does not use NDP, therefore very slow automatically. Manual usage advised

TARGET_NETWORK_IPv4=$1
TARGET_NETWORK_IPv6=$2
OUT_NAME=$3


# Check if TARGET_NETWORK_IPv4 is not provided
if [ -z "$TARGET_NETWORK_IPv4" ]; then
    echo "Error: TARGET_NETWORK_IPv4 not provided."
    exit 1
fi

# Check if TARGET_NETWORK_IPv6 is not provided
if [ -z "$TARGET_NETWORK_IPv6" ]; then
    echo "Error: TARGET_NETWORK_IPv6 not provided."
    exit 1
fi

if [ -z "$OUT_NAME" ]; then
    echo "Error: Output file name not provided."
    exit 1

fi

INTERFACE=${4:-"eth1"}

SCAN_OUT="scan6-out-$OUT_NAME.txt"
OUT_IPv4="nmap-out-ip4-$OUT_NAME.xml"
OUT_IPv6="nmap-out-ip6-$OUT_NAME.xml"

FILE_OUT="mega-scan-$OUT_NAME.txt"

sudo nmap -oX $OUT_IPv4 -sV -T4 --max-hostgroup=10 --max-parallelism=10 -A -sS $1

if [ "$TARGET_NETWORK_IPv6" != "skip" ]; then
    sudo scan6 -i $INTERFACE -L > $SCAN_OUT
    sudo nmap -6 -iL $SCAN_OUT -oX $OUT_IPv6 -sV -T4 --max-hostgroup=10 --max-parallelism=10 -A -sS $1
    python ./nmap2cip.py --filenameIPv4=$OUT_IPv4 --filenameIPv6=$OUT_IPv6 > $FILE_OUT
    echo ">>> SCAN FINISHED <<<"
    exit
fi

python ./nmap2cip.py --filenameIPv4=$OUT_IPv4 > $FILE_OUT
echo ">>> SCAN FINISHED <<<"