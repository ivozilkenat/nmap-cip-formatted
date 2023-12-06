#!/bin/bash

sudo nmap -oX "nmap-out.xml" -sV -T5 --max-hostgroup=10 --max-parallelism=10 -A -sS $1
