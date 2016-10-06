#! /usr/bin/env python

import sys
from scapy.all import *

pkts = rdpcap("pcap/ftp2.pcap")
pkts