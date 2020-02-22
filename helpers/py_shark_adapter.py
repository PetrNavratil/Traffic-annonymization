import json
import subprocess

# 913 * Writes
# the
# hex
# dump
# of
# a
# node.A
# json
# array is written
# containing
# the
# hex
# dump, position, length, bitmask and type
# of
# 914 * the
# node.
# 915 * /
# https://ask.wireshark.org/question/11743/where-is-tshark-t-jsonraw-documented/

# https://github.com/hokiespurs/velodyne-copte r/wiki/PCAP-format
import sys
import gc

import pyshark
from scapy.fields import MACField
from scapy.layers.l2 import DestMACField
from scapy.utils import str2mac, mac2str

from helpers.packet import Packet


class PySharkAdapter:

    PCAP_GLOBAL_HEADER = 24

    def __init__(self, file_name):
        self.pcap_global_header = self.get_global_header(file_name)
        self.file_name = file_name
        self.packets = pyshark.FileCapture(self.file_name, use_json=True, include_raw=True)
        self.output_file = open(f"{self.file_name.replace('.pcap', '.altered.pcap')}", 'wb')
        self.write_to_output_file(self.get_global_header(self.file_name))

    def get_global_header(self, file_name):
        # TODO: only works for pcap
        with open(file_name, 'rb') as f:
            return f.read(PySharkAdapter.PCAP_GLOBAL_HEADER)

    def write_to_output_file(self, write_bytes):
        self.output_file.write(write_bytes)

