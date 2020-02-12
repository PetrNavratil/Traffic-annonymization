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

# https://github.com/hokiespurs/velodyne-copter/wiki/PCAP-format
import sys
import gc

from scapy.fields import MACField
from scapy.layers.l2 import DestMACField
from scapy.utils import str2mac, mac2str

from helpers.packet import Packet


class TsharkAdapter:

    PCAP_GLOBAL_HEADER = 24

    def __init__(self, file_name):
        self.packets = []
        self.pcap_global_header = self.get_global_header(file_name)
        self.file_name = file_name
        print(self.pcap_global_header)
        result = subprocess.run([f'tshark', f'-r{file_name}', '-Tjson', '-x'], capture_output=True)
        try:
            result.check_returncode()
        except subprocess.CalledProcessError as e:
            print(f"Could not parse {file_name}", file=sys.stderr)
            print(e.stderr.decode(), file=sys.stderr)
            sys.exit(1)
        for i, packet in enumerate(json.loads(result.stdout.decode())):
            print(f"PACKET CISLO {i}")
            self.packets.append(Packet(packet))

    def get_global_header(self, file_name):
        # TODO: only works for pcap
        with open(file_name, 'rb') as f:
            return f.read(TsharkAdapter.PCAP_GLOBAL_HEADER)

    def write_modified_file(self):
        with open(f"../dataset/altered/{self.file_name.split('/')[-1]}", 'wb') as f:
            f.write(self.pcap_global_header)
            for packet in self.packets:
                f.write(packet.packet_header)
                f.write(packet.packet_bytes)
