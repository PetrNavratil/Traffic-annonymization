import asyncio
import json
import os
import subprocess
import fileinput

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

from jsonslicer import JsonSlicer
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
        # print(self.pcap_global_header)
        # with open(file_name.replace(".pcap", ".json"), 'w') as f:
        #     print(f'Modifying original pcap {file_name} to json')
        #     # r, w = os.pipe()
        #     # JsonSlicer(r, (None, None, 'layers'))
        #     # proc = await asyncio.create_subprocess_exec('tshark', [f'-r{file_name}', '-Tjson', '-x'])
        #     # result = subprocess.run([f'tshark', f'-r{file_name}', '-Tjson', '-x'], stdout=subprocess.PIPE)
        #     print("IT SHOULD BE NON BLOCKING")
        #     # print(result.returncode)
        #     # try:
        #     #     result.check_returncode()
        #     # except subprocess.CalledProcessError as e:
        #     #     print(f"Could not parse {file_name}", file=sys.stderr)
        #     #     print(e.stderr.decode(), file=sys.stderr)
        #     #     sys.exit(1)
        #     print('Modifying completed')
        # for i, packet in enumerate(json.loads(result.stdout.decode())):
        #     print(f"PACKET CISLO {i}")
        #     self.packets.append(Packet(packet))

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

    async def __get_packets(self):
        r, w = os.pipe()
        output_file = os.fdopen(w, 'wb')
        input_file = os.fdopen(r)
        await asyncio.create_subprocess_exec('tshark', f'-r{self.file_name}', '-Tjson', '-x', stdout=output_file)
        os.close(w)
        return JsonSlicer(input_file, (None, None, 'layers'))


    def get_packets(self):
        loop = asyncio.get_event_loop()
        slicer = loop.run_until_complete(self.__get_packets())
        return slicer
