import asyncio
import os

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


from jsonslicer import JsonSlicer

class TsharkAdapter:

    PCAP_GLOBAL_HEADER = 24

    def __init__(self, file_name):
        self.packets = []
        self.file_name = file_name
        self.output_file = open(self.file_name.replace('.pcap', '.altered.pcap'), 'wb')
        self.write_global_header()

    def get_global_header(self, file_name):
        # TODO: only works for pcap
        with open(file_name, 'rb') as f:
            return f.read(TsharkAdapter.PCAP_GLOBAL_HEADER)

    async def __get_packets(self):
        r, w = os.pipe()
        output_file = os.fdopen(w, 'wb')
        input_file = os.fdopen(r)
        await asyncio.create_subprocess_exec('tshark', f'-r{self.file_name}', '-Tjson', '-x', '--no-duplicate-keys', stdout=output_file)
        os.close(w)
        return JsonSlicer(input_file, (None, None, 'layers'))

    def get_packets(self):
        loop = asyncio.get_event_loop()
        slicer = loop.run_until_complete(self.__get_packets())
        return slicer

    def write_global_header(self):
        self.output_file.write(self.get_global_header(self.file_name))

    def write_modified_packet(self, modified_packet_bytes):
        self.output_file.write(modified_packet_bytes)

    def close_output_file(self):
        self.output_file.close()