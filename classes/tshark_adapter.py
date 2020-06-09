import asyncio
import os
import shutil
from jsonslicer import JsonSlicer


class TsharkAdapter:

    PCAP_GLOBAL_HEADER = 24
    PCAP_PACKET_HEADER = 16
    PCAP_BYTE_ORDERING_BIG = b'\xa1\xb2\xc3\xd4'
    PCAP_BYTE_ORDERING_LITTLE = b'\xd4\xc3\xb2\xa1'
    PCAP_BYTE_ORDERING_NANO_BIG = b'\xa1\xb2\x3c\x4d'
    PCAP_BYTE_ORDERING_NANO_LITTLE = b'\xa1\xb2\x3c\x4d'

    def __init__(self, file_names):
        self.packets = []
        self.file_names = file_names
        self.file_name = None
        self.output_file = None
        self.output_file_name = None
        self.metadata_file_name = None
        self.general_metadata_file_name = self.get_metadata_path() + 'meta_data.json'
        self.file_index = 0
        self.nano_resolution = False
        self.endianness = None

    def get_global_header(self, file_name):
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

    def write_modified_data(self, modified_packet_bytes):
        self.output_file.write(modified_packet_bytes)

    def write_field_data(self, data, position):
        self.go_to_file_position(position)
        self.write_modified_data(data)

    def go_to_file_position(self, position):
        self.output_file.seek(position, os.SEEK_SET)

    def close_output_file(self):
        if self.output_file is not None:
            self.output_file.close()

    def open_output_file(self):
        self.output_file = open(self.output_file_name, 'r+b')

    def open_next_file(self):
        if self.file_index < len(self.file_names):
            self.close_output_file()
            self.file_name = self.file_names[self.file_index]
            self.output_file_name = self.file_name.replace('.pcap', '.anonym.pcap')
            self.metadata_file_name = self.get_metadata_file_name()
            self.file_index += 1
            self.endianness, self.nano_resolution = self.get_pcap_info()
            return True
        return False

    def get_pcap_info(self):
        with open(self.file_name, 'rb') as f:
            magic_number_array = f.read(4)
            if magic_number_array == TsharkAdapter.PCAP_BYTE_ORDERING_BIG:
                return 'big', False
            if magic_number_array == TsharkAdapter.PCAP_BYTE_ORDERING_LITTLE:
                return 'little', False
            if magic_number_array == TsharkAdapter.PCAP_BYTE_ORDERING_NANO_BIG:
                return 'big', True
            if magic_number_array == TsharkAdapter.PCAP_BYTE_ORDERING_NANO_LITTLE:
                return 'little', True

    def get_file_additional_info(self):
        return {
            'endianness': self.endianness,
            'nano_resolution': self.nano_resolution
        }

    def copy_file(self):
        shutil.copy2(self.file_name, self.output_file_name)

    def get_metadata_file_name(self):
        head, sep, tail = self.file_name.rpartition('/')
        return self.get_metadata_path() + tail.replace('.pcap', '.json')

    def get_metadata_path(self):
        return os.getcwd() + '/metadata/'
