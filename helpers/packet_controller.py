import scapy.all as scapy


class PacketController:

    scapy_reader: scapy.PcapReader
    scapy_writer: scapy.PcapWriter

    def __init__(self, file_names):
        self.file_names = file_names
        self.load_scapy_reader(self.file_names[0])
        self.load_scapy_writer(self.file_names[0])

    def load_scapy_reader(self, file_name):
        self.scapy_reader = scapy.PcapReader(file_name)

    def load_scapy_writer(self, file_name):
        self.scapy_writer = scapy.PcapWriter(f"../dataset/altered/{file_name.split('/')[-1]}")

    def get_packet(self):
        self.scapy_reader.next()
        return self.scapy_reader.read_packet()

    def set_packet(self, packet):
        self.scapy_writer.write(packet)

