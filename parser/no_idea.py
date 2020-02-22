import asyncio
import os
import threading
from asyncio.subprocess import PIPE


class NoIdea:

    def __init__(self, file_name):
        self.file_name = file_name
        self.eventloop = None
        self._setup_eventloop()
        r, w = os.pipe()
        self.read_fd = os.fdopen(r)
        self.write_fd = w



    def _setup_eventloop(self):
        print('SETTING UP')
        """
        Sets up a new eventloop as the current one according to the OS.
        """
        if os.name == "nt":
            self.eventloop = asyncio.ProactorEventLoop()
        else:
            try:
                self.eventloop = asyncio.get_event_loop()
            except RuntimeError:
                if threading.current_thread() != threading.main_thread():
                    # Ran not in main thread, make a new eventloop
                    self.eventloop = asyncio.new_event_loop()
                    asyncio.set_event_loop(self.eventloop)
                else:
                    raise
        if os.name == "posix" and isinstance(threading.current_thread(), threading._MainThread):
            asyncio.get_child_watcher().attach_loop(self.eventloop)

    def run_kokotina(self):
        data = self.eventloop.run_until_complete(self.kokotina())
        print(data)

    async def kokotina(self):
        return 'kokotina'

    async def send_data(self, stream):
        data = await stream.read(1024)
        print(data)
        if not data:
            raise EOFError()
        # os.write(self.write_fd, data)
        return

    async def gen(self):
        tshark_process = self.eventloop.run_until_complete(self._get_tshark_process())
        try:
            print('start')
            while True:
                try:
                    print('adasds')
                    data = self.eventloop.run_until_complete(
                        self.send_data(tshark_process.stdout))

                except EOFError:
                    print("EOF")
                    break

                # if packet:
                #     packets_captured += 1
                #     yield packet
                # if packet_count and packets_captured >= packet_count:
                #     break
        finally:
            print("SLUS")

    async def _get_tshark_process(self, packet_count=None, stdin=None):
        """
        Returns a new tshark process with previously-set parameters.
        """
        print('CALLED')
        proc = await asyncio.create_subprocess_exec('tshark', f'-r{self.file_name}', '-Tjson', '-x', stdout=PIPE)
        return proc
