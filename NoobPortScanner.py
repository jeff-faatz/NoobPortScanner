#!/bin/python3

#------------------------------------------------------#
#----------- Noob Port Scanner  Version 0.1 -----------#
#--------------- Written by Jeff Faatz ----------------#
#--------------- Created February 2023 ----------------#
#----------- https://github.com/jeff-faatz ------------#
#-------------- https://jeffreyfaatz.com --------------#
#------------------------------------------------------#

import pyfiglet
import asyncio
import argparse
import socket

from typing import Generator, Any, Collection
from abc import ABC, abstractmethod
from time import ctime, time, perf_counter
from collections import defaultdict
from contextlib import contextmanager

#Banner
ascii_banner = pyfiglet.figlet_format("Noob Port Scanner")
print(ascii_banner)

class AsyncTCPScanner:

    def __init__(self,
                 targets: Collection[str],
                 ports: Collection[int],
                 timeout: float):

        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.results = defaultdict(dict)
        self.total_time = float()
        self._loop = asyncio.get_event_loop()
        self._observers = list()

    @property
    def _scan_tasks(self):

        return [self._scan_target_port(target, port) for port in self.ports
                for target in self.targets]

    @contextmanager
    def _timer(self):

        start_time: float = perf_counter()
        yield
        self.total_time = perf_counter() - start_time

    def register(self, observer):

        self._observers.append(observer)

    async def _notify_all(self):

        [asyncio.create_task(observer.update()) for observer in self._observers]

    async def _scan_target_port(self, address: str, port: int) -> None:

        try:
            await asyncio.wait_for(
                asyncio.open_connection(address, port, loop=self._loop),
                timeout=self.timeout
            )
            port_state, reason = 'open', 'SYN/ACK'
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
            reasons = {
                'ConnectionRefusedError': 'Connection refused',
                'TimeoutError': 'No response',
                'OSError': 'Network error'
            }
            port_state, reason = 'closed', reasons[e.__class__.__name__]
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = 'unknown'
        self.results[address].update({port: (port_state, service, reason)})

    def execute(self):
        with self._timer():
            self._loop.run_until_complete(asyncio.wait(self._scan_tasks))
        self._loop.run_until_complete(self._notify_all())

class Output(ABC):

    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    async def update(self, *args, **kwargs) -> None:
        pass

class OutputToScreen(Output):
    def __init__(self, subject, show_open_only: bool = False):
        super().__init__(subject)
        self.scan = subject
        self.open_only = show_open_only

    async def update(self) -> None:
        all_targets: str = ' | '.join(self.scan.targets)
        num_ports: int = len(self.scan.ports) * len(self.scan.targets)
        output: str = '    {: ^8}{: ^12}{: ^12}{: ^12}'

        print(f'Starting Async Port Scanner at {ctime(time())}')
        print(f'Scan report for {all_targets}')

        for address in self.scan.results.keys():
            print(f'\n[>] Results for {address}:')
            print(output.format('PORT', 'STATE', 'SERVICE', 'REASON'))
            for port, port_info in sorted(self.scan.results[address].items()):
                if self.open_only is True and port_info[0] == 'closed':
                    continue
                print(output.format(port, *port_info))

        print(f"\nAsync TCP Connect scan of {num_ports} ports for "
              f"{all_targets} completed in {self.scan.total_time:.2f} seconds")

        await asyncio.sleep(0)

def process_cli_args(targets: str,
                     ports: str,
                     *args, **kwargs) -> AsyncTCPScanner:

    def _parse_ports(port_seq: str) -> Generator[int, Any, None]:

        for port in port_seq.split(','):
            try:
                port = int(port)
                if not 0 < port < 65536:
                    raise SystemExit(f'Error: Invalid port number {port}.')
                yield port
            except ValueError:
                start, end = (int(port) for port in port.split('-'))
                yield from range(start, end + 1)

    return AsyncTCPScanner(targets=tuple(targets.split(',')),
                           ports=tuple(_parse_ports(ports)),
                           *args, **kwargs)

if __name__ == '__main__':

    usage = ('Usage examples:\n'
             '1. python3 simple_async_scan.py google.com -p 80,443\n'
             '2. python3 simple_async_scan.py '
             '45.33.32.156,demo.testfire.net,18.192.172.30 '
             '-p 20-25,53,80,111,135,139,443,3306,5900')

    parser = argparse.ArgumentParser(
        description='Simple asynchronous TCP Connect port scanner',
        epilog=usage,
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('targets', type=str, metavar='ADDRESSES',
                        help="A comma-separated sequence of IP addresses "
                             "and/or domain names to scan, e.g., "
                             "'45.33.32.156,65.61.137.117,"
                             "testphp.vulnweb.com'.")
    parser.add_argument('-p', '--ports', type=str, required=True,
                        help="A comma-separated sequence of port numbers "
                             "and/or port ranges to scan on each target "
                             "specified, e.g., '20-25,53,80,443'.")
    parser.add_argument('--timeout', type=float, default=10.0,
                        help='Time to wait for a response from a target before '
                             'closing a connection (defaults to 10.0 seconds).')
    parser.add_argument('--open', action='store_true',
                        help='Only show open ports in scan results.')
    cli_args = parser.parse_args()

    scanner = process_cli_args(targets=cli_args.targets,
                               ports=cli_args.ports,
                               timeout=cli_args.timeout)

    to_screen = OutputToScreen(subject=scanner,
                               show_open_only=cli_args.open)
    scanner.execute()