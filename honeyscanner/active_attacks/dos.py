import json
import os
import subprocess
import time

from pathlib import Path
from subprocess import CompletedProcess, Popen
from typing import TypeAlias
from .base_attack import AttackData, AttackResults, BaseAttack, BaseHoneypot
from .honeypot_port_scanner.honeypot_port_scanner import (HoneypotPortScanner,
                                                          AttackPorts)

Attack: TypeAlias = Popen | None
DoSResults: TypeAlias = dict[str, bool | float]

PIPE_PATH: str = "/tmp/data"
ATTACKS_PATH = Path(".") / "active_attacks" / "attacks"
RUN_ATTACKS: str = "go run main.go"


class DoS(BaseAttack):
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """
        Initializes a new DoSAllOpenPorts object.

        Args:
            honeypot (BaseHoneypot): Honeypot object to get the information
                                     for performing the DoS on the honeypot.
        """
        super().__init__(honeypot)
        self.honeypot_ports: AttackPorts = {}
        self.honeypot_rejecting_connections: bool = False

    def run_scanner(self) -> None:
        """
        Run the HoneypotPortScanner to get the open ports of the honeypot.
        """
        honeypot_scanner = HoneypotPortScanner(self.honeypot.ip)
        honeypot_scanner.run_scanner()
        self.honeypot_ports = honeypot_scanner.get_open_ports()

    def check_go_exists(self) -> bool:
        if os.path.exists("/usr/local/go/bin/go"):
            return True
        else:
            return False

    def make_pipe(self) -> None:
        """
        Create the named pipe in /tmp/data.
        """
        if not os.path.exists(PIPE_PATH):
            os.mkfifo(PIPE_PATH)

    def cleanup_pipe(self) -> None:
        """
        Delete the named pipe in /tmp/data.
        """
        if os.path.exists(PIPE_PATH):
            os.remove(PIPE_PATH)

    def read_data(self) -> DoSResults:
        """
        Read JSON data from the named pipe.

        Returns:
            DoSResults: JSON data from the named pipe.
        """
        fd = os.open(PIPE_PATH, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as pipe:
            data = pipe.read()
            while not data:
                data = pipe.read()
        return json.loads(data.decode("utf-8"))

    def write_data(self, data: dict) -> bool:
        """
        Write JSON data to the FIFO
        """
        with open(PIPE_PATH, "w") as pipe:
            json.dump(data, pipe)
            success: int = pipe.write("\n")
            if success == 0:
                print("[-] Failed to write data to pipe")
                return False
            return True

    def create_attack_process(self) -> Attack:
        """
        Start the subprocess that will run the attacks.

        Returns:
            Attack: Popen object that is running the attacks.
        """
        print("[+] Running attacks now")
        running = Popen(RUN_ATTACKS,
                        shell=True,
                        cwd=ATTACKS_PATH)
        if not running:
            print(f"[-] Failed to run attacks: {running.stderr}")
            return None
        return running

    def run_attack(self) -> AttackResults:
        """
        Launch the DoS attack using multiple threads.

        Returns:
            AttackResults: The results of the attack.
        """
        if not self.check_go_exists():
            print("[-] Go not found in $PATH. Cancelling DoS attack...")
            return (
                False,
                "[-] Failed to run attack",
                0,
                0
            )
        print("[+] Go was found in PATH, running DoS attack")
        self.run_scanner()
        time.sleep(.5)
        print(f"Running DoS attack on {self.honeypot.ip} and "
              f"ports: {list(self.honeypot_ports.keys())}")
        attack: Attack = self.create_attack_process()
        if not attack:
            return (
                False,
                "[-] Failed to run attack",
                0,
                0
            )
        program_data: AttackData = {
            "attack": "dos",
            "ports":   self.honeypot_ports,
            "server":  self.honeypot.ip,
            "user":    self.honeypot.username,
            "pass":    self.honeypot.password
        }
        self.make_pipe()
        print("[+] Sending data to attack program")
        time.sleep(2)
        self.write_data(program_data)
        time.sleep(.5)
        results: DoSResults = self.read_data()
        attack.wait()
        print("[+] Attack finished running")
        self.cleanup_pipe()
        output: str
        if results["success"]:
            output: str = "Vulnerability found: DoS attack made the honeypot "\
                          "reject connections"
        else:
            output: str = "Honeypot did not reject connections, attack "\
                          "unsuccessful"
        return (
            results["success"],
            output,
            results["time"],
            30000
        )
