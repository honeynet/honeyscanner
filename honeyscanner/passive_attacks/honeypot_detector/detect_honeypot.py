import requests
import socket
import ssl
import yaml

from colorama import Fore
from core import Honeyscanner
from pathlib import Path
from typing import TypeAlias
from .sshconnect import CowrieInteract

PortSet: TypeAlias = set[int]


class HoneypotDetector:

    def __init__(self, ip: str) -> None:
        """
        Initializes a new HoneypotDetector object.

        Args:
            ip (str): IP address of the host to check.
        """
        self.ip = ip
        signatures_path = Path(__file__).parent / "signatures.yaml"
        with open(signatures_path, "r") as stream:
            self.signatures: dict = yaml.safe_load(stream)

    def get_input(self, step: dict) -> bytes:
        """
        Returns the input for the given step.

        Args:
            step (dict): The step to get the input from.

        Returns:
            bytes: The input for the given step to send over a socket.
        """
        return step["input"].encode()

    def get_ouput(self, step: dict) -> bytes:
        """
        Returns the output for the given step.

        Args:
            step (dict): The step to get the output from.

        Returns:
            bytes: The output for the given step depending on the type.
        """
        return step["output"].encode()

    def connect_to_socket(
            self,
            port: int,
            message: bytes | None = None
            ) -> bytes | None:
        """
        Connects to a specific port on a given IP address.

        Args:
            port (int): The port number to connect to.
            message (bytes, optional): A message to send to the server after
                                       connecting. Default is None.

        Returns:
            bytes: The response received from the server, or None if
                   an error occurs.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # s.settimeout(60)
                s.connect((self.ip, port))
                if message:
                    s.sendall(message)
                resp = s.recv(1024)
                return resp
        except socket.error as e:
            print(f"{Fore.RED}[-]{Fore.RESET} Socket Error: {e}")
            return

    def check_port(self, port: int) -> bool:
        """
        Checks if a specific port is open.

        Args:
            port (int): The port number to check.

        Returns:
            bool: True if the port is open and accepting connections, False
                  otherwise.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((self.ip, port))
                return True
        except socket.timeout:
            return False
        except socket.error:
            return False

    def check_open_ports(self) -> PortSet:
        """
        Scans a given IP address to get set of open ports.

        Args:
            ip (str): The IP address of the host to scan.

        Returns:
            PortSet: A set of open ports on the given IP address.
        """
        ports: PortSet = {port for port in range(1, 65536)}
        open_ports = set()
        print(f"{Fore.GREEN}[+]{Fore.RESET} Starting port scan on {self.ip}")

        for port in ports:
            if self.check_port(port):
                open_ports.add(port)

        print(f"{Fore.GREEN}[+]{Fore.RESET} Open ports: {open_ports}")
        return open_ports

    def get_latest_version(self, honeypot: str) -> str:
        """
        Retrieves the latest version of a specified honeypot.

        Args:
            honeypot (str): The name of the honeypot. Supported values are
                            cowrie, kippo, dionaea, and conpot.

        Returns:
            str: The latest version tag of the specified honeypot, or None if
                 the version could not be retrieved.

        TODO:
            Update to get the links to the latest releases in a separate file.
        """
        url: str = ""
        if honeypot == "cowrie":
            url = "https://api.github.com/repos/cowrie/cowrie/releases/latest"
        elif honeypot == "kippo":
            url = "https://api.github.com/repos/desaster/kippo/releases/latest"
        elif honeypot == "dionaea":
            return "0.11.0"
        elif honeypot == "conpot":
            url = "https://api.github.com/repos/mushorg/conpot/releases/latest"

        response = requests.get(url)

        if response.status_code == 200:
            latest_release = response.json()["tag_name"]
            if honeypot == "conpot":
                latest_release = latest_release.split('_')[1]
            return latest_release
        else:
            print("Failed to find the latest version.")
            return ""

    def signature_check(self, port: int, steps: list[dict]) -> bool:
        """
        Checks if any of the inputs that we have for a port will give a
        recognizable output.

        Args:
            steps (list[dict]): The list of steps to check.

        Returns:
            True: True if a signature match is found, False otherwise.
        """
        for step in steps:
            input: bytes = self.get_input(step)
            output: bytes | str = self.get_ouput(step)
            if port == 443:
                data = self.check_ssl()
            else:
                data = self.connect_to_socket(port, input)
            if not data:
                return False
            if output in data:
                print(f"{Fore.GREEN}[+]{Fore.RESET} Found signature match!")
                return True
        return False

    def check_ssl(self) -> bytes | None:
        """
        Checks if the running service on port 443 has a honeypot signature
        SSL cert.

        Returns:
            bool: True if the response contains the default SSL cert,
                  False otherwise.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.ip, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.ip) as ssock:
                    cert: bytes | None = ssock.getpeercert(True)
                    return cert
        except Exception as e:
            print(f"{Fore.RED}[-]{Fore.RESET} SSL Socket Error: {e}")

    def detect_honeypot(
            self,
            username: str = "",
            password: str = ""
            ) -> Honeyscanner | None:
        """
        Detects if a given IP address is running a known honeypot based on
        open ports and responses.

        Args:
            username (str, optional): The username to use for authentication.
                                      Defaults to "".
            password (str, optional): The password to use for authentication.
                                      Defaults to "".

        Returns:
            Honeyscanner: A Honeyscanner object representing the detected
                          honeypot.
        """
        open_ports: PortSet = self.check_open_ports()
        if not open_ports:
            return
        version: str = ""
        current_suspect: tuple[str, int] = ("unsupported", 0)
        honeypots_suspected: dict[str, int] = {
            "conpot": 0,
            "cowrie": 0,
            "dionaea": 0,
            "kippo": 0,
            "unsupported": 0
        }

        for port in open_ports:
            print(f"{Fore.YELLOW}[~]{Fore.RESET} Matching signatures for port {port}...")
            for signature in self.signatures.get(port, []):
                name: str = signature["name"]
                if self.signature_check(port, signature["steps"]):
                    if name == "cowrie":
                        if CowrieInteract(
                                self.ip,
                                port,
                                username,
                                password).ssh_signatures():
                            honeypots_suspected[name] += 1
                    else:
                        honeypots_suspected[name] += 1
                if honeypots_suspected[name] > current_suspect[1]:
                    current_suspect = (name, honeypots_suspected[name])
        if current_suspect[0] == "unsupported":
            print(f"{Fore.RED}[-]{Fore.RESET} Didn't find any signature matches")
            return
        name: str = current_suspect[0]
        version: str = self.get_latest_version(name)
        print(f"{Fore.GREEN}[+]{Fore.RESET} This is most likely {name} {version}")

        if name == "cowrie" or name == "kippo":
            if not username:
                username = "root"
            if not password:
                password = "1234"
            return Honeyscanner(
                name,
                version,
                self.ip,
                open_ports,
                username,
                password
            )
        else:
            return Honeyscanner(
                name,
                version,
                self.ip,
                open_ports,
                "",
                ""
            )
