import socket
import requests
import ssl

from core import Honeyscanner
from typing import TypeAlias
from .sshconnect import SSHConnectCowrie

PortSet: TypeAlias = set[int]

COWRIE_KIPPO_PORT: PortSet = {2222}
CONPOT_PORTS: PortSet = {2121, 5020, 10201, 44818}
DIONAEA_PORTS: PortSet = {21,
                          23,
                          42,
                          53,
                          80,
                          135,
                          443,
                          445,
                          1433,
                          1723,
                          1883,
                          3306,
                          5060,
                          9100,
                          11211,
                          27017}


class HoneypotDetector:

    def __init__(self, ip: str) -> None:
        """
        Initializes a new HoneypotDetector object.

        Args:
            ip (str): IP address of the host to check.
        """
        self.ip = ip
        self.honeypot_ports: PortSet = set()
        self.honeypot_name: str = ""

    def connect_to_socket(self, port, message=None) -> bytes | None:
        """
        Connects to a specific port on a given IP address.

        Args:
            port (int): The port number to connect to.
            message (bytes, optional): A message to send to the server after
                                       connecting. Default is None.

        Returns:
            str: The response received from the server, or None if
                 an error occurs.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.ip, port))
                if message:
                    s.sendall(message)
                resp = s.recv(1024)
                return resp
        except socket.error as e:
            print(f'Socket error {e}')
            return None

    def check_port(self, ip, port) -> bool:
        """
        Checks if a specific port is open.

        Args:
            ip (str): The IP address of the host to check.
            port (int): The port number to check.

        Returns:
            bool: True if the port is open and accepting connections, False
                  otherwise.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((ip, port))
                return True
        except socket.timeout:
            return False
        except socket.error:
            return False

    def check_open_ports(self, ip: str) -> PortSet:
        """
        Scans a given IP address to get set of open ports.

        Args:
            ip (str): The IP address of the host to scan.

        Returns:
            PortSet: A set of open ports on the given IP address.
        """
        ports: PortSet = {port for port in range(1, 65536)}
        open_ports = set()

        print(f'Start scanning ports on {ip}')

        for port in ports:
            if self.check_port(ip, port):
                open_ports.add(port)

        print(f'Open ports: {open_ports}')
        self.honeypot_ports = open_ports
        return open_ports

    def get_latest_version(self, honeypot) -> str:
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
            latest_release = response.json()
            return latest_release['tag_name']
        else:
            print("Failed to find the latest version.")
            return ""

    def port_2222(self) -> str | None:
        """
        Checks if the SSH service on port 2222 of the given IP address is
        running a Cowrie or Kippo honeypot.

        Returns:
            str: cowrie if the banner matches the default Cowrie banner,
                 kippo if the banner matches the default Kippo banner,
                 None if neither banner matches.
        """
        print('Connecting to port 2222')
        response: bytes | None = self.connect_to_socket(2222)
        if response:
            data: str = response.decode().strip()
        else:
            return
        banner_cowrie: str = "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
        banner_kippo: str = "SSH-2.0-OpenSSH_5.1p1 Debian-5"
        if data == banner_cowrie:
            print("[\033[92m+\033[00m] Found default Cowrie banner")
            return "cowrie"
        elif data == banner_kippo:
            print("[\033[92m+\033[00m] Found default Kippo banner")
            return "kippo"
        else:
            print("[\033[91m-\033[00m] Didn't find default banner")
            return

    def port_21(self) -> bool:
        """
        Checks if the running service on port 21 is a specific FTP server.

        Args:
            ip (str): The IP address of the host to check.

        Returns:
            bool: True if the FTP banner matches the default expected banner,
                  False otherwise.
        """
        print('Connecting to port 21')
        response: bytes | None = self.connect_to_socket(21)
        if response:
            data: str = response.decode().strip()
        else:
            return False
        default_banner = '220 DiskStation FTP server ready.'
        if data == default_banner:
            print('[\033[92m+\033[00m] Found default FTP banner')
            return True
        else:
            print('[\033[91m-\033[00m] Didn\'t find default FTP banner')
            return False

    def port_443(self):
        """
        Checks if the running service on port 443 has Dionaea honeypot
        SSL cert.

        Returns:
            bool: True if the SSL certificate indicates a Dionaea SSL server,
                  False otherwise.
        """
        print('Connecting to port 443')

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((self.ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=self.ip) as ssock:
                cert = ssock.getpeercert(True)
                cert = str(cert)
                if "dionaea.carnivore.it1" in cert:
                    print("[\033[92m+\033[00m] Found dionaea ssl-cert")
                    return True
                else:
                    print("[\033[91m-\033[00m] Didn't find default dionaea ssl-cert")
                    return False

    def port_445(self) -> bool:
        """
        Checks if running service on port 445 is Dionaea SMB server.

        Returns:
            bool: True if the response indicates a Dionaea SMB server,
                  False otherwise.
        """
        print('Connecting to port 445')
        message: bytes = b"\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00" \
                         b"\x00\x00\x08\x01\x40\x00\x00\x00\x00\x00\x00" \
                         b"\x00\x00\x00\x00\x00\x00\x00\x00\x40\x06\x00" \
                         b"\x00\x01\x00\x00\x81\x00\x02PC NETWORK PROGR" \
                         b"AM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02" \
                         b"MICROSOFT NETWORKS 3.0\x00\x02LANMAN1.0\x00\x02" \
                         b"LM1.2X002\x00\x02Samba\x00\x02NT LANMAN 1.0\x00" \
                         b"\x02NT LM 0.12\x00"
        response: bytes | None = self.connect_to_socket(445, message=message)
        if not response:
            return False
        default_banner = b'SMBr'
        if default_banner in response:
            print("[\033[92m+\033[00m] Found dionaea smb server")
            return True
        else:
            print("[\033[91m-\033[00m] Didn\'t find dionaea smb server")
            return False

    def check_cowrie(self):
        """
        Checks if a given IP address is running a Cowrie honeypot by
        connecting via SSH and performing tests.

        Returns:
            None: This function performs checks and does not return a value.
        """
        ssh_conn = SSHConnectCowrie(ip=self.ip,
                                    port=2222,
                                    username="root",
                                    password="1234")
        ssh_conn.connect()
        ssh_conn.check_os_version()
        ssh_conn.check_meminfo()
        ssh_conn.check_mounts()
        ssh_conn.check_cpu()
        ssh_conn.check_group()
        ssh_conn.check_shadow()
        ssh_conn.check_passwd()
        ssh_conn.check_hostname()
        ssh_conn.close()

    def check_dionaea(self) -> bool:
        """
        Checks if a given IP address is running a Dionaea honeypot by
        checking specific ports.

        Returns:
            bool: True if the responses from the ports indicate a Dionaea
                  honeypot, False otherwise.
        """
        res_21 = self.port_21()
        res_443 = self.port_443()
        res_445 = self.port_445()
        return res_21 and res_443 and res_445

    def detect_honeypot(
            self,
            username: str = "",
            password: str = ""
            ) -> Honeyscanner | None:
        """
        Detects if a given IP address is running a known honeypot based on
        open ports and responses.

        Args:
            ip (str): The IP address of the host to check.

        Returns:
            Honeyscanner: A Honeyscanner object representing the detected
                          honeypot.
        """
        open_ports: PortSet = self.check_open_ports(self.ip)
        version: str = ""

        if open_ports == COWRIE_KIPPO_PORT:
            resp = self.port_2222()
            if resp == "cowrie":
                self.check_cowrie()
                print("This host is probably Cowrie honeypot")
                version = self.get_latest_version("cowrie")
                self.honeypot_name = "cowrie"
                print(f"Cowrie version {version}")
            elif resp == "kippo":
                print("This host is probably Kippo honeypot")
                version = self.get_latest_version("kippo")
                self.honeypot_name = "kippo"
                print(f"Kippo version {version}")
        elif open_ports <= DIONAEA_PORTS:
            print("The same open ports as in Dionaea honeypot")
            if self.check_dionaea():
                print("This host is probably Dionaea honeypot")
                version = self.get_latest_version("dionaea")
                self.honeypot_name = "dionaea"
                print(f"Dionaea version {version}")
            else:
                print("This host might be Dionaea")
        elif open_ports <= CONPOT_PORTS:
            print("This host is probably Conpot honeypot")
            version = self.get_latest_version("conpot")
            self.honeypot_name = "conpot"
            print(f"Conpot version {version}")
        else:
            print("Unsupported honeypot detected")
            return

        if self.honeypot_name == "cowrie" or self.honeypot_name == "kippo":
            if not username:
                username = 'root'
            if not password:
                password = '1234'
            return Honeyscanner(
                self.honeypot_name,
                version,
                self.ip,
                self.honeypot_ports,
                username,
                password
            )
        else:
            return Honeyscanner(
                self.honeypot_name,
                version,
                self.ip,
                self.honeypot_ports,
                "",
                ""
            )
