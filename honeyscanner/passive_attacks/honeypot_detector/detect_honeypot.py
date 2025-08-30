import asyncio
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

    async def connect_to_socket_async(
            self,
            port: int,
            message: bytes | None = None,
            timeout: float = 3.0
            ) -> bytes | None:
        """
        Asynchronously connects to a specific port on a given IP address.

        Args:
            port (int): The port number to connect to.
            message (bytes, optional): A message to send to the server after
                                       connecting. Default is None.
            timeout (float): Connection timeout in seconds. Default is 3.0.

        Returns:
            bytes: The response received from the server, or None if
                   an error occurs.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip, port),
                timeout=timeout
            )
            
            if message:
                writer.write(message)
                await writer.drain()
            
            # Read response with timeout
            resp = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            
            writer.close()
            await writer.wait_closed()
            return resp
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            return None
        except Exception as e:
            print(f"{Fore.RED}[-]{Fore.RESET} Socket Error on port {port}: {e}")
            return None

    def connect_to_socket(
            self,
            port: int,
            message: bytes | None = None
            ) -> bytes | None:
        """
        Synchronous wrapper for connect_to_socket_async to maintain compatibility.
        """
        return asyncio.run(self.connect_to_socket_async(port, message))

    async def check_port_async(self, port: int, timeout: float = 1.0) -> bool:
        """
        Asynchronously checks if a specific port is open.

        Args:
            port (int): The port number to check.
            timeout (float): Connection timeout in seconds. Default is 1.0.

        Returns:
            bool: True if the port is open and accepting connections, False otherwise.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
        except Exception:
            return False

    def check_port(self, port: int) -> bool:
        """
        Synchronous wrapper for check_port_async to maintain compatibility.
        """
        return asyncio.run(self.check_port_async(port))

    async def check_open_ports_async(
            self,
            port_range: tuple[int, int] = (1, 1025),
            max_concurrent: int = 100,
            timeout: float = 1.0,
            verbose: bool = True,
            show_closed: bool = False
            ) -> PortSet:
        """
        Asynchronously scans a given IP address to get set of open ports.

        Args:
            port_range (tuple): Range of ports to scan (start, end). Default is (1, 1025).
            max_concurrent (int): Maximum number of concurrent connections. Default is 100.
            timeout (float): Connection timeout per port in seconds. Default is 1.0.
            verbose (bool): Show progress during scanning. Default is True.
            show_closed (bool): Show closed/filtered ports. Default is False.

        Returns:
            PortSet: A set of open ports on the given IP address.
        """
        start_port, end_port = port_range
        total_ports = end_port - start_port + 1
        open_ports = set()
        completed_count = 0
        last_progress_shown = -1
        
        print(f"{Fore.GREEN}[+]{Fore.RESET} Starting async port scan on {self.ip} "
              f"(ports {start_port}-{end_port}, {total_ports} total)")

        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def check_single_port(port: int) -> None:
            nonlocal completed_count, last_progress_shown
            async with semaphore:
                if await self.check_port_async(port, timeout):
                    open_ports.add(port)
                    print(f"{Fore.GREEN}[+]{Fore.RESET} Port {port} is OPEN")
                elif show_closed:
                    print(f"{Fore.RED}[-]{Fore.RESET} Port {port} is closed/filtered")
                
                # Update progress after completing port check
                completed_count += 1
                current_progress = int((completed_count / total_ports) * 100)
                
                # Show progress every 10% or every 500 ports, whichever is more frequent
                progress_interval = min(500, max(50, total_ports // 10))
                
                if verbose and (completed_count % progress_interval == 0 or 
                              (current_progress > last_progress_shown and 
                               current_progress % 10 == 0)):
                    last_progress_shown = current_progress
                    print(f"{Fore.CYAN}[~]{Fore.RESET} Progress: {current_progress}% "
                          f"({completed_count}/{total_ports}) ports completed, "
                          f"{len(open_ports)} open ports found so far")

        # Create tasks for all ports
        tasks = [
            check_single_port(port) 
            for port in range(start_port, end_port + 1)
        ]
        
        # Run all tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
        
        print(f"{Fore.GREEN}[+]{Fore.RESET} Async scan complete. "
              f"Found {len(open_ports)} open ports out of {total_ports} scanned.")
        if open_ports:
            print(f"{Fore.GREEN}[+]{Fore.RESET} Open ports: {sorted(open_ports)}")
        else:
            print(f"{Fore.YELLOW}[!]{Fore.RESET} No open ports found in the specified range.")
        return open_ports

    def check_open_ports(
            self,
            port_range: tuple[int, int] = (1, 1025),
            max_concurrent: int = 100,
            timeout: float = 1.0,
            verbose: bool = True,
            show_closed: bool = False
            ) -> PortSet:
        """
        Scans a given IP address to get set of open ports (synchronous wrapper).

        Args:
            port_range (tuple): Range of ports to scan (start, end). Default is (1, 1025).
            max_concurrent (int): Maximum number of concurrent connections. Default is 100.
            timeout (float): Connection timeout per port in seconds. Default is 1.0.
            verbose (bool): Show progress during scanning. Default is True.
            show_closed (bool): Show closed/filtered ports. Default is False.

        Returns:
            PortSet: A set of open ports on the given IP address.
        """
        return asyncio.run(self.check_open_ports_async(
            port_range, max_concurrent, timeout, verbose, show_closed
        ))

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
            input_data: bytes = self.get_input(step)
            output: bytes | str = self.get_ouput(step)
            if port == 443:
                data = self.check_ssl()
            else:
                data = self.connect_to_socket(port, input_data)
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
            bytes: The SSL certificate data, or None if an error occurs.
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
            return None

    def detect_honeypot(
            self,
            username: str = "",
            password: str = "",
            port_range: tuple[int, int] = (1, 6000),
            max_concurrent: int = 100,
            verbose: bool = True,
            show_closed: bool = False
            ) -> Honeyscanner | None:
        """
        Detects if a given IP address is running a known honeypot based on
        open ports and responses.

        Args:
            username (str, optional): The username to use for authentication.
                                      Defaults to "".
            password (str, optional): The password to use for authentication.
                                      Defaults to "".
            port_range (tuple): Range of ports to scan. Default is (1, 1025).
            max_concurrent (int): Maximum concurrent connections. Default is 100.
            verbose (bool): Show progress during scanning. Default is True.
            show_closed (bool): Show closed/filtered ports. Default is False.

        Returns:
            Honeyscanner: A Honeyscanner object representing the detected
                          honeypot, or None if no honeypot is detected.
        """
        open_ports: PortSet = self.check_open_ports(
            port_range, max_concurrent, 1.0, verbose, show_closed
        )
        if not open_ports:
            return None
            
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
            return None
            
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