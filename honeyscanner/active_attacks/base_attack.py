import paramiko
import socket
import time

from honeypots import BaseHoneypot
from typing import TypeAlias

AttackResults: TypeAlias = list[tuple[bool, str, float, str | int | None]]


class BaseAttack:
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """
        Initializes a new BaseAttack object.

        Args:
            honeypot (BaseHoneypot): Honeypot object to use information from
                                     for the attacks.
        """
        self.honeypot: BaseHoneypot = honeypot
        self.ssh_connections: list[paramiko.SSHClient] = []
        self.socket_connections: list[socket.socket] = []
        self.transports: list[paramiko.Transport] = []

    def is_honeypot_alive(self) -> bool:
        """
        Checks if the Honeypot is alive.

        Returns:
            bool: True if the Honeypot is alive, False otherwise.
        """
        try:
            honeypot_addr: tuple[str, int] = (self.honeypot.ip,
                                              self.honeypot.port)
            sock: socket.socket = socket.create_connection(honeypot_addr,
                                                           timeout=10)
            sock.close()
            return True
        except Exception:
            return False

    def close_socket_connections(self):
        """
        Closes the socket connections.
        """
        for s in self.socket_connections:
            if s:
                s.close()
        for transport in self.transports:
            if transport:
                transport.close()

    def connect_socket(self) -> paramiko.Channel | None:
        """
        Creates a SSH connection to the Honeypot.

        Returns:
            paramiko.Channel | None: If a connection can be made to the
                                     Honeypot the Channel object is
                                     returned. Otherwise None is returned.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.honeypot.ip, self.honeypot.port))
            transport = paramiko.Transport(s)

            if self.honeypot.name == "kippo":
                # Set the key exchange and host key algorithms to
                # the ones supported by the honeypot
                sec_opts: paramiko.SecurityOptions = transport.get_security_options()
                sec_opts.kex = self.honeypot.kex_algorithms
                sec_opts.key_types = self.honeypot.host_key_algorithms

            # Start the client
            transport.start_client()

            # Wait for the transport to become active
            transport.auth_password(self.honeypot.username,
                                    self.honeypot.password)

            # Wait for authentication to succeed
            while not transport.is_authenticated():
                time.sleep(1)

            chan: paramiko.Channel = transport.open_session()
            chan.get_pty()
            chan.invoke_shell()

            self.transports.append(transport)

            return chan
        except Exception as e:
            print(f"Error while connecting socket: {e}")
            return None

    def run_attack(self):
        raise NotImplementedError(
            "Please implement the 'run' method in your attack class"
        )
