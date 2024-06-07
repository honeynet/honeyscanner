import paramiko
import socket
import time


class BaseAttack:
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.ssh_connections = []
        self.socket_connections = []
        self.transports = []

    def is_honeypot_alive(self):
        try:
            honeypot_addr: tuple[str, int] = (self.honeypot.ip, self.honeypot.port)
            sock = socket.create_connection(honeypot_addr, timeout=10)
            sock.close()
            return True
        except Exception:
            return False

    def close_socket_connections(self):
        for s in self.socket_connections:
            if s:
                s.close()
        for transport in self.transports:
            if transport:
                transport.close()

    def connect_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.honeypot.ip, self.honeypot.port))
            transport = paramiko.Transport(s)

            if self.honeypot.name == "kippo":
                # Set the key exchange and host key algorithms to
                # the ones supported by the honeypot
                sec_opts = transport.get_security_options()
                sec_opts.kex = self.honeypot.kex_algorithms
                sec_opts.key_types = self.honeypot.host_key_algorithms

            # Start the client
            transport.start_client()

            # Wait for the transport to become active
            transport.auth_password(self.honeypot.username, self.honeypot.password)

            # Wait for authentication to succeed
            while not transport.is_authenticated():
                time.sleep(1)

            chan = transport.open_session()
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
