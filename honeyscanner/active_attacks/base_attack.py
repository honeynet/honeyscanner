import paramiko
import socket

class BaseAttack:
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.ssh_connections = []
        self.socket_connections = []
        self.transports = []

    def is_honeypot_alive(self):
        try:
            sock = socket.create_connection((self.honeypot.get_ip(), self.honeypot.get_port()), timeout=10)
            sock.close()
            return True
        except Exception as e:
            return False

    def close_socket_connections(self):
        for s in self.socket_connections:
            if s:
                s.close()
        for transport in self.transports:
            if transport:
                transport.close()

    def connect_ssh(self):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.honeypot.get_ip(), port=self.honeypot.get_port(), username=self.honeypot.get_username(), password=self.honeypot.get_password(), timeout=60)
            
            transport = ssh.get_transport()
            transport.local_version = "SSH-2.0-OpenSSH_9.0"

            return ssh
        except Exception as e:
            print(f"Exception while connecting: {e}")
            return None

    def connect_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.honeypot.get_ip(), self.honeypot.get_port()))
            transport = paramiko.Transport(s)
            transport.start_client()

            # Wait for the transport to become active
            transport.auth_password(self.honeypot.get_username(), self.honeypot.get_password())

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
        raise NotImplementedError("Please implement the 'run' method in your attack class")
