import paramiko
import time
from .base_attack import BaseAttack

class SSHKeepAliver(BaseAttack):
    PACKETS_PER_MINUTE = 5
    TARGET_TOTAL_TIME = 250
    KEEP_ALIVE_INTERVAL = 60
    
    def __init__(self, honeypot):
        super().__init__(honeypot)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.packets_sent = 0
        self.total_time = 0
    
    def connect(self):
        """
        Establishes an SSH connection with the honeypot.
        """
        print("Connecting to the honeypot...")
        self.client.connect(
            self.honeypot.get_ip(), 
            port=self.honeypot.get_port(), 
            username=self.honeypot.get_username(), 
            password=self.honeypot.get_password()
        )
        transport = self.client.get_transport()
        transport.set_keepalive(self.KEEP_ALIVE_INTERVAL)
    
    def send_keep_alive_packets(self):
        """
        Sends keep-alive packets at regular intervals to keep the SSH session alive.
        """
        print("Sending keep-alive packets...")
        session = self.client.invoke_shell()

        try:
            start_time = time.time()
            while time.time() - start_time < self.TARGET_TOTAL_TIME:
                session.send("echo 'keep_alive'\n")
                print("Sent keep-alive packet.")
                self.packets_sent += 1
                time.sleep(60 / self.PACKETS_PER_MINUTE)
            self.total_time = time.time() - start_time
        except KeyboardInterrupt:
            print("Keyboard interrupt detected. Closing the session...")
            session.close()

    def run_attack(self):
        """
        Initiates the attack by connecting to the honeypot and sending keep-alive packets.
        """
        try:
            self.connect()
            self.send_keep_alive_packets()
            return True, "SSH keep-alive attack successfully maintained the connection.", self.total_time, self.packets_sent
        except paramiko.AuthenticationException:
            return False, "Authentication failed. Check the credentials.", 0, 0
        except paramiko.SSHException as e:
            return False, f"An SSH error occurred: {str(e)}", 0, 0
        except paramiko.ssh_exception.NoValidConnectionsError:
            return False, "Unable to connect to the SSH server.", 0, 0
        except Exception as e:
            return False, f"An error occurred: {str(e)}", 0, 0
        finally:
            self.client.close()
