import os
import time
import socket
from .base_attack import BaseAttack
from boofuzz import Session, Target, SocketConnection, s_initialize, s_string,s_static, s_delim, s_get,s_block,s_group,TCPSocketConnection

"""
Notes:
I could add non-ascii characters to the list of characters to fuzz
I could add unicode characters to the list of characters to fuzz
I tried but didn't have much success
A variable can be used to adjust the aggressiveness of the fuzzing - Future work

"""

class Fuzzing(BaseAttack):
    def __init__(self, honeypot):
        super().__init__(honeypot)
        self.max_banner_length = 512
        self.max_terminal_length = 1024

    def run_connection_fuzzing(self):
        """
        Perform connection fuzzing by sending fuzzed ssh banners to the honeypot.
        """
        try:
            s_initialize("fuzz_banner")
            s_string("SSH", fuzzable=True, max_len=self.max_banner_length)
            s_delim(":", fuzzable=True)

            target = Target(connection=SocketConnection(self.honeypot.ip, self.honeypot.port, proto='tcp'))
            session = Session(target=target, web_port=None, sleep_time=0)
            session.auto_free_clear = True

            session.connect(s_get("fuzz_banner"))
            session.fuzz()

            test_cases_executed = session.total_mutant_index

            if self.is_honeypot_alive():
                return False, "Honeypot is still alive after connection fuzzing", test_cases_executed
            else:
                return True, "Banner fuzzing completed", test_cases_executed
        except Exception as e:
            return False, f"Banner fuzzing failed: {e}", 0

    def run_terminal_fuzzing(self):
        """
        Perform terminal fuzzing by sending fuzzed terminal commands to the honeypot.
        """
        try:
            s_initialize("fuzz_command")
            s_string("A", fuzzable=True, max_len=self.max_terminal_length)
            s_delim(":", fuzzable=True)

            target = Target(connection=SocketConnection(self.honeypot.ip, self.honeypot.port, proto='tcp'))
            session = Session(target=target, 
             sleep_time=0)
            session.auto_free_clear = True

            session.connect(s_get("fuzz_command"))
            session.fuzz()

            test_cases_executed = session.total_mutant_index

            if self.is_honeypot_alive():
                return False, "Honeypot is still alive after terminal fuzzing", test_cases_executed
            else:
                return True, "Terminal fuzzing completed", test_cases_executed
        except Exception as e:
            return False, f"Terminal fuzzing failed: {e}", 0

    def run_http_fuzzing(self):
        """
        Perform connection fuzzing by sending fuzzed ssh banners to the honeypot.
        """
        try:
            target = Target(connection=TCPSocketConnection(self.honeypot.ip, self.honeypot.port))
            session = Session(target=target, sleep_time=0)
            session.auto_free_clear = True
            s_initialize(name="Request")
            with s_block("Request-Line"):
                s_group("Method", ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"])
                s_delim(" ", name="space-1")
                s_string("/index.html", name="Request-URI", max_len=self.max_banner_length)
                s_delim(" ", name="space-2")
                s_string("HTTP/1.1", name="HTTP-Version",max_len=self.max_banner_length)
                s_static("\r\n", name="Request-Line-CRLF")
                s_string("Host:", name="Host-Line",max_len=self.max_banner_length)
                s_delim(" ", name="space-3")
                s_string("example.com", name="Host-Line-Value",max_len=self.max_banner_length)
                s_static("\r\n", name="Host-Line-CRLF")
            s_static("\r\n", "Request-CRLF")
            session.connect(s_get("Request"))
            session.fuzz()

            test_cases_executed = session.total_mutant_index

            if self.is_honeypot_alive():
                return False, "Honeypot is still alive after terminal fuzzing", test_cases_executed
            else:
                return True, "Terminal fuzzing completed", test_cases_executed

        except Exception as e:
            return False, f"Terminal fuzzing failed: {e}", 0

    def run_attack(self):
        """
        Run both connection fuzzing and terminal fuzzing attacks.
        """
        print(f"Running fuzzing attack on {self.honeypot.ip}:{self.honeypot.port}...")
        start_time = time.time()
        if self.honeypot.port == 80:
            success_terminal, message_terminal, test_cases_terminal = self.run_http_fuzzing()
            print(success_terminal, message_terminal)

        # terminal fuzzing 
        success_terminal, message_terminal, test_cases_terminal = self.run_terminal_fuzzing()
        print(success_terminal, message_terminal)

        # connection fuzzing
        success_connection, message_connection, test_cases_connection = self.run_connection_fuzzing()
        print(success_connection, message_connection)

        end_time = time.time()
        time_taken = end_time - start_time

        total_cases = test_cases_terminal + test_cases_connection

        success = success_connection or success_terminal
        message = f"{message_connection} - {message_terminal} - {total_cases} test cases executed"

        return success, message, time_taken, total_cases
