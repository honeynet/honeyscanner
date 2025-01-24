import threading
import signal

class TimeoutManager:
    def __init__(self, timeout_seconds):
        self.timeout_seconds = timeout_seconds
        self.timer = None
        
    def start_timeout(self):
        self.timer = threading.Timer(self.timeout_seconds, self._handle_timeout) # threading.Timer: Creates a timer that runs a function after delay
        self.timer.start()
        
    def stop_timeout(self):
        if self.timer:
            self.timer.cancel()
            
    def _handle_timeout(self):
        print(f"\nScan timed out after {self.timeout_seconds} seconds")
        signal.raise_signal(signal.SIGINT) # signal.SIGINT: Simulates CTRL+C to gracefully stop scan
