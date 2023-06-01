from .base_honeypot import BaseHoneypot

class Cowrie(BaseHoneypot):
    def __init__(self, version, ip, port, username, password):
        super().__init__("cowrie", version, ip, port, username, password)