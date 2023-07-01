from .base_honeypot import BaseHoneypot

class Kippo(BaseHoneypot):
    def __init__(self, version, ip, port, username='root', password='123456'):
        super().__init__("kippo", version, ip, port, username, password)