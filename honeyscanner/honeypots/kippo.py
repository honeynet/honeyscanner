from .base_honeypot import BaseHoneypot

class Kippo(BaseHoneypot):
    def __init__(self, version, ip, port, username='root', password='123456'):
        super().__init__("kippo", version, ip, port, username, password)
    
    def set_version(self, version):
        if version == "0.9":
            return 'v' + version
        else: 
            return version

    def set_source_code_url(self):
        return "https://github.com/desaster/kippo/archive/refs/tags"

    def set_versions_list(self):
        return [
            {
                "version": "v0.9",
                "requirements_url": "https://raw.githubusercontent.com/aristofanischionis/kippo/master/requirements.txt",
            }
        ]
    
    def set_owner(self):
        return "desaster"
