from .base_honeypot import BaseHoneypot

class Glastopf(BaseHoneypot):
    def __init__(self, version, ip, port, username='', password=''):
        # Glastopf does not have a default username and password
        if username is None:
            username = ''
        if password is None:
            password = ''
        super().__init__("glastopf", version, ip, port, username, password)

    def set_source_code_url(self):
        return "https://github.com/mushorg/glastopf/archive/refs/tags"

    def set_versions_list(self):
        return [
            {
                "version": "3.1.2",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/glastopf/3.1.2/requirements.txt",
            }
        ]

    def set_owner(self):
        return "mushorg"