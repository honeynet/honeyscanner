from .base_honeypot import BaseHoneypot


class Conpot(BaseHoneypot):
    def __init__(self, version, ip, port, username='', password=''):
        if username is None:
            username = ''
        if password is None:
            password = ''
        super().__init__("conpot", version, ip, port, username, password)

    def set_source_code_url(self):
        return "https://github.com/mushorg/conpot/archive/refs/tags"

    def set_versions_list(self):
        return [
            {
                "version": "0.6.0",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/Release_0.6.0/requirements.txt",
            },
            {
                "version": "0.5.2",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/Release_0.5.2/requirements.txt",
            },
            {
                "version": "0.5.1",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/Release_0.5.1/requirements.txt",
            },
            {
                "version": "0.5.0",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/Release_0.5.0/requirements.txt",
            },
            {
                "version": "0.4.0",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/Release_0.4.0/requirements.txt",
            },
            {
                "version": "0.3.1",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/Release_0.3.1/requirements.txt",
            },
            {
                "version": "0.3.0",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/Release_0.3.0/requirements.txt",
            },
            # NO Release_ used in front of the version from here on
            {
                "version": "0.2.2",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/0.2.2/requirements.txt",
            },
            {
                "version": "0.2.2",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/0.2.2/requirements.txt",
            },
            {
                "version": "0.2.1",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/0.2.1/requirements.txt",
            },
            {
                "version": "0.2",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/conpot/0.2/requirements.txt",
            }
        ]

    def set_owner(self):
        return "mushorg"
