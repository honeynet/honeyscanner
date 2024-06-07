from .base_honeypot import BaseHoneypot


class Cowrie(BaseHoneypot):
    def __init__(self, version, ip, port, username='root', password='12345'):
        if username is None:
            username = 'root'
        if password is None:
            password = '12345'
        super().__init__("cowrie", version, ip, port, username, password)

    def set_version(self, version):
        if version in ["2.1.0", "2.4.0", "2.5.0"]:
            return 'v' + version
        else:
            return version

    def set_source_code_url(self):
        return "https://github.com/cowrie/cowrie/archive/refs/tags"

    def set_versions_list(self):
        return [
            {
                "version": "1.5.1",
                "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/1.5.1/requirements.txt",
            },
            {
                "version": "1.5.3",
                "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/1.5.3/requirements.txt",
            },
            {
                "version": "v2.1.0",
                "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/v2.1.0/requirements.txt",
            },
            {
                "version": "v2.4.0",
                "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/v2.4.0/requirements.txt",
            },
            {
                "version": "v2.5.0",
                "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/v2.5.0/requirements.txt",
            }
        ]

    def set_owner(self):
        return "cowrie"
