class BaseHoneypot:
    def __init__(self, name, version, ip, port, username, password):
        self.name = name
        self.set_version(version)
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password

    def get_name(self):
        return self.name

    def get_version(self):
        return self.version

    def get_ip(self):
        return self.ip

    def get_port(self):
        return self.port

    def get_username(self):
        return self.username

    def get_password(self):
        return self.password

    def set_version(self, version):
        # Cowrie has this weird versioning scheme, after version 2 they added a 'v' in front of the version number
        if self.name == "cowrie" and version in ["2.1.0", "2.4.0", "2.5.0"]:
            self.version = 'v' + version
        else: 
            self.version = version