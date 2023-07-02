class BaseHoneypot:
    def __init__(self, name, version, ip, port, username, password):
        self.name = name
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.version = self.set_version(version)
        self.owner = self.set_owner()
        self.source_code_url = self.set_source_code_url()
        self.versions_list = self.set_versions_list()

    def set_version(self, version):
        return version

    def set_owner(self):
        raise NotImplementedError("This method should be overriden in a subclass")

    def set_source_code_url(self):
        raise NotImplementedError("This method should be overriden in a subclass")

    def set_versions_list(self):
        raise NotImplementedError("This method should be overriden in a subclass")
