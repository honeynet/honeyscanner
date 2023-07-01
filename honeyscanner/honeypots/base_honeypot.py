class BaseHoneypot:
    def __init__(self, name, version, ip, port, username, password):
        self.name = name
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.set_version(version)
        self.set_owner()
        self.set_source_code_url()
        self.set_versions_list()

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
    
    def get_source_code_url(self):
        return self.source_code_url
    
    def get_versions_list(self):
        return self.versions_list
    
    def get_owner(self):
        return self.owner

    def set_version(self, version):
        # Cowrie has this weird versioning scheme, after version 2 they added a 'v' in front of the version number
        # Same for Kippo, but only for version 0.9
        if self.name == "cowrie" and version in ["2.1.0", "2.4.0", "2.5.0"]:
            self.version = 'v' + version
        elif self.name == "kippo" and version in ["0.9"]:
            self.version = 'v' + version
        else: 
            self.version = version
    
    def set_source_code_url(self):
        if self.name == "cowrie":
            self.source_code_url = "https://github.com/cowrie/cowrie/archive/refs/tags"
        elif self.name == "kippo":
            self.source_code_url = "https://github.com/desaster/kippo/archive/refs/tags"
        else:
            self.source_code_url = None
            raise ValueError(f"Unsupported honeypot type: {self.name}")
    
    def set_versions_list(self):
        if self.name == "cowrie":
            self.versions_list = [
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
        elif self.name == "kippo":
            # Kippo doesn't have a requirements.txt file, so I created mine
            self.versions_list = [
                {
                    "version": "v0.9",
                    "requirements_url": "https://raw.githubusercontent.com/aristofanischionis/kippo/master/requirements.txt",
                }
            ]
        else:
            self.versions_list = None
            raise ValueError(f"Unsupported honeypot type: {self.name}")

    def set_owner(self):
        if self.name == "cowrie":
            self.owner = "cowrie"
        elif self.name == "kippo":
            self.owner = "desaster"
        else:
            self.owner = None
            raise ValueError(f"Unsupported honeypot type: {self.name}")