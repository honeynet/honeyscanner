from .base_honeypot import BaseHoneypot, Versions


class Kippo(BaseHoneypot):
    def __init__(self,
                 version: str,
                 ip: str,
                 ports: set[int],
                 username: str | None = 'root',
                 password: str | None = '123456') -> None:
        """
        Initializes a new instance of the Kippo Honeypot object.

        Args:
            version (str): The version of the Kippo Honeypot.
            ip (str): The IP address of the Honeypot.
            port (int): The port number of the Honeypot.
            username (str, optional): The username to authenticate with.
                                      Defaults to 'root'.
            password (str, optional): The password to authenticate with.
                                      Defaults to '123456'.
        """
        if username is None:
            username = 'root'
        if password is None:
            password = '123456'
        super().__init__("kippo", version, ip, ports, username, password)
        self.kex_algorithms = ['diffie-hellman-group1-sha1']
        self.host_key_algorithms = ['ssh-dss', 'ssh-rsa']

    def _set_version(self, version: str) -> str:
        """
        Gets the version of the running Kippo Honeypot

        Args:
            version (str): User inputted version number

        Returns:
            str: The version of the Kippo Honeypot
        """
        if version == "0.9":
            return 'v' + version
        else:
            return version

    def _set_source_code_url(self) -> str:
        """
        Sets the source code URL of the running Kippo Honeypot

        Returns:
            str: The source code URL of the Kippo Honeypot
        """
        return "https://github.com/desaster/kippo/archive/refs/tags"

    def _set_versions_list(self) -> Versions:
        """
        Sets the list of versions of the Kippo Honeypot

        Returns:
            list[dict]: List of versions of the Kippo Honeypot
        """
        return [
            {
                "version": "v0.9",
                "requirements_url": "https://raw.githubusercontent.com/aristofanischionis/kippo/master/requirements.txt",
            }
        ]

    def _set_owner(self) -> str:
        """
        Sets the owner of the Kippo Honeypot

        Returns:
            str: The owner of the Kippo Honeypot
        """
        return "desaster"
