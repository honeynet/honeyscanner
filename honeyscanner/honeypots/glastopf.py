from .base_honeypot import BaseHoneypot, Versions


class Glastopf(BaseHoneypot):
    def __init__(self,
                 version: str,
                 ip: str,
                 ports: set[int],
                 username: str | None = 'root',
                 password: str | None = '12345') -> None:
        """
        Initializes a new instance of the Glastopf Honeypot object.

        Args:
            version (str): The version of the Glastopf Honeypot.
            ip (str): The IP address of the Honeypot.
            port (int): The port number of the Honeypot.
            username (str, optional): The username to authenticate with.
                                      Defaults to 'root'.
            password (str, optional): The password to authenticate with.
                                      Defaults to '12345'.
        """
        if username is None:
            username = 'root'
        if password is None:
            password = '1234'
        super().__init__("glastopf", version, ip, ports, username, password)

    def _set_version(self, version: str) -> str:
        """
        Sets the version of the running Glastopf Honeypot

        Args:
            version (str): User inputted version number

        Returns:
            str: The version of the Cowire Honeypot
        """
        if version in ["3.0.0", "3.0.6", "3.0.7","3.0.8","3.1","3.1.1","3.1.2"]:
            return version

    def _set_source_code_url(self) -> str:
        """
        Sets the source code URL of the running Glastopf Honeypot

        Returns:
            str: The source code URL of the Glastopf Honeypot
        """
        return "https://github.com/mushorg/glastopf/archive/refs/tags"

    def _set_versions_list(self) -> Versions:
        """
        Sets the list of versions of the Glastopf Honeypot

        Returns:
            list[dict]: List of versions of the Glastopf Honeypot
        """
        return [
            {
                "version": "3.0.0",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/glastopf/refs/tags/3.0.0/requirements.txt",
            },
            {
                "version": "3.0.6",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/glastopf/refs/tags/3.0.6/requirements.txt",
            },
            {
                "version": "3.0.7",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/glastopf/refs/tags/3.0.7/requirements.txt",
            },
            {
                "version": "3.0.8",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/glastopf/refs/tags/3.0.8/requirements.txt",
            },
            {
                "version": "3.1",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/glastopf/refs/tags/3.1/requirements.txt",
            },
            {
                "version": "3.1.1",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/glastopf/refs/tags/3.1.1/requirements.txt",
            },
            {
                "version": "3.1.2",
                "requirements_url": "https://raw.githubusercontent.com/mushorg/glastopf/refs/tags/3.1.2/requirements.txt",
            }
        ]

    def _set_owner(self) -> str:
        """
        Sets the owner of the Glastopf Honeypot

        Returns:
            str: The owner of the Glastopf Honeypot
        """
        return "mushorg"
