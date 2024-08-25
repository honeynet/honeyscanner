from .base_honeypot import BaseHoneypot, Versions


class Cowrie(BaseHoneypot):
    def __init__(self,
                 version: str,
                 ip: str,
                 ports: set[int],
                 username: str | None = 'root',
                 password: str | None = '12345') -> None:
        """
        Initializes a new instance of the Cowrie Honeypot object.

        Args:
            version (str): The version of the Cowrie Honeypot.
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
        super().__init__("cowrie", version, ip, ports, username, password)

    def _set_version(self, version: str) -> str:
        """
        Sets the version of the running Cowire Honeypot

        Args:
            version (str): User inputted version number

        Returns:
            str: The version of the Cowire Honeypot
        """
        if version in ["2.1.0", "2.4.0", "2.5.0"]:
            return 'v' + version
        else:
            return version

    def _set_source_code_url(self) -> str:
        """
        Sets the source code URL of the running Cowire Honeypot

        Returns:
            str: The source code URL of the Cowire Honeypot
        """
        return "https://github.com/cowrie/cowrie/archive/refs/tags"

    def _set_versions_list(self) -> Versions:
        """
        Sets the list of versions of the Cowire Honeypot

        Returns:
            list[dict]: List of versions of the Cowire Honeypot
        """
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

    def _set_owner(self) -> str:
        """
        Sets the owner of the Cowire Honeypot

        Returns:
            str: The owner of the Cowire Honeypot
        """
        return "cowrie"
