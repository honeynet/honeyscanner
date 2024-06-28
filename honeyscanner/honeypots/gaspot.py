from .base_honeypot import BaseHoneypot, Versions


class GasPot(BaseHoneypot):
    def __init__(self,
                 version: str,
                 ip: str,
                 port: int,
                 username: str | None = 'root',
                 password: str | None = '12345') -> None:
        """
        Initializes a new instance of the GasPot Honeypot object.

        Args:
            version (str): The version of the GasPot Honeypot.
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
            password = '12345'
        super().__init__("gaspot", version, ip, port, username, password)

    def _set_version(self, version: str) -> str:
        """
        Sets the version of the running GasPot Honeypot

        Args:
            version (str): User inputted version number

        Returns:
            str: The version of the GasPot Honeypot
        """
        # Validate version against supported versions
        supported_versions = ["0.1.0"]
        if version in supported_versions:
            return version
        else:
            return 'v' + version  # Default to this format if not in supported list

    def _set_source_code_url(self) -> str:
        """
        Sets the source code URL of the running GasPot Honeypot

        Returns:
            str: The source code URL of the GasPot Honeypot
        """
        return "file:///home/kali/honeyscanner/honeyscanner/GasPot"

    def _set_versions_list(self) -> Versions:
        """
        Sets the list of versions of the GasPot Honeypot

        Returns:
            list[dict]: List of versions of the GasPot Honeypot
        """
        return [
            {
                "version": "0.1.0",
                "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/1.5.1/requirements.txt",
                "dependencies": [
                    "Flask==2.0.1",
                    "requests==2.26.0",
                    "peewee==3.14.4",
                    "six==1.16.0",
                    "beautifulsoup4==4.10.0",
                    "datetime==4.3",
                    "configparser==6.4.0",
                    "argparse==1.4.0",
                    "pytz==2021.3"
                ],
            }
        ]

    def _set_owner(self) -> str:
        """
        Sets the owner of the GasPot Honeypot

        Returns:
            str: The owner of the GasPot Honeypot
        """
        return "sjhilt"
