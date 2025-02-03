from .base_honeypot import BaseHoneypot, Versions


class Conpot(BaseHoneypot):
    def __init__(self,
                 version: str,
                 ip: str,
                 ports: set[int],
                 username: str | None = '',
                 password: str | None = '') -> None:
        """
        Initializes a new instance of the Conpot Honeypot object.

        Args:
            version (str): The version of the Conpot Honeypot.
            ip (str): The IP address of the Honeypot.
            port (int): The port number of the Honeypot.
            username (str, optional): The username to authenticate with.
                                      Defaults to ''.
            password (str, optional): The password to authenticate with.
                                      Defaults to ''.
        """
        if username is None:
            username = ''
        if password is None:
            password = ''
        super().__init__("conpot", version, ip, ports, username, password)

    def _set_source_code_url(self) -> str:
        """
        Sets the source code URL of the running Conpot Honeypot

        Returns:
            str: The source code URL of the Conpot Honeypot
        """
        return "https://github.com/mushorg/conpot/archive/refs/tags"

    def _set_versions_list(self) -> Versions:
        """
        Sets the list of versions of the Conpot Honeypot

        Returns:
            list[dict]: List of versions of the Conpot Honeypot
        """
        version_list = super().get_requirements('mushorg/conpot')
        return version_list

    def _set_owner(self) -> str:
        """
        Sets the owner of the Conpot Honeypot

        Returns:
            str: The owner of the Conpot Honeypot
        """
        return "mushorg"
