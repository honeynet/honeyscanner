from .base_honeypot import BaseHoneypot, Versions


class Dionaea(BaseHoneypot):
    def __init__(self,
                 version: str,
                 ip: str,
                 port: int,
                 username: str | None = '',
                 password: str | None = '') -> None:
        """
        Initializes a new instance of the Dionaea Honeypot object.

        Args:
            version (str): The version of the Dionaea Honeypot.
            ip (str): The IP address of the Honeypot.
            port (int): The port number of the Honeypot.
            username (str, optional): The username to authenticate with.
                                      Defaults to ''.
            password (str, optional): The password to authenticate with.
                                      Defaults to ''.
        """
        # Dionaea does not have a default username and password
        if username is None:
            username = ''
        if password is None:
            password = ''
        super().__init__("dionaea", version, ip, port, username, password)

    def _set_source_code_url(self) -> str:
        """
        Sets the source code URL of the running Dionaea Honeypot

        Returns:
            str: The source code URL of the Dionaea Honeypot
        """
        return "https://github.com/DinoTools/dionaea/archive/refs/tags"

    """
    I manually inspected the Dockerfile provided from T-pot
    (https://github.com/telekom-security/tpotce/blob/master/docker/dionaea/Dockerfile)
    and I found all the python3 dependencies, then I inspected the date of
    the last release tag 30 Nov 2020 I could manually create the
    requirements file for all the versions, it could change just the
    packages version. But as there only 3 packages I figured out that is
    probably not worth the time.
    """
    def _set_versions_list(self) -> Versions:
        """
        Sets the list of versions of the Dionaea Honeypot

        Returns:
            list[dict]: List of versions of the Dionaea Honeypot
        """
        return [
            {
                "version": "0.11.0",
                "requirements_url": "https://raw.githubusercontent.com/aristofanischionis/DinoTools-dionaea/main/requirements.txt",
            }
        ]

    def _set_owner(self) -> str:
        """
        Sets the owner of the Dionaea Honeypot

        Returns:
            str: The owner of the Dionaea Honeypot
        """
        return "DinoTools"
