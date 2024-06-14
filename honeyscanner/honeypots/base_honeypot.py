from typing import TypeAlias


Versions: TypeAlias = list[dict[str, str]]


class BaseHoneypot:
    _impl_err: str = "This method should be overridden in a subclass"

    def __init__(self,
                 name: str,
                 version: str,
                 ip: str,
                 port: int,
                 username: str,
                 password: str) -> None:
        """
        Initializes a new instance of the BaseHoneypot class.

        Args:
            name (str): Name of the Honeypot
            version (str): Version number of the Honeypot
            ip (str): IP address of the Honeypot
            port (int): Port number of the Honeypot
            username (str): Username to authenticate with
            password (str): Password to authenticate with
        """
        self.name: str = name
        self.ip: str = ip
        self.port: int = port
        self.username: str = username
        self.password: str = password
        self.version: str = self._set_version(version)
        self.owner: str = self._set_owner()
        self.source_code_url: str = self._set_source_code_url()
        self.versions_list: Versions = self._set_versions_list()

    def _set_version(self, version: str) -> str:
        return version

    def _set_owner(self) -> str:
        raise NotImplementedError(self._impl_err)

    def _set_source_code_url(self) -> str:
        raise NotImplementedError(self._impl_err)

    def _set_versions_list(self) -> Versions:
        raise NotImplementedError(self._impl_err)
