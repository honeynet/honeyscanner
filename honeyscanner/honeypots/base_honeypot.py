from typing import TypeAlias
import requests

Versions: TypeAlias = list[dict[str, str]]


class BaseHoneypot:
    _impl_err: str = "This method should be overridden in a subclass"

    def __init__(self,
                 name: str,
                 version: str,
                 ip: str,
                 ports: set[int],
                 username: str,
                 password: str) -> None:
        """
        Initializes a new instance of the BaseHoneypot class.

        Args:
            name (str): Name of the Honeypot
            version (str): Version number of the Honeypot
            ip (str): IP address of the Honeypot
            ports (set[int]): Set of ports to run a DoS against
            username (str): Username to authenticate with
            password (str): Password to authenticate with
        """
        self.name = name
        self.ip = ip
        self.ports = ports
        self.username = username
        self.password = password
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
    
    def get_requirements(self,repo):
        #repos = ['cowrie/cowrie','mushorg/conpot','DinoTools/dionaea','desaster/kippo']
        headers = {
            "X-GitHub-Api-Version": "2022-11-28",
            "Accept": "application/vnd.github.v3+json"
        }
        response_ver = requests.get(f'https://api.github.com/repos/{repo}/tags',headers=headers).json()

        versions = []
        for el in response_ver:
            versions.append(el["name"])

        return_data = []
        for version in versions:
            data = {
                "version" :'',
                "requirements_url" : ''
            }
            data["version"] = version
            data["requirements_url"] = f'https://raw.githubusercontent.com/{repo}/{version}/requirements.txt'

            return_data.append(data)
        
        return return_data
