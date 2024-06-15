from typing import TypeAlias


class Vulnerability:
    VulnDict: TypeAlias = dict[str, str | float | None]

    def __init__(self,
                 name: str,
                 installed_version: str,
                 affected_versions: str,
                 cve: str | None = None,
                 vulnerability_id: str | None = None,
                 advisory: str | None = None,
                 cvss_score: float | None = None) -> None:
        """
        Initializes the Vulnerability class.

        Args:
            name (str): Name of the vulnerable
            installed_version (str): Installed version of the vulnerable
                                     package/library
            affected_versions (str): Affected versions of the
                                     vulnerable package/library
            cve (str | None, optional): CVE ID of the vulnerability.
                                        Defaults to None.
            vulnerability_id (str | None, optional): Vulnerability ID of
                                                     the vulnerability.
                                                     Defaults to None.
            advisory (str | None, optional): Advisory towards patching
                                             the vulnerability.Defaults to
                                             None.
            cvss_score (float | None, optional): CVSS score of the
                                                 vulnerability. Defaults to
                                                 None.
        """
        self.name = name
        self.installed_version = installed_version
        self.affected_versions = affected_versions
        self.cve = cve
        self.vulnerability_id = vulnerability_id
        self.advisory = advisory
        self.cvss_score = cvss_score

    def to_dict(self) -> VulnDict:
        """
        Returns the Vulnerability object attributes as a dictionary.

        Returns:
            VulnDict: Vulnerability object attributes as a dictionary.
        """
        return {
            "name": self.name,
            "installed_version": self.installed_version,
            "affected_versions": self.affected_versions,
            "cve": self.cve,
            "vulnerability_id": self.vulnerability_id,
            "advisory": self.advisory,
            "cvss_score": self.cvss_score
        }
