class Vulnerability:
    def __init__(
        self,
        name,
        installed_version,
        affected_versions,
        cve=None,
        vulnerability_id=None,
        advisory=None,
        poc_url=None,
        cvss_score=None
    ):
        self.name = name
        self.installed_version = installed_version
        self.affected_versions = affected_versions
        self.cve = cve
        self.vulnerability_id = vulnerability_id
        self.advisory = advisory
        self.poc_url = poc_url
        self.cvss_score = cvss_score

    def to_dict(self):
        return {
            "name": self.name,
            "installed_version": self.installed_version,
            "affected_versions": self.affected_versions,
            "cve": self.cve,
            "vulnerability_id": self.vulnerability_id,
            "advisory": self.advisory,
            "poc_url": self.poc_url,
            "cvss_score": self.cvss_score
        }
