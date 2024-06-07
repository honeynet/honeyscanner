from .base_honeypot import BaseHoneypot


class Dionaea(BaseHoneypot):
    def __init__(self, version, ip, port, username='', password=''):
        # Dionaea does not have a default username and password
        if username is None:
            username = ''
        if password is None:
            password = ''
        super().__init__("dionaea", version, ip, port, username, password)

    def set_source_code_url(self):
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
    def set_versions_list(self):
        return [
            {
                "version": "0.11.0",
                "requirements_url": "https://raw.githubusercontent.com/aristofanischionis/DinoTools-dionaea/main/requirements.txt",
            }
        ]

    def set_owner(self):
        return "DinoTools"
