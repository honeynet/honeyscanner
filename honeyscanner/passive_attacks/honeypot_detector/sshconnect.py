import paramiko

from colorama import Fore


class SSHConnect:
    def __init__(
            self,
            ip: str,
            port: int,
            username: str,
            password: str
            ) -> None:
        """
        Initializes a new SSHConnect object.

        Args:
            ip (str): The IP address of the Honeypot.
            port (int): The port number of the Honeypot.
            username (str): The username to authenticate with.
            password (str): The password to authenticate with.
        """
        self.ip = ip
        self.port = port
        if username:
            self.username = username
        else:
            self.username = "root"
        if password:
            self.password = password
        else:
            self.password: str = "1234"
        self.ssh: paramiko.SSHClient
        self.channel: paramiko.Channel

    def connect(self):
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(self.ip,
                             port=self.port,
                             username=self.username,
                             password=self.password)
            self.channel = self.ssh.invoke_shell()
        except paramiko.BadHostKeyException as e:
            print(f"Server’s host key could not be verified: {e}")
        except paramiko.AuthenticationException:
            print("Authentication failed")
        except paramiko.SSHException as e:
            print(f"Can't establish SSH connection: {e}")
        except Exception as e:
            print(f"Error: {e}")

    def execute_command(self, cmd, end_marker, ignore_first=False):
        buffer = ''
        self.channel.send(cmd + '\n')
        first = True
        while True:
            resp = self.channel.recv(9999).decode('utf-8')
            buffer += resp
            if ignore_first and first:
                if buffer.endswith(end_marker):
                    buffer = ''
                    first = False
            else:
                if buffer.endswith(end_marker):
                    break
        return buffer

    def close(self):
        """
        Closes the SSH connection.
        """
        if self.channel:
            self.channel.close()
        if self.ssh:
            self.ssh.close()


class CowrieInteract(SSHConnect):

    def __init__(
            self,
            ip: str,
            port: int,
            username: str,
            password: str
            ) -> None:
        """
        Initializes a new CowrieInteract object.

        Args:
            ip (str): The IP address of the Honeypot.
            port (int): The port number of the Honeypot.
            username (str): The username to authenticate with.
            password (str): The password to authenticate with.
        """
        super().__init__(ip, port, username, password)

    def ssh_signatures(self) -> bool:
        """
        Checks Cowrie instance for more signatures.

        Returns:
            bool: True if the confidence is high or medium, False if the
                  confidence is low.
        """
        print(f"\t{Fore.YELLOW}[~]{Fore.RESET} Connecting to Cowrie instance")
        self.connect()
        print(f"\t{Fore.GREEN}[+]{Fore.RESET} Connected to Cowrie instance")
        curr_confidence: str = "low"
        max_score: int = 8
        confidence_score: int = 0

        print(f"\t{Fore.GREEN}[+]{Fore.RESET} Checking SSH service for more "
              f"Cowrie signatures")
        for check_func in [self.check_os_version,
                           self.check_meminfo,
                           self.check_mounts,
                           self.check_cpu,
                           self.check_group,
                           self.check_hostname,
                           self.check_shadow,
                           self.check_passwd]:
            if check_func():
                confidence_score += 1

        if confidence_score == max_score:
            curr_confidence = "high"
        elif confidence_score >= (max_score // 2):
            curr_confidence = "medium"
        else:
            curr_confidence = "low"
        print(f"\t{Fore.YELLOW}[~]{Fore.RESET} Closing Cowrie instance")
        self.close()
        print(f"\t{Fore.GREEN}[+]{Fore.RESET} Cowrie Instance closed")
        print(f"\t{Fore.CYAN}[@]{Fore.RESET} Cowrie Instance Confidence: {curr_confidence}")
        if curr_confidence == "low":
            return False
        return True

    def check_os_version(self) -> bool:
        print(f"\t{Fore.YELLOW}[~]{Fore.RESET} Checking OS version")
        end_marker = '~# '
        resp = self.execute_command('cat /proc/version', end_marker, ignore_first=True)
        version = resp.split('\n')[1].strip('\x1b[4l').strip('\r')
        default_version = 'Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3 (Debian 4.6.3-14) ) #1 SMP Debian 3.2.68-1+deb7u1'
        return version == default_version

    def check_meminfo(self) -> bool:
        print(f"\t{Fore.YELLOW}[~]{Fore.RESET} Checking memory info")
        end_marker = '~# '
        resp = self.execute_command('cat /proc/meminfo', end_marker)
        memory = resp.split('\n')[2].strip('\r')
        default_memory = 'MemFree:          997740 kB'
        return memory == default_memory

    def check_mounts(self) -> bool:
        print(f"\t{Fore.YELLOW}[~]{Fore.RESET} Checking mounts file")
        end_marker = '~# '
        resp = self.execute_command('cat /proc/mounts', end_marker)
        mounts = '\n'.join(resp.split('\n')[1:-1]).strip('\x1b[4l').replace('\r', '')
        default_mounts = """rootfs / rootfs rw 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,relatime 0 0
udev /dev devtmpfs rw,relatime,size=10240k,nr_inodes=997843,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,relatime,size=1613336k,mode=755 0 0
/dev/dm-0 / ext3 rw,relatime,errors=remount-ro,data=ordered 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=22,pgrp=1,timeout=300,minproto=5,maxproto=5,direct 0 0
fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0
/dev/sda1 /boot ext2 rw,relatime 0 0
/dev/mapper/home /home ext3 rw,relatime,data=ordered 0 0
binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw,relatime 0 0"""
        default_mounts = default_mounts.replace('    ', '')
        return mounts == default_mounts

    def check_cpu(self) -> bool:
        print(f"\t{Fore.YELLOW}[~]{Fore.RESET} Checking CPU info")
        end_marker = '~# '
        resp = self.execute_command('cat /proc/cpuinfo', end_marker)
        cpu = resp.split('\n')[5].strip('\r')
        default_cpu = 'model name\t: Intel(R) Core(TM)2 Duo CPU     E8200  @ 2.66GHz'
        return cpu == default_cpu

    def check_group(self) -> bool:
        print(f"\t{Fore.YELLOW}[~]{Fore.RESET} Checking group info")
        end_marker = '~# '
        resp = self.execute_command('cat /etc/group', end_marker)
        group = resp.split('\n')[-2].split(':')[0]
        default_group = 'phil'
        return group == default_group

    def check_shadow(self) -> bool:
        print(f"\t{Fore.YELLOW}[~]{Fore.RESET} Checking shadow file")
        end = '~# '
        resp = self.execute_command('cat /etc/shadow', end)
        default_user = 'phil'
        return default_user in resp

    def check_passwd(self) -> bool:
        print(f"\t{Fore.YELLOW}[~]{Fore.RESET} Checking passwd file")
        end = '~# '
        resp = self.execute_command('cat /etc/passwd', end)
        default_user = 'phil'
        return default_user in resp

    def check_hostname(self) -> bool:
        print(f"\t{Fore.YELLOW}[~]{Fore.RESET} Checking hostname")
        end_marker = '~# '
        resp = self.execute_command('hostname', end_marker)
        return 'svr04' in resp
