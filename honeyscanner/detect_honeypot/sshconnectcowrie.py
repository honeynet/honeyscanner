import paramiko


class SSHConnectCowrie:
    def __init__(self, ip, port, username, password):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.ssh = None
        self.channel = None

    def connect(self):
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(self.ip, port=self.port, username=self.username, password=self.password)
            self.channel = self.ssh.invoke_shell()
            print('Connected')
            print('Start scanning ...')
        except paramiko.BadHostKeyException as e:
            print(f"Server’s host key could not be verified: {e}")
        except paramiko.AuthenticationException:
            print('Authentication failed')
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

    def check_os_version(self):
        print('Checking OS version')
        end_marker = '~# '
        resp = self.execute_command('cat /proc/version', end_marker, ignore_first=True)
        version = resp.split('\n')[1].strip('\x1b[4l').strip('\r')
        default_version = 'Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3 (Debian 4.6.3-14) ) #1 SMP Debian 3.2.68-1+deb7u1'
        if version == default_version:
            print('[\033[92m+\033[00m] Found the same OS version')
        else:
            print('[\033[91m-\033[00m] OS version is different')

    def check_meminfo(self):
        print('Checking memory info')
        end_marker = '~# '
        resp = self.execute_command('cat /proc/meminfo', end_marker)
        memory = resp.split('\n')[2].strip('\r')
        default_memory = 'MemFree:          997740 kB'
        if memory == default_memory:
            print('[\033[92m+\033[00m] Found static memory information')
        else:
            print('[\033[91m-\033[00m] Memory is different than default value')

    def check_mounts(self):
        print('Checking mounts file')
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
        if mounts == default_mounts:
            print('[\033[92m+\033[00m] Found default mounted file systems')
        else:
            print('[\033[91m-\033[00m] Mounted file systems are different')

    def check_cpu(self):
        print('Checking CPU')
        end_marker = '~# '
        resp = self.execute_command('cat /proc/cpuinfo', end_marker)
        cpu = resp.split('\n')[5].strip('\r')
        default_cpu = 'model name\t: Intel(R) Core(TM)2 Duo CPU     E8200  @ 2.66GHz'
        if cpu == default_cpu:
            print('[\033[92m+\033[00m] Found default CPU')
        else:
            print('[\033[91m-\033[00m] CPUs are different')

    def check_group(self):
        print('Checking group')
        end_marker = '~# '
        resp = self.execute_command('cat /etc/group', end_marker)
        group = resp.split('\n')[-2].split(':')[0]
        default_group = 'phil'
        if group == default_group:
            print('[\033[92m+\033[00m] Found phil in group')
        else:
            print('[\033[91m-\033[00m] Didn\'t find phil in group')

    def check_shadow(self):
        print('Checking shadow file')
        end = '~# '
        resp = self.execute_command('cat /etc/shadow', end)
        default_user = 'phil'
        if default_user in resp:
            print('[\033[92m+\033[00m] Found user phil in shadow file')
        else:
            print('[\033[91m-\033[00m] Didn\'t find user phil in shadow file')

    def check_passwd(self):
        print('Checking passwd file')
        end = '~# '
        resp = self.execute_command('cat /etc/passwd', end)
        default_user = 'phil'
        if default_user in resp:
            print('[\033[92m+\033[00m] Found user phil in passwd file')
        else:
            print('[\033[91m-\033[00m] Didn\'t find user phil in passwd file')

    def check_hostname(self):
        print('Checking hostname')
        end_marker = '~# '
        resp = self.execute_command('hostname', end_marker)
        if 'svr04' in resp:
            print('[\033[92m+\033[00m] Found default hostname')
        else:
            print('[\033[91m-\033[00m] Didn\'t find default hostname')

    def close(self):
        if self.channel:
            self.channel.close()
        if self.ssh:
            self.ssh.close()