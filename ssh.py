# https://blog.secursive.com/posts/verifying-ssh-host-key-fingerprint/
# Retrieving SSH host key and verifying SSH host key using Paramiko

import paramiko
import hashlib
import base64
import getpass

HOST = '10.0.0.1'
USER = 'root'
PASSWORD = getpass.getpass("Enter password for {}@{}: ".format(USER, HOST))


class HostKeyInfo():
    def __init__(self, base64key):
        self.base64key = base64key

    def getBase64Key(self):
        return self.base64key

    def getFingerprint(self):
        return self.getSHA256Fingerprint()

    def getMD5Fingerprint(self):
        return hashlib.md5(base64.b64decode(hostkey)).hexdigest().upper()

    def getSHA1Fingerprint(self):
        return hashlib.sha1(base64.b64decode(hostkey)).hexdigest().upper()

    def getSHA256Fingerprint(self):
        return hashlib.sha256(base64.b64decode(hostkey)).hexdigest().upper()


class VerifyHostKeyPolicy(paramiko.client.MissingHostKeyPolicy):
    def __init__(self, hostkey):
        self.hostkey = hostkey

    def missing_host_key(self, client, hostname, key):
        if key.get_base64() != self.hostkey.getBase64Key():
            raise paramiko.ssh_exception.SSHException("Invalid Host Key Fingerprint")


def retrieveHostKey(host):
    try:
        client.connect(host)
    except:
        pass
    key = client.get_transport().get_remote_server_key().get_base64()
    client.close()
    return key


def connectWithHostKey(host, user, password, hostkey):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(VerifyHostKeyPolicy(HostKeyInfo(hostkey)))
    client.connect(host, username=user, password=password)
    return client


if __name__ == '__main__':
    hostkey = retrieveHostKey(HOST)
    hostkeyinfo = HostKeyInfo(hostkey)
    print('Host Key: {}'.format(hostkeyinfo.getBase64Key()))
    print('Host Key MD5 fingerprint: {}'.format(hostkeyinfo.getMD5Fingerprint()))
    print('Host Key SHA1 fingerprint: {}'.format(hostkeyinfo.getSHA1Fingerprint()))
    print('Host Key SHA256 fingerprint: {}'.format(hostkeyinfo.getSHA256Fingerprint()))
    if str(input('Connect? (y/n): ')).lower().strip().startswith('y'):
        client = connectWithHostKey(HOST, USER, PASSWORD, hostkey)
        stdin, stdout, stderr = client.exec_command('ls -l')
        print("Output:\n{}".format(stdout.read()))
        client.close()
