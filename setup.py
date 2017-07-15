#/usr/bin/python
# pylint: disable=C0111,C0325,C0103,W0702
import os
import subprocess
import sys
import tempfile
from setuptools import setup


PACKAGE_READY = "is already installed"
PACKAGE_INSTALLED_SUCCESS = "is successfully installed"
PACKAGE_INSTALLED_FAILED = "installation failed"


def rootness():
    if os.geteuid() != 0:
        print('The programme must be run as root. Aborting')
        sys.exit(1)


def execute_shell_cmd(cmd):
    try:
        out = subprocess.check_output(cmd)
    except:
        return 1, ''
    return 0, out


def install_strongswan():
    rc, _ = execute_shell_cmd(['ipsec', '--version'])
    if rc != 0:
        rc, _ = execute_shell_cmd(
            ['apt-get', 'install', '-y', 'strongswan'])
        if rc == 0:
            cmd = ["echo", "\"1\"", ">", "/proc/sys/net/ipv4/ip_forward"]
            execute_shell_cmd(cmd)
            cmd = ["sed", "-i",
                   '/net.ipv4.ip_forward.*/d;$a\\net.ipv4.ip_forward " \
                  "= 1', "/etc/sysctl.conf"]
            execute_shell_cmd(cmd)
            print('strongswan {0}'.format(PACKAGE_INSTALLED_SUCCESS))
        else:
            print('strongswan {0}'.format(PACKAGE_INSTALLED_FAILED))
    else:
        print('strongswan {0}'.format(PACKAGE_READY))


def install_package():
    rootness()
    install_strongswan()


def copy_templates():
    subprocess.call(['mkdir', '-p', '/etc/slcli'])
    subprocess.call(['cp', 'templates', '/etc/slcli/', '-rf'])

def enable_autocompletion():
    line = r'''eval "$(_SL_COMPLETE=source sl)"'''
    bashrc = os.path.expanduser('~')+'/.bashrc'
    lines = []
    if os.path.exists(bashrc):
        with open(bashrc, 'r') as read_file:
            lines = read_file.readlines()
    for _line in lines:
        if line not in _line:
            continue
        return

    with open(bashrc, 'a+') as out_file:
        out_file.write('\n'+line+'\n')


install_package()
copy_templates()
enable_autocompletion()

setup(
    name='sl',
    version='0.1',
    py_modules=['sl'],
    install_requires=[
        'Click',
        'Jinja2',
        'pyyaml',
        'requests',
        'python-crontab',
    ],
    entry_points='''
        [console_scripts]
        sl=sl:gcli
    ''',
)
