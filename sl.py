#!/usr/bin/python
# pylint: disable=C0111,C0103,C0302,C1801,W0622,W0702
import subprocess
import json
import os
import socket
import copy
import click
from jinja2 import Environment, FileSystemLoader

DEV_PRIVATE = 'eth0'
DEV_PUBLIC = 'eth1'
CONF_FILE = '/etc/slcli/config.json'
RUNNING_FILE = '/etc/slcli/running.json'
TEMPLATE_PATH = '/etc/slcli/templates'

CONF_DIR = '/etc/slcli'

dict_map = {'bi-directional': 'start', 'response-only': 'add',
            'group2': 'modp1024', 'group5': 'modp1536',
            'group14': 'modp2048'}

def cmd_exec(*popenargs, **kwargs):
    try:
        output = subprocess.check_output(stderr=subprocess.STDOUT, *popenargs, **kwargs)
        return 0, output
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output


#phase2 functionality
def validate_ip_addr(addr):
    try:
        socket.inet_aton(addr)
        q = addr.split('.')
        if len(q) != 4:
            return False
        return True
    except socket.error:
        return False

def validate_ip_prefix(cidr):
    net = cidr.split('/')
    if len(net) != 2:
        return False
    prefix = int(net[1])
    if prefix < 0 or prefix > 32:
        return False
    addr = net[0]
    try:
        socket.inet_aton(addr)
        q = addr.split('.')
        if len(q) != 4:
            return False
        return True
    except socket.error:
        return False

class BasedIPv4ParamType(click.ParamType):
    name = 'ipaddr'

    def convert(self, value, param, ctx):
        if not validate_ip_addr(value):
            self.fail('%s is not a valid ip address' % value, param, ctx)
        return value

IPv4 = BasedIPv4ParamType()

class BasedIPv4CidrListParamType(click.ParamType):
    name = 'cidrlist'

    def convert(self, value, param, ctx):
        iplist = value.strip(',').split(',')
        for ip in iplist:
            if not validate_ip_prefix(ip):
                self.fail('%s is not a valid CIDR list' % value)
        return value.strip(',')

IPv4CidrList = BasedIPv4CidrListParamType()

def getcfg(cfg, key, dfv):
    val = cfg.get(key, dfv)
    if not val:
        cfg[key] = dfv
    return cfg[key]

def get_local_ip(dev=DEV_PRIVATE):
    _, out = cmd_exec(['ip', 'add', 'show', dev])
    lines = out.split('\n')
    line = lines[2].strip()
    ipadd = line.split()[1].split('/')[0]
    return ipadd

def splitby(value, separator):
    return value.split(separator)

def get_template(filename):
    env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                      trim_blocks=True, lstrip_blocks=True)
    env.filters['splitby'] = splitby
    template = env.get_template(filename)
    return template

def generate_config(tpl, cfg):
    template = get_template(tpl)
    content = template.render(cfg=cfg)

    files = {'ipsec.conf.tpl': '/etc/ipsec.conf',
             'ipsec.secrets.tpl': '/etc/ipsec.secrets'}
    dest = files[tpl]
    with open(dest, 'w') as out_file:
        out_file.write(content)

def read_config(filename=CONF_FILE):
    if not os.path.exists(filename):
        return {}
    with open(filename) as conf_file:
        try:
            data = json.load(conf_file)
        except ValueError:
            data = {}

    return data

def write_config(cfg):
    with open(CONF_FILE, 'w') as out_file:
        json.dump(cfg, out_file, indent=4, sort_keys=True)


def ensure_config(cfg):
    ipsec = getcfg(cfg, 'ipsec', {})
    getcfg(ipsec, 'connections', [])

    return True

def restart_service():
    cmd_exec(['ipsec', 'restart'])

def save_running_config():
    cmd_exec(['cp', CONF_FILE, RUNNING_FILE])

def do_commit():
    ipadd = get_local_ip()
    cfg = read_config()
    cfg['ipadd'] = ipadd
    if not ensure_config(cfg):
        return
    write_config(cfg)

    generate_config('ipsec.conf.tpl', cfg)
    generate_config('ipsec.secrets.tpl', cfg)

    restart_service()
    save_running_config()

def find_ikepolicy(ikepolicy):
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    ikes = getcfg(ipsec, 'ikes', [])
    for ike in ikes:
        if ike['name'] == ikepolicy:
            return copy.deepcopy(ike)
    return None

def find_ipsecpolicy(ipsecpolicy):
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    ipsecs = getcfg(ipsec, 'ipsecs', [])
    for _ipsec in ipsecs:
        if _ipsec['name'] == ipsecpolicy:
            return copy.deepcopy(_ipsec)
    return None

def find_site_connection(connection_name):
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    connections = getcfg(ipsec, 'connections', [])
    for conn in connections:
        if conn['name'] == connection_name:
            return copy.deepcopy(conn)
    return None

def is_ikepolicy_in_use(ikepolicy):
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    connections = getcfg(ipsec, 'connections', [])
    for conn in connections:
        if conn['_ikepolicy'] == ikepolicy:
            return True
    return False

def is_ipsecpolicy_in_use(ipsecpolicy):
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    connections = getcfg(ipsec, 'connections', [])
    for conn in connections:
        if conn['_ipsecpolicy'] == ipsecpolicy:
            return True
    return False

def to_output(filename):
    out = ''
    cfg = read_config(filename)

    ipsec = getcfg(cfg, 'ipsec', {})
    if ipsec:
        connections = getcfg(ipsec, 'connections', [])
        if connections:
            out += 'Site Connection Configuration:\n'
        for conn in connections:
            out += '  Connection Name: %s\n' % conn['name']
            out += '  initiator: %s\n' % conn['initiator']
            out += '  admin state down: %s\n' % conn['admin_state_down']
            out += '  dpd action: %s\n' % conn['dpd_action']
            out += '  dpd interval: %s(sec)\n' % conn['dpd_interval']
            out += '  dpd timeout: %s(sec)\n' % conn['dpd_timeout']
            out += '  local cidrs: %s\n' % conn['local_cidrs']
            out += '  peer id: %s\n' % conn['peer_id']
            out += '  peer address: %s\n' % conn['peer_addr']
            out += '  peer cidrs: %s\n' % conn['peer_cidrs']
            out += '  PSK: %s\n' % conn['psk']
            out += '  IKE Policy:\n'
            out += '    auth algorithm: %s\n' % conn['ikepolicy']['auth_algorithm']
            out += '    encryption algorithm: %s\n' % conn['ikepolicy']['encryption_algorithm']
            out += '    ike lifetime: %d(sec)\n' % conn['ikepolicy']['ike_lifetime']
            out += '    ike version: %s\n' % conn['ikepolicy']['ike_version']
            out += '    pfs: %s\n' % conn['ikepolicy']['_pfs']
            out += '  IPSec Policy:\n'
            out += '    auth algorithm: %s\n' % conn['ipsecpolicy']['auth_algorithm']
            out += '    encryption algorithm: %s\n' % conn['ipsecpolicy']['encryption_algorithm']
            out += '    ipsec lifetime: %d(sec)\n' % conn['ipsecpolicy']['ipsec_lifetime']
            out += '    encapsulation mode: %s\n' % conn['ipsecpolicy']['encapsulation_mode']
            out += '    transform protocol: %s\n' % conn['ipsecpolicy']['transform_protocol']
            out += '    pfs: %s\n' % conn['ipsecpolicy']['_pfs']
            out += '\n'
        if not connections:
            out += '\n'

        ikes = getcfg(ipsec, 'ikes', [])
        if ikes:
            out += 'IKE Policy Configuration:\n'
        for ike in ikes:
            out += '  IKE Name: %s\n' % ike['name']
            out += '  auth algorithm: %s\n' % ike['auth_algorithm']
            out += '  encryption algorithm: %s\n' % ike['encryption_algorithm']
            out += '  ike lifetime: %d(sec)\n' % ike['ike_lifetime']
            out += '  ike version: %s\n' % ike['ike_version']
            out += '  pfs: %s\n' % ike['pfs']
            out += '\n'

        ipsecs = getcfg(ipsec, 'ipsecs', [])
        if ipsecs:
            out += 'IPSec Policy Configuration:\n'
        for _ipsec in ipsecs:
            out += '  IPSec Name: %s\n' % _ipsec['name']
            out += '  auth algorithm: %s\n' % _ipsec['auth_algorithm']
            out += '  encryption algorithm: %s\n' % _ipsec['encryption_algorithm']
            out += '  ipsec lifetime: %d(sec)\n' % _ipsec['ipsec_lifetime']
            out += '  encapsulation mode: %s\n' % _ipsec['encapsulation_mode']
            out += '  transform protocol: %s\n' % _ipsec['transform_protocol']
            out += '  pfs: %s\n' % _ipsec['pfs']
            out += '\n'
    return out

@click.group()
def gcli():
    pass

@gcli.command(name='commit-all')
def commit_all():
    """Commit all the changes"""
    do_commit()
    click.echo('Commit Success.')

#Ipsec commands
@gcli.command(name='vpn-ikepolicy-create')
@click.option('--auth-algorithm',
              default='sha1', show_default=True,
              type=click.Choice(['sha1', 'sha256', 'sha384', 'sha512']),
              help='Authentication algorithm')
@click.option('--encryption-algorithm',
              default='aes128', show_default=True,
              type=click.Choice(['3des', 'aes128', 'aes192', 'aes256']),
              help='Encryption algorithm')
@click.option('--ike-version',
              default='ikev1', show_default=True,
              type=click.Choice(['ikev1', 'ikev2']),
              help='Version number of IKE')
@click.option('--pfs',
              default='group2', show_default=True,
              type=click.Choice(['group2', 'group5', 'group14']),
              help='Perfect Forward Secrecy')
@click.option('--ike-lifetime', type=int, default=10800, show_default=True,
              help='IKE lifetime in seconds')
@click.argument('name')
def create_vpn_ikepolicy(auth_algorithm, encryption_algorithm,
                         ike_version, pfs, ike_lifetime, name):
    """Create IKE Policy"""
    item = {'name': name, 'auth_algorithm': auth_algorithm,
            'encryption_algorithm': encryption_algorithm, 'ike_version': ike_version,
            'pfs': pfs, 'ike_lifetime': ike_lifetime}
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    ikes = getcfg(ipsec, 'ikes', [])
    names = [ike['name'] for ike in ikes]
    if name in names:
        click.echo('%s is used, choose another name.' % name)
        return
    ikes.append(item)
    write_config(cfg)

@gcli.command(name='vpn-ikepolicy-delete')
@click.argument('name')
def delete_vpn_ikepolicy(name):
    """Delete IKE Policy"""
    if is_ikepolicy_in_use(name):
        click.echo('IKE Policy %s is in use' % name)
        return
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    ikes = getcfg(ipsec, 'ikes', [])

    for ike in ikes:
        if ike['name'] != name:
            continue
        ikes.remove(ike)
        break
    write_config(cfg)

@gcli.command(name='vpn-ipsecpolicy-create')
@click.option('--auth-algorithm',
              default='sha1', show_default=True,
              type=click.Choice(['sha1', 'sha256', 'sha384', 'sha512']),
              help='Authentication algorithm')
@click.option('--encryption-algorithm',
              default='aes128', show_default=True,
              type=click.Choice(['3des', 'aes128', 'aes192', 'aes256']),
              help='Encryption algorithm')
@click.option('--encapsulation-mode',
              default='tunnel', show_default=True,
              type=click.Choice(['tunnel', 'transport']),
              help='Type of connection')
@click.option('--ipsec-lifetime', type=int, default=3600, show_default=True,
              help='IPSec lifetime in seconds')
@click.option('--transform-protocol', default='esp', show_default=True,
              type=click.Choice(['esp', 'ah']),
              help='Transform protocol for IPSec policy')
@click.option('--pfs',
              default='group2', show_default=True,
              type=click.Choice(['group2', 'group5', 'group14']),
              help='Perfect Forward Secrecy')
@click.argument('name')
def create_vpn_ipsecpolicy(auth_algorithm, encryption_algorithm,
                           encapsulation_mode, ipsec_lifetime, transform_protocol, pfs, name):
    """Create IPSec Policy"""
    item = {'name': name, 'auth_algorithm': auth_algorithm,
            'encryption_algorithm': encryption_algorithm,
            'encapsulation_mode': encapsulation_mode, 'ipsec_lifetime': ipsec_lifetime,
            'transform_protocol': transform_protocol, 'pfs': pfs}
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    ipsecs = getcfg(ipsec, 'ipsecs', [])
    names = [_ipsec['name'] for _ipsec in ipsecs]
    if name in names:
        click.echo('%s is used, choose another name.' % name)
        return
    ipsecs.append(item)
    write_config(cfg)

@gcli.command(name='vpn-ipsecpolicy-delete')
@click.argument('name')
def delete_vpn_ipsecpolicy(name):
    """Delete IPSec Policy"""
    if is_ipsecpolicy_in_use(name):
        click.echo('IPSec Policy %s is in use' % name)
        return
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    ipsecs = getcfg(ipsec, 'ipsecs', [])

    for _ipsec in ipsecs:
        if _ipsec['name'] != name:
            continue
        ipsecs.remove(_ipsec)
        break
    write_config(cfg)

@gcli.command(name='ipsec-site-connection-create')
@click.option('--admin-state-down',
              is_flag=True,
              help='Set admin state up to false')
@click.option('--ikepolicy', help='IKE policy name')
@click.option('--ipsecpolicy', help='IPSec policy name')
@click.option('--dpd-action',
              default='hold', show_default=True,
              type=click.Choice(['hold', 'clear', 'disabled', 'restart', 'restart-by-peer']),
              help='DPD action')
@click.option('--dpd-interval',
              default=30, show_default=True,
              type=int,
              help='DPD interval in seconds')
@click.option('--dpd-timeout',
              default=120, show_default=True,
              type=int,
              help='DPD timeout in seconds')
@click.option('--local-cidrs', type=IPv4CidrList, help='Local CIDRs separate by comma')
@click.option('--peer-cidrs', type=IPv4CidrList, help='Peer CIDRs separate by comma')
@click.option('--peer-id', help='Peer router identity for authentication')
@click.option('--peer-addr', type=IPv4, help='Peer gateway public IPv4')
@click.option('--psk', help='Pre-shared key string')
@click.option('--initiator',
              default='bi-directional', show_default=True,
              type=click.Choice(['bi-directional', 'response-only']),
              help='Initiator state in lowercase')
@click.argument('name')
def create_ipsec_site_connection(admin_state_down, ikepolicy, ipsecpolicy, dpd_action,
                                 dpd_interval, dpd_timeout, local_cidrs, peer_cidrs,
                                 peer_id, peer_addr, psk, initiator, name):
    """Create IPSec connection"""
    if not (ikepolicy and ipsecpolicy and local_cidrs
            and peer_cidrs and peer_id and peer_addr and psk):
        click.echo('--ikepolicy --ipsecpolicy --local-cidrs '
                   '--peer-cidrs --peer-id --peer-addr --psk are required')
        return
    ike = find_ikepolicy(ikepolicy)
    if not ike:
        click.echo('IKE policy %s not found' % ikepolicy)
        return
    _ipsec = find_ipsecpolicy(ipsecpolicy)
    if not _ipsec:
        click.echo('IPSec policy %s not found' % ipsecpolicy)
        return
    local_id = get_local_ip(DEV_PUBLIC)
    ike['_pfs'] = ike['pfs']
    ike['pfs'] = dict_map[ike['pfs']]
    _ipsec['_pfs'] = _ipsec['pfs']
    _ipsec['pfs'] = dict_map[_ipsec['pfs']]

    item = {'admin_state_down': admin_state_down, 'ikepolicy': ike,
            'ipsecpolicy': _ipsec, 'dpd_action': dpd_action, 'dpd_interval': dpd_interval,
            'dpd_timeout': dpd_timeout, 'local_cidrs': local_cidrs,
            'peer_cidrs': peer_cidrs, 'peer_id': peer_id, 'peer_addr': peer_addr,
            'psk': psk, 'initiator': dict_map[initiator], 'name': name,
            '_ikepolicy': ikepolicy, '_ipsecpolicy': ipsecpolicy,
            '_initiator': initiator, 'local_id': local_id}
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    conns = getcfg(ipsec, 'connections', [])
    names = [conn['name'] for conn in conns]
    if name in names:
        click.echo('Connection name %s is used, choose another name' % name)
        return
    conns.append(item)
    write_config(cfg)

@gcli.command(name='ipsec-site-connection-delete')
@click.argument('name')
def delete_ipsec_site_connection(name):
    """Delete IPSec connection"""
    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    conns = getcfg(ipsec, 'connections', [])
    for conn in conns:
        if conn['name'] != name:
            continue
        conns.remove(conn)
        break
    write_config(cfg)

@gcli.command(name='ipsec-site-connection-update')
@click.option('--admin-state-down/--admin-state-up', default=False,
              help='Up or down admin state')
@click.option('--ikepolicy', help='IKE policy name')
@click.option('--ipsecpolicy', help='IPSec policy name')
@click.option('--dpd-action',
              type=click.Choice(['hold', 'clear', 'disabled', 'restart', 'restart-by-peer']),
              help='DPD action')
@click.option('--dpd-interval',
              type=int,
              help='DPD interval in seconds')
@click.option('--dpd-timeout',
              type=int,
              help='DPD timeout in seconds')
@click.option('--local-cidrs', type=IPv4CidrList, help='Local CIDRs separate by comma')
@click.option('--peer-cidrs', type=IPv4CidrList, help='Peer CIDRs separate by comma')
@click.option('--peer-id', help='Peer router identity for authentication')
@click.option('--peer-addr', type=IPv4, help='Peer gateway public IPv4')
@click.option('--psk', help='Pre-shared key string')
@click.option('--initiator',
              type=click.Choice(['bi-directional', 'response-only']),
              help='Initiator state in lowercase')
@click.argument('name')
def update_ipsec_site_connection(admin_state_down, ikepolicy, ipsecpolicy, dpd_action,
                                 dpd_interval, dpd_timeout, local_cidrs, peer_cidrs,
                                 peer_id, peer_addr, psk, initiator, name):
    """Update IPSec connection"""
    conn = find_site_connection(name)
    if not conn:
        click.echo('Connection %s is not found' % name)
        return
    conn['admin_state_down'] = admin_state_down
    if ikepolicy:
        ike = find_ikepolicy(ikepolicy)
        if not ike:
            click.echo('IKE Policy %s is not found' % ikepolicy)
            return
        ike['_pfs'] = ike['pfs']
        ike['pfs'] = dict_map[ike['pfs']]
        conn['ikepolicy'] = ike
        conn['_ikepolicy'] = ikepolicy
    if ipsecpolicy:
        _ipsec = find_ipsecpolicy(ipsecpolicy)
        if not _ipsec:
            click.echo('IPSec policy %s not found' % ipsecpolicy)
            return
        _ipsec['_pfs'] = _ipsec['pfs']
        _ipsec['pfs'] = dict_map[_ipsec['pfs']]
        conn['ipsecpolicy'] = _ipsec
        conn['_ipsecpolicy'] = ipsecpolicy
    if dpd_action:
        conn['dpd_action'] = dpd_action
    if dpd_interval:
        conn['dpd_interval'] = dpd_interval
    if dpd_timeout:
        conn['dpd_timeout'] = dpd_timeout
    if local_cidrs:
        conn['local_cidrs'] = local_cidrs
    if peer_cidrs:
        conn['peer_cidrs'] = peer_cidrs
    if peer_id:
        conn['peer_id'] = peer_id
    if peer_addr:
        conn['peer_addr'] = peer_addr
    if psk:
        conn['psk'] = psk
    if initiator:
        conn['initiator'] = initiator

    cfg = read_config()
    ipsec = getcfg(cfg, 'ipsec', {})
    conns = getcfg(ipsec, 'connections', [])
    for _conn in conns:
        if _conn['name'] != name:
            continue
        conns.remove(_conn)
        break
    conns.append(conn)
    write_config(cfg)

@gcli.command(name='ipsec-status')
@click.option('--detail', is_flag=True)
def show_ipsec_status(detail):
    """Show current IPSec status"""
    if not detail:
        _, out = cmd_exec(['ipsec', 'status'])
    else:
        _, out = cmd_exec(['ipsec', 'statusall'])
    click.echo(out)

@gcli.command(name='current-config-show')
def show_current_config():
    """Display current configurations"""
    out = to_output(CONF_FILE)
    click.echo_via_pager(out)

@gcli.command(name='running-config-show')
def show_running_config():
    """Display running configurations"""
    out = to_output(RUNNING_FILE)
    click.echo_via_pager(out)

@gcli.command(name='config-diff')
def show_diff_config():
    """Display the difference of current and running configurations"""
    current_file = '/tmp/current_cfg.tmp'
    running_file = '/tmp/running_cfg.tmp'
    current_out = to_output(CONF_FILE)
    running_out = to_output(RUNNING_FILE)
    with open(current_file, 'w') as current:
        current.write(current_out)
    with open(running_file, 'w') as running:
        running.write(running_out)

    output = 'Current and Running config are identical'
    rc, _ = cmd_exec(['diff', current_file, running_file])
    if not rc:
        click.echo(output)
        return
    else:
        rc, out = cmd_exec((['diff', '-y', current_file, running_file]))
        output = '#Left side is current config, right side is running config:\n\n' + out

    click.echo_via_pager(output)


if __name__ == '__main__':
    gcli()
