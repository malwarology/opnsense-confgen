# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Generate an example configuration object."""
import configparser


def generate():
    """Generate an example ConfigParser object."""
    config = configparser.ConfigParser()

    config['Host'] = {'hostname': 'firewall',
                      'domain': 'example.com',
                      'dns': '198.51.100.100'}
    config['WAN'] = {'if': 'vtnet0',
                     'ip': '192.0.2.10',
                     'subnet': '24',
                     'gateway': '192.0.2.1'}
    config['LAN'] = {'if': 'vtnet1',
                     'ip': '172.16.0.1',
                     'subnet': '24',
                     'description': 'Workstations',
                     'dhcp_start': '172.16.0.10',
                     'dhcp_end': '172.16.0.250'}
    config['OPT1'] = {'if': 'vtnet2',
                      'ip': '172.17.0.1',
                      'subnet': '24',
                      'description': 'Servers',
                      'dhcp_start': '172.17.0.10',
                      'dhcp_end': '172.17.0.250'}
    config['OPT2'] = {'if': 'vtnet3',
                      'ip': '172.18.0.1',
                      'subnet': '24',
                      'description': 'DMZ',
                      'dhcp_start': '172.18.0.10',
                      'dhcp_end': '172.18.0.250'}
    config['WGB'] = {'port': '51821',
                     'server_privkey': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                     'server_ip': '172.19.0.1/24',
                     'client_ip': '172.19.0.2/32',
                     'client_pubkey': 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC'}

    return config
