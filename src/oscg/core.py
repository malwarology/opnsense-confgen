# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Core functions for generating configs."""
import configparser
import importlib.metadata
import importlib.resources
import io
import ipaddress
import re
import time
import uuid
import xml.etree.ElementTree

import oscg.utils


class GenerateConfigs:
    """Class for generating an OPNsense config and optionally a WireGuard client config."""

    def __init__(self, config, testing=False):
        with importlib.resources.open_text('oscg.templates', 'config.xml') as config_template:
            tree = xml.etree.ElementTree.parse(config_template)
        self._root = tree.getroot()
        if isinstance(config, dict):
            conf_parser = configparser.ConfigParser()
            conf_parser.read_dict(config)
            self._ini_config = conf_parser
        else:
            self._ini_config = config
        self._hostname = None
        self._domain = None

        self._wg_configparser = None

        self.console_url = None

        if not testing:
            self._gen_os_config()

    def _set_revision(self):
        """Set configuration revision information."""
        revision = self._root.find('revision')
        revision.find('time').text = str(round(time.time(), 4))
        version = importlib.metadata.version('opnsense-confgen')
        description = f'Created by OPNsense Configuration Generator v{version}'
        revision.find('description').text = description

    def _set_system(self):
        """Set system section of configuration."""
        system = self._root.find('system')

        if hostname := self._ini_config['Host'].get('hostname'):
            self._hostname = system.find('hostname').text = hostname
        if domain := self._ini_config['Host'].get('domain'):
            self._domain = system.find('domain').text = domain

        system.find('dnsserver').text = self._ini_config['Host']['dns']

    def _set_wan_if(self):
        """Set the WAN interface section of configuration."""
        wan_if = self._root.find('interfaces').find('wan')
        wan_if.find('if').text = self._ini_config['WAN']['if']
        wan_if.find('ipaddr').text = self._ini_config['WAN']['ip']
        wan_if.find('subnet').text = self._ini_config['WAN']['subnet']

    def _set_lan_if(self):
        """Set the LAN interface section of configuration."""
        lan_if = self._root.find('interfaces').find('lan')
        lan_if.find('if').text = self._ini_config['LAN']['if']
        lan_if.find('descr').text = self._ini_config['LAN']['description']
        lan_if.find('ipaddr').text = self._ini_config['LAN']['ip']
        lan_if.find('subnet').text = self._ini_config['LAN']['subnet']

    def _set_lan_dhcp(self):
        """Set the LAN DHCP section of configuration."""
        lan_dhcp = self._root.find('dhcpd').find('lan')
        lan_dhcp.find('gateway').text = self._ini_config['LAN']['ip']
        lan_dhcp.find('range').find('from').text = self._ini_config['LAN']['dhcp_start']
        lan_dhcp.find('range').find('to').text = self._ini_config['LAN']['dhcp_end']
        lan_dhcp.find('dnsserver').text = self._ini_config['LAN']['ip']

    def _set_gateway(self):
        """Set the gateway section of configuration."""
        gateway = self._root.find('gateways').find('gateway_item')
        gateway.find('gateway').text = self._ini_config['WAN']['gateway']

        gateway_ip = ipaddress.ip_address(self._ini_config['WAN']['gateway'])

        wan_ip = self._ini_config['WAN']['ip']
        wan_subnet = self._ini_config['WAN']['subnet']
        wan_netblock = ipaddress.ip_network(f'{wan_ip}/{wan_subnet}', strict=False)
        far_gateway = gateway.find('fargw')

        if gateway_ip in wan_netblock:
            far_gateway.text = '0'
        else:
            far_gateway.text = '1'

    def _check_serverkey(self):
        """Check for WireGuard server key and generate one if missing."""
        if private := self._ini_config['WGB'].get('server_privkey'):
            public = oscg.utils._wggetpub(private)
        else:
            private, public = oscg.utils._wgkeys()
            self._ini_config['WGB']['server_privkey'] = private
        self._ini_config['WGB']['server_pubkey'] = public

    def _gen_wg_config(self):
        """Generate WireGuard key and client config."""
        self._wg_configparser = configparser.RawConfigParser()
        self._wg_configparser.optionxform = lambda option: option

        private, public = oscg.utils._wgkeys()
        self._ini_config['WGB']['client_pubkey'] = public

        self._wg_configparser['Interface'] = {'PrivateKey': private,
                                              'Address': self._ini_config['WGB']['client_ip']}

        if self._hostname and self._domain:
            host = f'{self._hostname}.{self._domain}'
        else:
            host = self._ini_config['WAN']['ip']
        endpoint = '{}:{}'.format(host, self._ini_config['WGB']['port'])

        self._wg_configparser['Peer'] = {'PublicKey': self._ini_config['WGB']['server_pubkey'],
                                         'AllowedIPs': self._ini_config['WGB']['server_ip'],
                                         'Endpoint': endpoint}

    def _set_wg_console_url(self):
        """Extract WireGuard server IP and set URL as attribute."""
        server_cidr = self._ini_config['WGB']['server_ip']
        server_ip = server_cidr.split('/')[0]

        self.console_url = f'https://{server_ip}/'

    def _add_wg_plugin(self):
        """Add WireGuard plugin to configuration."""
        plugins = xml.etree.ElementTree.Element('plugins')
        plugins.text = 'os-wireguard'
        self._root.find('system').find('firmware').append(plugins)

    def _add_wg_if(self):
        """Append WireGuard interfaces to configuration."""
        # Append WireGuard interface group.
        wg_grp_template = importlib.resources.read_text('oscg.templates', 'wg_grp.xml')
        wg_grp = xml.etree.ElementTree.fromstring(wg_grp_template)
        self._root.find('interfaces').append(wg_grp)

        # Append wg1 interface.
        wg_if_template = importlib.resources.read_text('oscg.templates', 'wg_if.xml')
        wg_if = xml.etree.ElementTree.fromstring(wg_if_template)
        self._root.find('interfaces').append(wg_if)

    def _add_wg_fw(self):
        """Add firewall rules relating to WireGuard."""
        # Insert firewall rule to allow WireGuard traffic on WAN interface at top of rule set.
        fw_wg_template = importlib.resources.read_text('oscg.templates', 'fw_wg.xml')
        fw_wg = xml.etree.ElementTree.fromstring(fw_wg_template)
        fw_wg.find('destination').find('port').text = self._ini_config['WGB']['port']
        self._root.find('filter').insert(0, fw_wg)

        # Append firewall rule allowing access to OPNsense admin portal from WireGuard interface.
        fw_admin_template = importlib.resources.read_text('oscg.templates', 'fw_admin.xml')
        fw_admin = xml.etree.ElementTree.fromstring(fw_admin_template)
        self._root.find('filter').append(fw_admin)

    def _add_wg_settings(self):
        """Append WireGuard settings to configuration."""
        wg_conf_template = importlib.resources.read_text('oscg.templates', 'wg_conf.xml')
        wg_conf = xml.etree.ElementTree.fromstring(wg_conf_template)
        wgc = wg_conf.find('wireguard')

        # Add server endpoint settings.
        wg_server = wgc.find('server').find('servers').find('server')
        wg_server.set('uuid', str(uuid.uuid4()))
        wg_server.find('pubkey').text = self._ini_config['WGB']['server_pubkey']
        wg_server.find('privkey').text = self._ini_config['WGB']['server_privkey']
        wg_server.find('port').text = self._ini_config['WGB']['port']
        wg_server.find('tunneladdress').text = self._ini_config['WGB']['server_ip']
        client_id = str(uuid.uuid4())
        wg_server.find('peers').text = client_id

        # Add client settings.
        wg_client = wgc.find('client').find('clients').find('client')
        wg_client.set('uuid', client_id)
        wg_client.find('pubkey').text = self._ini_config['WGB']['client_pubkey']
        wg_client.find('tunneladdress').text = self._ini_config['WGB']['client_ip']

        self._root.append(wg_conf)

    def _find_opt(self):
        """Find all sections of the config that describe optional interfaces."""
        opt_sections = list()

        for section in self._ini_config.sections():
            if match := re.match(r'OPT(?P<number>\d)', section):
                opt_sections.append(match)

        return opt_sections

    def _add_opt_if(self, match):
        """Append optional interface settings to configuration."""
        section = match.group(0)

        opt_if_template = importlib.resources.read_text('oscg.templates', 'opt_if.xml')
        opt_if = xml.etree.ElementTree.fromstring(opt_if_template)

        opt_if.tag = 'opt{}'.format(match.group('number'))
        opt_if.find('if').text = self._ini_config[section]['if']
        opt_if.find('descr').text = self._ini_config[section]['description']
        opt_if.find('ipaddr').text = self._ini_config[section]['ip']
        opt_if.find('subnet').text = self._ini_config[section]['subnet']

        self._root.find('interfaces').append(opt_if)

    def _add_opt_dhcp(self, match):
        """Append optional interface DHCP settings to configuration."""
        section = match.group(0)

        opt_dhcp_template = importlib.resources.read_text('oscg.templates', 'opt_dhcp.xml')
        opt_dhcp = xml.etree.ElementTree.fromstring(opt_dhcp_template)

        opt_dhcp.tag = 'opt{}'.format(match.group('number'))
        opt_dhcp.find('gateway').text = self._ini_config[section]['ip']
        opt_dhcp.find('range').find('from').text = self._ini_config[section].get('dhcp_start')
        opt_dhcp.find('range').find('to').text = self._ini_config[section]['dhcp_end']
        opt_dhcp.find('dnsserver').text = self._ini_config[section]['ip']

        self._root.find('dhcpd').append(opt_dhcp)

    def _gen_os_config(self):
        """Generate an OPNsense configuration file."""
        self._set_revision()
        self._set_system()
        self._set_wan_if()
        self._set_lan_if()
        self._set_lan_dhcp()
        self._set_gateway()

        # Handle WireGuard bootstrap if needed.
        if self._ini_config.has_section('WGB'):
            self._check_serverkey()
            if not self._ini_config['WGB'].get('client_pubkey'):
                self._gen_wg_config()
            self._set_wg_console_url()
            self._add_wg_plugin()
            self._add_wg_if()
            self._add_wg_fw()
            self._add_wg_settings()

        # Handle optional interfaces if needed.
        for section_matches in self._find_opt():
            self._add_opt_if(section_matches)
            if self._ini_config[section_matches.group(0)].get('dhcp_start'):
                self._add_opt_dhcp(section_matches)

        xml.etree.ElementTree.indent(self._root, space='  ')

    @property
    def os_config(self):
        """Property which returns the finished config XML."""
        config_xml = xml.etree.ElementTree.tostring(self._root, xml_declaration=True)

        return config_xml.decode()

    @property
    def wg_config(self):
        """Property which returns the finished WireGuard client config string."""
        if self._wg_configparser is not None:
            with io.StringIO() as configfile:
                self._wg_configparser.write(configfile)
                configfile.seek(0)
                config_str = configfile.read()

            return config_str

        return None

    @property
    def mac_shortcut(self):
        """Property which returns the finished console URL macOS internet shortcut string."""
        if self.console_url is not None:
            return '[InternetShortcut]\nURL={}\n'.format(self.console_url)
        else:
            return None

    def debug(self):
        """Dump config XML to stdout."""
        xml.etree.ElementTree.dump(self._root)
