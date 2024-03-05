# Copyright 2024 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Unit test config generator core module."""
import base64
import configparser
import contextlib
import copy
import io
import pathlib
import re
import unittest
import xml.etree.ElementTree

import nacl.public

import oscg.core

THIS_DIR = pathlib.Path(__file__).parent

config_dict = dict()
config_dict['Host'] = {
    'hostname': 'firewall',
    'domain': 'example.com',
    'dns': '198.51.100.100'
}
config_dict['WAN'] = {
    'if': 'vtnet0',
    'ip': '192.0.2.10',
    'subnet': '24',
    'gateway': '192.0.2.1'
}
config_dict['LAN'] = {
    'if': 'vtnet1',
    'ip': '172.16.0.1',
    'subnet': '24',
    'description': 'Workstations',
    'dhcp_start': '172.16.0.10',
    'dhcp_end': '172.16.0.250'
}
config_dict['OPT1'] = {
    'if': 'vtnet2',
    'ip': '172.17.0.1',
    'subnet': '24',
    'description': 'Servers',
    'dhcp_start': '172.17.0.10',
    'dhcp_end': '172.17.0.250'
}
config_dict['OPT2'] = {
    'if': 'vtnet3',
    'ip': '172.18.0.1',
    'subnet': '24',
    'description': 'DMZ',
    'dhcp_start': '172.18.0.10',
    'dhcp_end': '172.18.0.250'
}
config_dict['WGB'] = {
    'port': '51821',
    'server_privkey': 'w9aO9TLbNoHxic3TLzniwP7b4dVnmVETe5s60TsK33A=',
    'server_ip': '172.19.0.1/24',
    'client_ip': '172.19.0.2/32',
    'client_pubkey': 'Ybc61c6eXt2wDmpVw92LSsmZFkQQiBDsHY24WZiziDQ='
}
config_dict['API'] = {
    'key': 'Ku7rxJotUKNM+SNQtMhL2yNzkp/XQF21ZY25HevhRER67eyUk2CyJQalvq51zd5bG5gYjS5b4pG4YnSS',
    'secret': '$6$$x.ZrJq6a4Nue2upbwKxz/57wN50arCSH3vRUEzHFfU4wiF7CDPycSiCfkTJUUO2RdPOiwsOw0cuwv1zM85RSl0'
}


class TestGeneratorClassInit(unittest.TestCase):
    """Check if the configuration generator class is initialized properly."""

    def setUp(self):
        """Instantiate the classes for testing."""
        self.gcd = oscg.core.GenerateConfigs(config_dict, testing=True)

        self.config = configparser.ConfigParser()
        self.config.read_dict(config_dict)
        self.gc = oscg.core.GenerateConfigs(self.config, testing=True)

    def test_dict_config(self):
        """Test that the dictionary INI configuration is initialized properly."""
        self.assertDictEqual(self.gcd._ini_config._sections, config_dict,
                             'INI not initialized properly from dictionary.')

    def test_configparser_config(self):
        """Test that the ConfigParser INI configuration is initialized properly."""
        self.assertDictEqual(self.gc._ini_config._sections, self.config._sections,
                             'INI not initialized properly from ConfigParser.')

    def test_tree_type(self):
        """Test that the initialized XML root is the correct type."""
        self.assertIsInstance(self.gc._root, xml.etree.ElementTree.Element, 'Root is not correct type.')


class TestGeneratorClassFunct(unittest.TestCase):
    """Test all functions in configuration generator class."""

    def setUp(self):
        """Instantiate the class for testing."""
        config = configparser.ConfigParser()
        config.read_dict(config_dict)
        self.gc = oscg.core.GenerateConfigs(config, testing=True)

    def test_revision(self):
        """Test that the revision is set properly."""
        section_re = THIS_DIR.joinpath('data').joinpath('sections').joinpath('revision.re').read_text()

        self.gc._set_revision()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('revision'), encoding='unicode')

        self.assertRegex(section, section_re, 'Revision is not set as expected.')

    def test_system(self):
        """Test that the system section is set properly."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('system.xml').read_text()

        self.gc._set_system()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('system'), encoding='unicode')

        self.assertEqual(section_str, section, 'System section is not set as expected.')

    def test_system_no_hostname(self):
        """Test that the system section is set properly with hostname not provided."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('system_no_host.xml').read_text()

        config_local = copy.deepcopy(config_dict)
        del config_local['Host']['hostname']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._set_system()

        section = xml.etree.ElementTree.tostring(gcl._root.find('system'), encoding='unicode')

        self.assertEqual(section_str, section, 'System section with hostname not provided not as expected.')

    def test_system_no_domain(self):
        """Test that the system section is set properly with domain not provided."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('system_no_domain.xml').read_text()

        config_local = copy.deepcopy(config_dict)
        del config_local['Host']['domain']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._set_system()

        section = xml.etree.ElementTree.tostring(gcl._root.find('system'), encoding='unicode')

        self.assertEqual(section_str, section, 'System section with domain not provided not as expected.')

    def test_system_no_host_no_domain(self):
        """Test that the system section is set properly with hostname and domain not provided."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('system_no_host_domain.xml').read_text()

        config_local = copy.deepcopy(config_dict)
        del config_local['Host']['domain']
        del config_local['Host']['hostname']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._set_system()

        section = xml.etree.ElementTree.tostring(gcl._root.find('system'), encoding='unicode')

        self.assertEqual(section_str, section, 'System section with hostname/domain not provided not as expected.')

    def test_wan_if(self):
        """Test that the WAN interface section is set properly."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('wan_if.xml').read_text()

        self.gc._set_wan_if()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('interfaces').find('wan'), encoding='unicode')

        self.assertEqual(section_str, section, 'WAN interface section is not set as expected.')

    def test_lan_if(self):
        """Test that the LAN interface section is set properly."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('lan_if.xml').read_text()

        self.gc._set_lan_if()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('interfaces').find('lan'), encoding='unicode')

        self.assertEqual(section_str, section, 'LAN interface section is not set as expected.')

    def test_lan_dhcp(self):
        """Test that the LAN DHCP section is set properly."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('lan_dhcp.xml').read_text()

        self.gc._set_lan_dhcp()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('dhcpd').find('lan'), encoding='unicode')

        self.assertEqual(section_str, section, 'LAN DHCP section is not set as expected.')

    def test_gateway(self):
        """Test that the gateway section is set properly for a standard gateway."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('gw.xml').read_text()

        self.gc._set_gateway()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('gateways').find('gateway_item'),
                                                 encoding='unicode')

        self.assertEqual(section_str, section, 'Standard gateway section is not set as expected.')

    def test_far_gateway(self):
        """Test that the gateway section is set properly for a far gateway."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('gw_far.xml').read_text()

        config_local = copy.deepcopy(config_dict)
        config_local['WAN']['gateway'] = '203.0.113.254'
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._set_gateway()

        section = xml.etree.ElementTree.tostring(gcl._root.find('gateways').find('gateway_item'), encoding='unicode')

        self.assertEqual(section_str, section, 'Far gateway section is not set as expected.')

    def test_server_key(self):
        """Test server public key is populated properly when private key is provided."""
        public = 'Pm76qcDtNmlPg3ecorCCiplqArUhP2YMYbehpodKwkQ='

        self.gc._check_serverkey()

        server_pubkey = self.gc._ini_config['WGB'].get('server_pubkey')

        self.assertEqual(public, server_pubkey, 'Recovered server public key not as expected.')

    def test_no_server_key(self):
        """Test server key pair is populated properly when private key is not provided."""
        wgkey_re = r'[a-zA-Z0-9+/]{43}='

        config_local = copy.deepcopy(config_dict)
        del config_local['WGB']['server_privkey']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._check_serverkey()

        keys = {'public': gcl._ini_config['WGB'].get('server_pubkey', str()),
                'private': gcl._ini_config['WGB'].get('server_privkey', str())}

        for ktype, key in keys.items():
            with self.subTest(key_type=ktype):

                self.assertRegex(key, wgkey_re, f'Key not as expected: {ktype}.')

    def test_server_key_derivation(self):
        """Test server public key is derived from private key."""
        config_local = copy.deepcopy(config_dict)
        del config_local['WGB']['server_privkey']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._check_serverkey()

        public = gcl._ini_config['WGB'].get('server_pubkey', str())
        private = gcl._ini_config['WGB'].get('server_privkey', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')

        key_bytes = base64.b64decode(private)
        privkey = nacl.public.PrivateKey(private_key=key_bytes)
        pubkey = base64.b64encode(bytes(privkey.public_key)).decode()

        self.assertEqual(public, pubkey, 'Server public key not derived from private key.')

    def test_wg_client_config(self):
        """Test WireGuard client config is generated properly."""
        wg_conf_re = THIS_DIR.joinpath('data').joinpath('wg_client_config_fqdn.re').read_text()

        config_local = copy.deepcopy(config_dict)
        del config_local['WGB']['client_pubkey']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._set_system()
        gcl._check_serverkey()
        gcl._gen_wg_config()
        wg_conf_str = gcl.wg_config

        self.assertRegex(wg_conf_str, wg_conf_re, 'WireGuard configuration is not as expected.')

    def test_wg_client_config_server_dynamic(self):
        """Test WireGuard client config is generated properly when server key is generated."""
        wg_conf_re = THIS_DIR.joinpath('data').joinpath('wg_client_config_fqdn_server_dynamic.re').read_text()

        config_local = copy.deepcopy(config_dict)
        del config_local['WGB']['server_privkey']
        del config_local['WGB']['client_pubkey']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._set_system()
        gcl._check_serverkey()
        gcl._gen_wg_config()
        wg_conf_str = gcl.wg_config

        self.assertRegex(wg_conf_str, wg_conf_re, 'WireGuard configuration is not as expected with dynamic server key.')

    def test_wg_client_config_no_hostname_no_domain(self):
        """Test WireGuard client config is generated properly when hostname and domain are not provided."""
        wg_conf_re = THIS_DIR.joinpath('data').joinpath('wg_client_config_ip.re').read_text()

        config_local = copy.deepcopy(config_dict)
        del config_local['WGB']['client_pubkey']
        del config_local['Host']['domain']
        del config_local['Host']['hostname']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._set_system()
        gcl._check_serverkey()
        gcl._gen_wg_config()
        wg_conf_str = gcl.wg_config

        self.assertRegex(wg_conf_str, wg_conf_re, 'WireGuard config not as expected, hostname/domain not provided.')

    def test_console_url(self):
        """Test that the console URL is set properly."""
        self.gc._set_wg_console_url()
        console_url = self.gc.console_url

        self.assertEqual(console_url, 'https://172.19.0.1/', 'Console URL not set properly.')

    def test_plugin(self):
        """Test that the plugin is added properly to the system configuration."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('plugin.xml').read_text()

        self.gc._add_wg_plugin()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('system').find('firmware'), encoding='unicode')

        self.assertEqual(section_str, section, 'Plugins section is not set as expected.')

    def test_wg_if(self):
        """Test that the WireGuard interface and interface group are both appended correctly to interfaces."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('wg_if.xml').read_text()

        self.gc._add_wg_if()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('interfaces'), encoding='unicode')

        self.assertEqual(section_str, section, 'WireGuard interfaces are not set as expected.')

    def test_wg_fw(self):
        """Test that the WireGuard firewall rules are added correctly to the rule set."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('wg_fw.xml').read_text()

        self.gc._add_wg_fw()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('filter'), encoding='unicode')

        self.assertEqual(section_str, section, 'WireGuard firewall rules are not set as expected.')

    def test_wg_settings(self):
        """Test that the WireGuard settings are appended correctly to the configuration."""
        section_re = THIS_DIR.joinpath('data').joinpath('sections').joinpath('wg_settings.re').read_text().strip()

        self.gc._check_serverkey()
        self.gc._add_wg_settings()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('OPNsense'), encoding='unicode')

        self.assertRegex(section, section_re, 'WireGuard settings not set as expected.')

    def test_wg_peer_uuid(self):
        """Test that the client UUID matches the server peer."""
        peer_re = r'<peers>(?P<uuid>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})</peers>'
        client_re = r'<client uuid="(?P<uuid>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})">'

        self.gc._check_serverkey()
        self.gc._add_wg_settings()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('OPNsense'), encoding='unicode')
        peer = re.search(peer_re, section)
        client = re.search(client_re, section)

        self.assertEqual(peer.group('uuid'), client.group('uuid'), 'Client UUID and server peer do not match.')

    def test_find_opt_type(self):
        """Test that a list is returned by the function."""
        section_matches = self.gc._find_opt()

        self.assertIsInstance(section_matches, list, 'Return object is not list.')

    def test_find_opt_length(self):
        """Test that the list is length two."""
        section_matches = self.gc._find_opt()

        self.assertIs(len(section_matches), 2, 'List is not length two.')

    def test_find_opt_content(self):
        """Test that the list content is correct."""
        section_matches = self.gc._find_opt()

        for match in section_matches:
            with self.subTest(section=match.group(0)):
                self.assertIn(match.group('number'), ['1', '2'], 'Optional interfaces found is not correct.')

    def test_opt_if(self):
        """Test that an optional interface is appended correctly to interfaces."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('opt_if.xml').read_text()

        config_local = copy.deepcopy(config_dict)
        del config_local['OPT2']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)

        for match in gcl._find_opt():
            gcl._add_opt_if(match)

        section = xml.etree.ElementTree.tostring(gcl._root.find('interfaces'), encoding='unicode')

        self.assertEqual(section_str, section, 'Optional interface not set as expected.')

    def test_opt_dhcp(self):
        """Test that optional DHCP settings section is appended correctly."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('opt_dhcp.xml').read_text()

        config_local = copy.deepcopy(config_dict)
        del config_local['OPT2']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)

        for match in gcl._find_opt():
            gcl._add_opt_dhcp(match)

        section = xml.etree.ElementTree.tostring(gcl._root.find('dhcpd'), encoding='unicode')

        self.assertEqual(section_str, section, 'DHCP settings not set as expected.')

    def test_apikey(self):
        """Test that the API key bootstrap is added to the user section correctly."""
        section_str = THIS_DIR.joinpath('data').joinpath('sections').joinpath('user.xml').read_text()

        self.gc._add_apikey()

        section = xml.etree.ElementTree.tostring(self.gc._root.find('system').find('user'), encoding='unicode')

        self.assertEqual(section_str, section, 'User section with API key is not set as expected.')

    def test_gen_os_config(self):
        """Test that the full configuration generation function works as expected."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_stat_keys.re').read_text().strip()

        self.gc._gen_os_config()

        section = xml.etree.ElementTree.tostring(self.gc._root, encoding='unicode')

        self.assertRegex(section, config_re, 'Full OPNsense configuration not formatted correctly.')

    def test_os_config_type(self):
        """Test that the type returned by the os_config property is a string."""
        self.gc._gen_os_config()
        os_config = self.gc.os_config

        self.assertIsInstance(os_config, str, 'OPNsense configuration is not the expected string type.')

    def test_wg_config_type(self):
        """Test that the type returned by the wg_config property is a string."""
        config_local = copy.deepcopy(config_dict)
        del config_local['WGB']['client_pubkey']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._set_system()
        gcl._check_serverkey()
        gcl._gen_wg_config()
        wg_config = gcl.wg_config

        self.assertIsInstance(wg_config, str, 'WireGuard client configuration is not the expected string type.')

    def test_os_config_debug_dump(self):
        """Test that configuration generation function works as expected using debug dump no testing mode."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_stat_keys.re').read_text().strip()

        gcl = oscg.core.GenerateConfigs(config_dict)
        with contextlib.redirect_stdout(io.StringIO()) as f:
            gcl.debug()
        section = f.getvalue()

        self.assertRegex(section, config_re, 'Output not formatted correctly via debug dump.')

    def test_os_config_prop(self):
        """Test that the full configuration generation function works as expected using the os_config property."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_stat_keys_with_decl.re').read_text().strip()

        self.gc._gen_os_config()
        section = self.gc.os_config

        self.assertRegex(section, config_re, 'Output not formatted correctly via os_config property.')

    def test_os_config_prop_no_testing(self):
        """Test that configuration generation function works as expected using os_config property no testing mode."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_stat_keys_with_decl.re').read_text().strip()

        gcl = oscg.core.GenerateConfigs(config_dict)
        section = gcl.os_config

        self.assertRegex(section, config_re, 'Output not formatted correctly via os_config property and no testing.')

    def test_gen_os_config_no_opt_dhcp(self):
        """Test that the full configuration generation function works as expected without DHCP on optional interface."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_no_opt_dhcp.re').read_text().strip()

        config_local = copy.deepcopy(config_dict)
        del config_local['OPT1']['dhcp_start']
        del config_local['OPT1']['dhcp_end']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._gen_os_config()

        section = xml.etree.ElementTree.tostring(gcl._root, encoding='unicode')

        self.assertRegex(section, config_re, 'Output not formatted correctly, no DHCP on optional.')

    def test_gen_os_config_no_wg_client_key(self):
        """Test that the full configuration generation function works as expected without WireGuard client key."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_dyn_cpub.re').read_text().strip()

        config_local = copy.deepcopy(config_dict)
        del config_local['WGB']['client_pubkey']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._gen_os_config()

        section = xml.etree.ElementTree.tostring(gcl._root, encoding='unicode')

        self.assertRegex(section, config_re, 'Output not formatted correctly, no WireGuard client key.')

    def test_gen_os_config_no_wireguard(self):
        """Test that the full configuration generation function works as expected without WireGuard settings."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_no_wg.re').read_text().strip()

        config_local = copy.deepcopy(config_dict)
        del config_local['WGB']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._gen_os_config()

        section = xml.etree.ElementTree.tostring(gcl._root, encoding='unicode')

        self.assertRegex(section, config_re, 'Output not formatted correctly, no WireGuard.')

    def test_gen_os_config_no_apikey(self):
        """Test that the full configuration generation function works as expected without API key bootstrap."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_no_apikey.re').read_text().strip()

        config_local = copy.deepcopy(config_dict)
        del config_local['API']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._gen_os_config()

        section = xml.etree.ElementTree.tostring(gcl._root, encoding='unicode')

        self.assertRegex(section, config_re, 'Output not formatted correctly, no API key bootstrap.')

    def test_wg_config_prop_no_wireguard(self):
        """Test that the WireGuard config property returns None when config is not generated."""
        self.gc._gen_os_config()
        wg_config = self.gc.wg_config

        self.assertIsNone(wg_config, 'WireGuard config property is not None.')

    def test_mac_shortcut_prop(self):
        """Test that the macOS shortcut property returns the correct data."""
        expected = '[InternetShortcut]\nURL=https://172.19.0.1/\n'

        self.gc._gen_os_config()
        mac_shortcut = self.gc.mac_shortcut

        self.assertEqual(mac_shortcut, expected, 'Shortcut for macOS not returned correctly from property.')

    def test_no_mac_shortcut_prop(self):
        """Test that the macOS shortcut property returns None when WireGuard bootstrap is not in config INI."""
        config_local = copy.deepcopy(config_dict)
        del config_local['WGB']
        gcl = oscg.core.GenerateConfigs(config_local, testing=True)
        gcl._gen_os_config()
        mac_shortcut = self.gc.mac_shortcut

        self.assertIsNone(mac_shortcut, 'Shortcut property is not None.')


if __name__ == '__main__':
    unittest.main(verbosity=2)
