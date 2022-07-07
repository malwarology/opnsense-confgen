# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Generate OPNsense configuration XML.

The OPNsense Configuration Generator (oscg) is a command line tool for generating configuration XML files. The generator
takes a simple INI file and emits a full config.xml file that is ready to use with the OPNsense importer during the
install process. An optional WireGuard bootstrap can be included which allows immediate remote access to the new
OPNsense instance. This bootstrap can use already existing keypairs, or can generate keypairs and a client config file
if needed. The config.xml output can optionally be exported as an ISO.
"""
import argparse
import configparser
import distutils
import enum
import pathlib
import sys

import oscg.core
import oscg.example
import oscg.utils


class _Output(enum.Enum):
    """Output path objects."""

    XML = pathlib.Path('config.xml')
    ISO = pathlib.Path('config.iso')
    WG = pathlib.Path('WGBootstrap.conf')
    URL = pathlib.Path('WGBootstrap.url')
    EX = pathlib.Path('opnsense_config_example.ini')


def _cleanup():
    """Delete all output files."""
    delete = input('Delete all output files? (y/N): ')
    try:
        proceed = distutils.util.strtobool(delete)
    except ValueError:
        proceed = False
    if not proceed:
        sys.exit()
    for path in list(_Output):
        path.value.unlink(missing_ok=True)
    sys.exit()


def _write_example():
    """Write an example configuration INI file."""
    ini_config = oscg.example.generate()
    conf_path = _Output.EX.value
    with open(conf_path, 'w') as configfile:
        ini_config.write(configfile)
    print(f'Example configuration file written to: {conf_path}')
    sys.exit()


def _check_path(path):
    """Check if path exists and ask if it should be overwritten."""
    if path.exists():
        overwrite = input('File "{}" exists, overwrite? (y/N): '.format(path.name))
        try:
            proceed = distutils.util.strtobool(overwrite)
        except ValueError:
            proceed = False

        return proceed

    return True


def _get_path(filename):
    """Check text string input path and return pathlib object if it exists."""
    path = pathlib.Path(filename)
    if not path.exists():
        sys.exit(f'File not found: {filename}')

    return path


def _generate_configs(ini_path, debug=False):
    """Run the core configuration generator and return configurations and optional console URL."""
    config = configparser.ConfigParser()
    config.read(ini_path)
    gc = oscg.core.GenerateConfigs(config)
    if debug:
        gc.debug()

    return gc.os_config, gc.wg_config, gc.mac_shortcut, gc.console_url


def _write_xml(os_config):
    """Write OPNsense XML configuration to file."""
    conf_path = _Output.XML.value
    if not _check_path(conf_path):
        return
    conf_path.write_text(os_config)
    print(f'OPNsense configuration written to: {conf_path}')


def _write_wg(wg_config):
    """Write WireGuard client configuration to file."""
    conf_path = _Output.WG.value
    if not _check_path(conf_path):
        return
    conf_path.write_text(wg_config)
    print(f'WireGuard client configuration written to: {conf_path}')


def _write_iso(os_config):
    """Write OPNsense configuration to ISO image."""
    conf_path = _Output.ISO.value
    if not _check_path(conf_path):
        return
    iso = oscg.utils.make_iso(os_config)
    conf_path.write_bytes(iso)
    print(f'OPNsense configuration written to: {conf_path}')


def _write_mac_shortcut(mac_shortcut):
    """Write console URL macOS internet shortcut to file."""
    shortcut_path = _Output.URL.value
    if not _check_path(shortcut_path):
        return
    shortcut_path.write_text(mac_shortcut)
    print(f'Console URL macOS internet shortcut written to: {shortcut_path}')


def main():
    """Get arguments and run the console script functions."""
    parser = argparse.ArgumentParser(description='Generate OPNsense configuration XML')
    parser.add_argument('ini', nargs='?', metavar='INI', default='opnsense_config.ini',
                        help='Path to INI file, default: "opnsense_config.ini"')
    parser.add_argument('-e', '--example', action='store_true', help='Write an example INI file then exit')
    parser.add_argument('-f', '--format', choices=['xml', 'iso', 'both'], default='xml',
                        help='Output format, default: xml')
    parser.add_argument('-s', '--shortcut', action='store_true', help='Write console URL macOS internet shortcut')
    parser.add_argument('-u', '--url', action='store_true', help='Print console URL to terminal')
    parser.add_argument('-d', '--debug', action='store_true', help='Print configuration XML to console')
    parser.add_argument('-c', '--cleanup', action='store_true', help='Delete all output files then exit')

    args = parser.parse_args()

    if args.cleanup:
        _cleanup()

    if args.example:
        _write_example()

    os_config, wg_config, mac_shortcut, console_url = _generate_configs(_get_path(args.ini), debug=args.debug)

    if args.format in ['xml', 'both']:
        _write_xml(os_config)

    if args.format in ['iso', 'both']:
        _write_iso(os_config)

    if wg_config:
        _write_wg(wg_config)
        if args.shortcut:
            _write_mac_shortcut(mac_shortcut)
        if args.url:
            print(console_url)
