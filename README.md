# OPNsense Configuration Generator

This package takes a Python ConfigParser formatted INI file and generates a ready to use config.xml file for OPNsense. The intent is for the file to be used during the installation process by the OPNsense Importer. The end result is a minimal working configuraion with interfaces fully configured. Included in this package are a command line interface and a class which is importable into Python scripts and other applications.

More information about the OPNsense importer can be found [here](https://docs.opnsense.org/manual/install.html#opnsense-importer).

There are five potential output files:

| Filename | Content |
|--------- | ------- |
| config.xml | OPNsense configuration XML |
| config.iso | OPNsense configuration XML in a CD image |
| WGBootstrap.conf | WireGuard client configuration |
| WGBootstrap.url | macOS shortcut leading to OPNsense console |
| opnsense_config_example.ini | Example configuration INI |

## Optional Interfaces

Any number of optional network interfaces beyond the basic WAN and LAN can be included in the INI as `OPT` sections. Each may include a description that would result in the display name of the interface being `Servers` rather than `OPT2` for example.

## DHCP Configuration

If an `OPT` section of the INI contains a `dhcp_start` field, then a DHCP configuration section will be included that corresponds to that interface.

## WireGuard Bootstrap

An optional feature is the WireGuard bootstrap. If a `WGB` section is provided in the INI, then a working WireGuard VPN interface will be available for immediate connection. The interface occupies instance 1, therefore the device will be `wg1` rather than `wg0`. This is to allow the user or automation to create a permanent WireGuard VPN interface at `wg0` then delete the bootstrap. The goal with this process is to have the permanent WireGaurd private key generated on the OPNsense instance and never to have been transmitted at any time.

The WireGuard bootstrap has a number of options. If the INI contains a server private key, it will be used to derive a public key. That resulting key pair will be used to populate the configuration output. If the server private key is missing from the INI file, a new key pair will be generated using libsodium which will then be used to populate the configuration output. If a WireGuard client public key is present, it will be used to populate the endpoint section of the configuration output. If this public key is missing, a new key pair will be generated and used to populate the configuration output. A missing client public key will also trigger the output of a WireGuard client configuration file with the server public key and the client key pair populated and ready to be imported into the user's WireGuard client. Lastly, if a hostname and domain are included in the INI, they will be used to make an FQDN to populate the `Endpoint` field in the WireGuard client configuration file.

For convenience, an optional macOS shortcut file can be created that leads to the OPNsense console with one click.

## ISO Image

An alterative output format is an ISO image that contains the `config.xml` file in a directory named `conf` as expected by the OPNsense Importer. With OPNsense version 22.1.7, the importer is able to detect ISO9660 and grab the config. This mode of delivery can be used in a virtualization environment such as Proxmox which has shared ISO storage. One ISO can be used simultaneously in multiple OPNsense deployments.

## Installation

```
pip install opnsense-confgen
```

## Command Line Usage

##### Write example INI file then exit

```
oscg -e
```

##### Write XML OPNsense configuration file

```
oscg -f xml
```

##### Write ISO image containing OPNsense configuration file

```
oscg -f iso
```

##### Write both XML and ISO configuration files

```
oscg -f both
```

##### Write macOS shortcut file

```
oscg -s
```

##### Delete all existing output files

```
oscg -c
```

##### Print the OPNsense console URL

```
oscg -u
```

##### Print the XML config for debugging

```
oscg -d
```

## Class Usage

### Example Code

The following example will read a file `opnsense_config.ini` and instantiate the class with it. The OPNsense configuration result is an XML text string and the WireGuard result is a ConfigParser generated string. The config input used to instantiate the class can be a ConfigParser instance or it can be a dictionary object with the same section and field structure as what would result from reading the INI.

```
import configparser
import pathlib
import oscg.core

ini_config = configparser.ConfigParser()
ini_config.read('opnsense_config.ini')

gc = oscg.core.GenerateConfigs(ini_config)
opnsense_config = gc.os_config
wireguard_config = gc.wg_config
macos_shortcut = gc.mac_shortcut

config_path = pathlib.Path('config.xml')
config_path.write_text(opnsense_config)

wg_path = pathlib.Path('WGBootstrap.conf')
wg_path.write_text(wireguard_config)

sc_path = pathlib.Path('WGBootstrap.url')
sc_path.write_text(macos_shortcut)
```

### Example INI

```
[Host]
hostname = firewall
domain = example.com
dns = 198.51.100.100

[WAN]
if = vtnet0
ip = 192.0.2.10
subnet = 24
gateway = 192.0.2.1

[LAN]
if = vtnet1
ip = 172.16.0.1
subnet = 24
description = Workstations
dhcp_start = 172.16.0.10
dhcp_end = 172.16.0.250

[OPT1]
if = vtnet2
ip = 172.17.0.1
subnet = 24
description = Servers
dhcp_start = 172.17.0.10
dhcp_end = 172.17.0.250

[OPT2]
if = vtnet3
ip = 172.18.0.1
subnet = 24
description = DMZ
dhcp_start = 172.18.0.10
dhcp_end = 172.18.0.250

[WGB]
port = 51821
server_privkey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
server_ip = 172.19.0.1/24
client_ip = 172.19.0.2/32
client_pubkey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC
```

**Note:** The keys in the example above are deliberately malformed so that they are not accidentally used in a real deployment.

### Example INI Section for Optional Interface without DHCP

```
[OPT2]
if = vtnet3
ip = 172.18.0.1
subnet = 24
description = DMZ
```

### Example INI section for WireGuard Bootstrap which will generate a client configuration

```
[WGB]
port = 51821
server_privkey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
server_ip = 172.19.0.1/24
client_ip = 172.19.0.2/32
```

### Example INI section for WireGuard Bootstrap which will generate a new server key pair and a client configuration

```
[WGB]
port = 51821
server_ip = 172.19.0.1/24
client_ip = 172.19.0.2/32
```

## Dependencies

1. PyNaCl Python binding to libsodium https://pynacl.readthedocs.io/en/latest/
2. pycdlib https://clalancette.github.io/pycdlib/

## Known Issues

The automatically created `WireGuard (Group)` interface that is normally part of the WireGuard plugin is removed during the OPNsense install process.

To workaround this issue, login to the OPNsense console, navigate to the `Interfaces` menu and select `Assignments`. In the pane that appears on the right, click `Save`. This will recreate the `WireGuard (Group)` interface.

The Github issue for this bug is here: https://github.com/opnsense/core/issues/5768
