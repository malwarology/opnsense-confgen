<\?xml version='1\.0' encoding='us-ascii'\?>
<opnsense>
  <theme>opnsense</theme>
  <sysctl>
    <item>
      <descr>Increase UFS read-ahead speeds to match the state of hard drives and NCQ\.</descr>
      <tunable>vfs\.read_max</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Set the ephemeral port range to be lower\.</descr>
      <tunable>net\.inet\.ip\.portrange\.first</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Drop packets to closed TCP ports without returning a RST</descr>
      <tunable>net\.inet\.tcp\.blackhole</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Do not send ICMP port unreachable messages for closed UDP ports</descr>
      <tunable>net\.inet\.udp\.blackhole</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Randomize the ID field in IP packets</descr>
      <tunable>net\.inet\.ip\.random_id</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>
        Source routing is another way for an attacker to try to reach non-routable addresses behind your box\.
        It can also be used to probe for information about your internal networks\. These functions come enabled
        as part of the standard FreeBSD core system\.
      </descr>
      <tunable>net\.inet\.ip\.sourceroute</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>
        Source routing is another way for an attacker to try to reach non-routable addresses behind your box\.
        It can also be used to probe for information about your internal networks\. These functions come enabled
        as part of the standard FreeBSD core system\.
      </descr>
      <tunable>net\.inet\.ip\.accept_sourceroute</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>
        This option turns off the logging of redirect packets because there is no limit and this could fill
        up your logs consuming your whole hard drive\.
      </descr>
      <tunable>net\.inet\.icmp\.log_redirect</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Drop SYN-FIN packets \(breaks RFC1379, but nobody uses it anyway\)</descr>
      <tunable>net\.inet\.tcp\.drop_synfin</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Enable sending IPv6 redirects</descr>
      <tunable>net\.inet6\.ip6\.redirect</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Enable privacy settings for IPv6 \(RFC 4941\)</descr>
      <tunable>net\.inet6\.ip6\.use_tempaddr</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Prefer privacy addresses and use them over the normal addresses</descr>
      <tunable>net\.inet6\.ip6\.prefer_tempaddr</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Generate SYN cookies for outbound SYN-ACK packets</descr>
      <tunable>net\.inet\.tcp\.syncookies</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Maximum incoming/outgoing TCP datagram size \(receive\)</descr>
      <tunable>net\.inet\.tcp\.recvspace</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Maximum incoming/outgoing TCP datagram size \(send\)</descr>
      <tunable>net\.inet\.tcp\.sendspace</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Do not delay ACK to try and piggyback it onto a data packet</descr>
      <tunable>net\.inet\.tcp\.delayed_ack</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Maximum outgoing UDP datagram size</descr>
      <tunable>net\.inet\.udp\.maxdgram</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Handling of non-IP packets which are not passed to pfil \(see if_bridge\(4\)\)</descr>
      <tunable>net\.link\.bridge\.pfil_onlyip</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Set to 1 to additionally filter on the physical interface for locally destined packets</descr>
      <tunable>net\.link\.bridge\.pfil_local_phys</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Set to 0 to disable filtering on the incoming and outgoing member interfaces\.</descr>
      <tunable>net\.link\.bridge\.pfil_member</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Set to 1 to enable filtering on the bridge interface</descr>
      <tunable>net\.link\.bridge\.pfil_bridge</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Allow unprivileged access to tap\(4\) device nodes</descr>
      <tunable>net\.link\.tap\.user_open</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Randomize PID's \(see src/sys/kern/kern_fork\.c: sysctl_kern_randompid\(\)\)</descr>
      <tunable>kern\.randompid</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Disable CTRL\+ALT\+Delete reboot from keyboard\.</descr>
      <tunable>hw\.syscons\.kbd_reboot</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Enable TCP extended debugging</descr>
      <tunable>net\.inet\.tcp\.log_debug</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Set ICMP Limits</descr>
      <tunable>net\.inet\.icmp\.icmplim</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>TCP Offload Engine</descr>
      <tunable>net\.inet\.tcp\.tso</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>UDP Checksums</descr>
      <tunable>net\.inet\.udp\.checksum</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Maximum socket buffer size</descr>
      <tunable>kern\.ipc\.maxsockbuf</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Page Table Isolation \(Meltdown mitigation, requires reboot\.\)</descr>
      <tunable>vm\.pmap\.pti</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Disable Indirect Branch Restricted Speculation \(Spectre V2 mitigation\)</descr>
      <tunable>hw\.ibrs_disable</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Hide processes running as other groups</descr>
      <tunable>security\.bsd\.see_other_gids</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Hide processes running as other users</descr>
      <tunable>security\.bsd\.see_other_uids</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>Enable/disable sending of ICMP redirects in response to IP packets for which a better,
        and for the sender directly reachable, route and next hop is known\.
      </descr>
      <tunable>net\.inet\.ip\.redirect</tunable>
      <value>default</value>
    </item>
    <item>
      <descr>
        Redirect attacks are the purposeful mass-issuing of ICMP type 5 packets\. In a normal network, redirects
        to the end stations should not be required\. This option enables the NIC to drop all inbound ICMP redirect
        packets without returning a response\.
      </descr>
      <tunable>net\.inet\.icmp\.drop_redirect</tunable>
      <value>1</value>
    </item>
    <item>
      <descr>Maximum outgoing UDP datagram size</descr>
      <tunable>net\.local\.dgram\.maxdgram</tunable>
      <value>default</value>
    </item>
  </sysctl>
  <system>
    <optimization>normal</optimization>
    <hostname>firewall</hostname>
    <domain>example\.com</domain>
    <group>
      <name>admins</name>
      <description>System Administrators</description>
      <scope>system</scope>
      <gid>1999</gid>
      <member>0</member>
      <priv>page-all</priv>
    </group>
    <user>
      <name>root</name>
      <descr>System Administrator</descr>
      <scope>system</scope>
      <groupname>admins</groupname>
      <password>\$2y\$10\$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS</password>
      <uid>0</uid>
      <apikeys>
        <item>
          <key>Ku7rxJotUKNM\+SNQtMhL2yNzkp/XQF21ZY25HevhRER67eyUk2CyJQalvq51zd5bG5gYjS5b4pG4YnSS</key>
          <secret>\$6\$\$x\.ZrJq6a4Nue2upbwKxz/57wN50arCSH3vRUEzHFfU4wiF7CDPycSiCfkTJUUO2RdPOiwsOw0cuwv1zM85RSl0</secret>
        </item>
      </apikeys>
      <expires />
      <authorizedkeys />
      <ipsecpsk />
      <otp_seed />
    </user>
    <nextuid>2000</nextuid>
    <nextgid>2000</nextgid>
    <timezone>Etc/UTC</timezone>
    <timeservers>0\.opnsense\.pool\.ntp\.org 1\.opnsense\.pool\.ntp\.org 2\.opnsense\.pool\.ntp\.org 3\.opnsense\.pool\.ntp\.org</timeservers>
    <webgui>
      <protocol>https</protocol>
    </webgui>
    <disablenatreflection>yes</disablenatreflection>
    <usevirtualterminal>1</usevirtualterminal>
    <disableconsolemenu />
    <disablevlanhwfilter>1</disablevlanhwfilter>
    <disablechecksumoffloading>1</disablechecksumoffloading>
    <disablesegmentationoffloading>1</disablesegmentationoffloading>
    <disablelargereceiveoffloading>1</disablelargereceiveoffloading>
    <ipv6allow />
    <powerd_ac_mode>hadp</powerd_ac_mode>
    <powerd_battery_mode>hadp</powerd_battery_mode>
    <powerd_normal_mode>hadp</powerd_normal_mode>
    <bogons>
      <interval>monthly</interval>
    </bogons>
    <pf_share_forward>1</pf_share_forward>
    <lb_use_sticky>1</lb_use_sticky>
    <ssh>
      <group>admins</group>
    </ssh>
    <rrdbackup>-1</rrdbackup>
    <netflowbackup>-1</netflowbackup>
    <firmware version="1\.0\.1">
      <mirror />
      <flavour />
      <plugins />
      <type />
      <subscription />
      <reboot />
    </firmware>
    <dnsserver>198\.51\.100\.100</dnsserver>
    <language>en_US</language>
  </system>
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>vtnet0</if>
      <ipaddr>192\.0\.2\.10</ipaddr>
      <ipaddrv6 />
      <subnet>24</subnet>
      <gateway>WAN_GW</gateway>
      <blockpriv>on</blockpriv>
      <blockbogons>on</blockbogons>
      <media />
      <mediaopt />
      <dhcp6-ia-pd-len>0</dhcp6-ia-pd-len>
      <subnetv6 />
      <gatewayv6 />
    </wan>
    <lan>
      <if>vtnet1</if>
      <descr>Workstations</descr>
      <enable>1</enable>
      <spoofmac />
      <ipaddr>172\.16\.0\.1</ipaddr>
      <subnet>24</subnet>
    </lan>
    <lo0>
      <internal_dynamic>1</internal_dynamic>
      <descr>Loopback</descr>
      <enable>1</enable>
      <if>lo0</if>
      <ipaddr>127\.0\.0\.1</ipaddr>
      <ipaddrv6>::1</ipaddrv6>
      <subnet>8</subnet>
      <subnetv6>128</subnetv6>
      <type>none</type>
      <virtual>1</virtual>
    </lo0>
    <wireguard>
      <internal_dynamic>1</internal_dynamic>
      <enable>1</enable>
      <if>wireguard</if>
      <descr>WireGuard \(Group\)</descr>
      <type>group</type>
      <virtual>1</virtual>
    </wireguard>
    <opt0>
      <if>wg1</if>
      <descr>WGB</descr>
      <enable>1</enable>
      <lock>1</lock>
      <spoofmac />
    </opt0>
    <opt1>
      <if>vtnet2</if>
      <descr>Servers</descr>
      <enable>1</enable>
      <spoofmac />
      <ipaddr>172\.17\.0\.1</ipaddr>
      <subnet>24</subnet>
    </opt1>
    <opt2>
      <if>vtnet3</if>
      <descr>DMZ</descr>
      <enable>1</enable>
      <spoofmac />
      <ipaddr>172\.18\.0\.1</ipaddr>
      <subnet>24</subnet>
    </opt2>
  </interfaces>
  <dhcpd>
    <lan>
      <enable>1</enable>
      <gateway>172\.16\.0\.1</gateway>
      <ddnsdomainalgorithm>hmac-md5</ddnsdomainalgorithm>
      <numberoptions>
        <item />
      </numberoptions>
      <range>
        <from>172\.16\.0\.10</from>
        <to>172\.16\.0\.250</to>
      </range>
      <winsserver />
      <dnsserver>172\.16\.0\.1</dnsserver>
      <ntpserver />
    </lan>
    <opt1>
      <enable>1</enable>
      <gateway>172\.17\.0\.1</gateway>
      <ddnsdomainalgorithm>hmac-md5</ddnsdomainalgorithm>
      <numberoptions>
        <item />
      </numberoptions>
      <range>
        <from>172\.17\.0\.10</from>
        <to>172\.17\.0\.250</to>
      </range>
      <winsserver />
      <dnsserver>172\.17\.0\.1</dnsserver>
      <ntpserver />
    </opt1>
    <opt2>
      <enable>1</enable>
      <gateway>172\.18\.0\.1</gateway>
      <ddnsdomainalgorithm>hmac-md5</ddnsdomainalgorithm>
      <numberoptions>
        <item />
      </numberoptions>
      <range>
        <from>172\.18\.0\.10</from>
        <to>172\.18\.0\.250</to>
      </range>
      <winsserver />
      <dnsserver>172\.18\.0\.1</dnsserver>
      <ntpserver />
    </opt2>
  </dhcpd>
  <unbound>
    <enable>on</enable>
    <dnssec>on</dnssec>
    <dnssecstripped>on</dnssecstripped>
  </unbound>
  <snmpd>
    <syslocation />
    <syscontact />
    <rocommunity>public</rocommunity>
  </snmpd>
  <nat>
    <outbound>
      <mode>automatic</mode>
    </outbound>
  </nat>
  <filter>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <statetype>keep state</statetype>
      <direction>in</direction>
      <quick>1</quick>
      <protocol>udp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>51821</port>
      </destination>
    </rule>
    <rule>
      <type>pass</type>
      <ipprotocol>inet</ipprotocol>
      <descr>Default allow LAN to any rule</descr>
      <interface>lan</interface>
      <source>
        <network>lan</network>
      </source>
      <destination>
        <any />
      </destination>
    </rule>
    <rule>
      <type>pass</type>
      <ipprotocol>inet6</ipprotocol>
      <descr>Default allow LAN IPv6 to any rule</descr>
      <interface>lan</interface>
      <source>
        <network>lan</network>
      </source>
      <destination>
        <any />
      </destination>
    </rule>
    <rule>
      <type>pass</type>
      <interface>opt0</interface>
      <ipprotocol>inet</ipprotocol>
      <statetype>keep state</statetype>
      <direction>in</direction>
      <quick>1</quick>
      <protocol>tcp</protocol>
      <source>
        <network>opt0</network>
      </source>
      <destination>
        <network>opt0ip</network>
        <port>443</port>
      </destination>
    </rule>
  </filter>
  <rrd>
    <enable />
  </rrd>
  <load_balancer>
    <monitor_type>
      <name>ICMP</name>
      <type>icmp</type>
      <descr>ICMP</descr>
      <options />
    </monitor_type>
    <monitor_type>
      <name>TCP</name>
      <type>tcp</type>
      <descr>Generic TCP</descr>
      <options />
    </monitor_type>
    <monitor_type>
      <name>HTTP</name>
      <type>http</type>
      <descr>Generic HTTP</descr>
      <options>
        <path>/</path>
        <host />
        <code>200</code>
      </options>
    </monitor_type>
    <monitor_type>
      <name>HTTPS</name>
      <type>https</type>
      <descr>Generic HTTPS</descr>
      <options>
        <path>/</path>
        <host />
        <code>200</code>
      </options>
    </monitor_type>
    <monitor_type>
      <name>SMTP</name>
      <type>send</type>
      <descr>Generic SMTP</descr>
      <options>
        <send />
        <expect>220 \*</expect>
      </options>
    </monitor_type>
  </load_balancer>
  <ntpd>
    <prefer>0\.opnsense\.pool\.ntp\.org</prefer>
  </ntpd>
  <widgets>
    <sequence>system_information-container:00000000-col3:show,services_status-container:00000001-col4:show,gateways-container:00000002-col4:show,interface_list-container:00000003-col4:show</sequence>
    <column_count>2</column_count>
  </widgets>
  <revision>
    <username>\(system\)</username>
    <time>\d+\.\d+</time>
    <description>Created by OPNsense Configuration Generator v\d\.\d\.\d</description>
  </revision>
  <gateways>
    <gateway_item>
      <descr>Interface WAN Gateway</descr>
      <defaultgw>1</defaultgw>
      <ipprotocol>inet</ipprotocol>
      <interface>wan</interface>
      <gateway>192\.0\.2\.1</gateway>
      <monitor_disable>1</monitor_disable>
      <name>WAN_GW</name>
      <interval>1</interval>
      <weight>1</weight>
      <fargw>0</fargw>
    </gateway_item>
  </gateways>
  <OPNsense>
    <wireguard>
      <general version="0\.0\.1">
        <enabled>1</enabled>
      </general>
      <server version="0\.0\.4">
        <servers>
          <server uuid="[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}">
            <enabled>1</enabled>
            <name>WGBootstrap</name>
            <instance>1</instance>
            <pubkey>Pm76qcDtNmlPg3ecorCCiplqArUhP2YMYbehpodKwkQ=</pubkey>
            <privkey>w9aO9TLbNoHxic3TLzniwP7b4dVnmVETe5s60TsK33A=</privkey>
            <port>51821</port>
            <mtu />
            <dns />
            <tunneladdress>172\.19\.0\.1/24</tunneladdress>
            <disableroutes>0</disableroutes>
            <gateway />
            <peers>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}</peers>
          </server>
        </servers>
      </server>
      <client version="0\.0\.7">
        <clients>
          <client uuid="[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}">
            <enabled>1</enabled>
            <name>WGBootstrap</name>
            <pubkey>[a-zA-Z0-9+/]{43}=</pubkey>
            <psk />
            <tunneladdress>172\.19\.0\.2/32</tunneladdress>
            <serveraddress />
            <serverport />
            <keepalive />
          </client>
        </clients>
      </client>
    </wireguard>
  </OPNsense>
</opnsense>
