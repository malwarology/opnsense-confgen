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
          <pubkey>Ybc61c6eXt2wDmpVw92LSsmZFkQQiBDsHY24WZiziDQ=</pubkey>
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
