# strongswan-cli

```
apt-get install python-pip
python setup.py install
vpn-ikepolicy-create *default*
vpn-ipsecpolicy-create *default*
ipsec-site-connection-create conn1 --ikepolicy=*default* --ipsecpolicy=*default* --local-cidrs=*cidr1,cidr2* --peer-cidrs=*cidr1,cidr2* --peer-id=*peer-id* --peer-addr=*peer-addr* --psk=*passwd*
sl commit-all
```
