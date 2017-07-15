# strongswan-cli

1. apt-get install python-pip
2. python setup.py install
3. vpn-ikepolicy-create *default*
4. vpn-ipsecpolicy-create *default*
5. ipsec-site-connection-create *conn1* --ikepolicy=*default* --ipsecpolicy=*default* --local-cidrs=*cidr1,cidr2* --peer-cidrs=*cidr1,cidr2* --peer-id=*peer-id* --peer-addr=*peer-addr* --psk=*passwd*
6. sl commit-all
