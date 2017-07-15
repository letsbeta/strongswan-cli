# auto generated configuration, any manually changes will lost
config setup

conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        authby=psk
        mobike=no

{% for ipsec_site_connection in cfg.ipsec.connections%}
{% if not ipsec_site_connection.admin_state_down %}
{% if ipsec_site_connection.ikepolicy.ike_version == 'ikev1' %}
{% for left in ipsec_site_connection['local_cidrs']|splitby(',') %}
{% set outer_loop = loop %}
{% for right in ipsec_site_connection['peer_cidrs']|splitby(',') %}
conn {{ipsec_site_connection.name}}{{outer_loop.index0}}x{{loop.index0}}
    keyexchange={{ipsec_site_connection.ikepolicy.ike_version}}
    left={{ipsec_site_connection.local_id}}
    leftsubnet={{left}}
    leftid={{ipsec_site_connection.local_id}}
    leftfirewall=yes
    right={{ipsec_site_connection.peer_addr}}
    rightsubnet={{right}}
    rightid={{ipsec_site_connection.peer_id}}
    auto={{ipsec_site_connection.initiator}}
    dpdaction={{ipsec_site_connection.dpd_action}}
    dpddelay={{ipsec_site_connection.dpd_interval}}s
    dpdtimeout={{ipsec_site_connection.dpd_timeout}}s
    ike={{ipsec_site_connection.ikepolicy.encryption_algorithm}}-{{ipsec_site_connection.ikepolicy.auth_algorithm}}-{{ipsec_site_connection.ikepolicy.pfs}}
    ikelifetime={{ipsec_site_connection.ikepolicy.ike_lifetime}}s
    {% if ipsec_site_connection.ipsecpolicy.transform_protocol == "ah" %}
    ah={{ipsec_site_connection.ipsecpolicy.auth_algorithm}}-{{ipsec_site_connection.ipsecpolicy.pfs}}
    {% else %}
    esp={{ipsec_site_connection.ipsecpolicy.encryption_algorithm}}-{{ipsec_site_connection.ipsecpolicy.auth_algorithm}}-{{ipsec_site_connection.ipsecpolicy.pfs}}
    {% endif %}
    lifetime={{ipsec_site_connection.ipsecpolicy.ipsec_lifetime}}s
    type={{ipsec_site_connection.ipsecpolicy.encapsulation_mode}}

{% endfor %}
{% endfor %}
{% else %}
conn {{ipsec_site_connection.name}}
    keyexchange={{ipsec_site_connection.ikepolicy.ike_version}}
    left={{ipsec_site_connection.local_id}}
    leftsubnet={{ipsec_site_connection['local_cidrs']}}
    leftid={{ipsec_site_connection.local_id}}
    leftfirewall=yes
    right={{ipsec_site_connection.peer_addr}}
    rightsubnet={{ipsec_site_connection['peer_cidrs']}}
    rightid={{ipsec_site_connection.peer_id}}
    auto={{ipsec_site_connection.initiator}}
    dpdaction={{ipsec_site_connection.dpd_action}}
    dpddelay={{ipsec_site_connection.dpd_interval}}s
    dpdtimeout={{ipsec_site_connection.dpd_timeout}}s
    ike={{ipsec_site_connection.ikepolicy.encryption_algorithm}}-{{ipsec_site_connection.ikepolicy.auth_algorithm}}-{{ipsec_site_connection.ikepolicy.pfs}}
    ikelifetime={{ipsec_site_connection.ikepolicy.ike_lifetime}}s
    {% if ipsec_site_connection.ipsecpolicy.transform_protocol == "ah" %}
    ah={{ipsec_site_connection.ipsecpolicy.auth_algorithm}}-{{ipsec_site_connection.ipsecpolicy.pfs}}
    {% else %}
    esp={{ipsec_site_connection.ipsecpolicy.encryption_algorithm}}-{{ipsec_site_connection.ipsecpolicy.auth_algorithm}}-{{ipsec_site_connection.ipsecpolicy.pfs}}
    {% endif %}
    lifetime={{ipsec_site_connection.ipsecpolicy.ipsec_lifetime}}s
    type={{ipsec_site_connection.ipsecpolicy.encapsulation_mode}}

{% endif %}
{% endif %}
{% endfor %}
