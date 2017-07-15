# auto generated configuration, any manually changes will lost
{% for ipsec_site_connection in cfg.ipsec.connections %}
{{ipsec_site_connection.local_id}} {{ipsec_site_connection.peer_id}} : PSK "{{ipsec_site_connection.psk}}"
{% endfor %}