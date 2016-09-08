#!/bin/sh
iptables -t nat -F OUTPUT
ipset create whitelist hash:ip counters timeout 86400
ipset create blacklist hash:ip counters timeout 86400
iptables -t nat -A OUTPUT -m set --match-set whitelist dst -j LOG --log-macdecode --log-prefix ipsetmagic_whitelist
iptables -t nat -A OUTPUT -m set --match-set whitelist dst -j RETURN
iptables -t nat -A OUTPUT -m set --match-set blacklist dst -j LOG --log-macdecode --log-prefix ipsetmagic_blacklist
iptables -t nat -A OUTPUT -m set --match-set blacklist dst -j RETURN
iptables -t nat -A OUTPUT -m owner --uid-owner 0 -d 121.199.7.125 -p tcp --dport 80 -j REDIRECT --to-port 7070
