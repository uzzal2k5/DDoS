################## DDOS MITIGATION #####################################
#******************************************************************************************************************
#10.0.0.0/8 - RFC 1918 private networks address (used for larger networks)
#169.254.0.0/16 - link local networks address
#172.16.0.0/12 - RFC 1918 private networks Address
#127.0.0.0/8  -local address
#224.0.0.0/4 - Class D Multicast Addresses
#240.0.0.0/5 - Class E Reserved
#0.0.0.0/8 - UNSPEC broadcast
#248.0.0.0/5 - Reserved
#239.255.255.0/24
#255.255.255.255 - broadcast
#******* ACCEPTING WHAT WE NEED *******
iptables -A INPUT -p tcp --dport http -m state --ctstate NEW,ESTABLISHED -j ACCEPT


#********************************************************************************************************************
#A Martian packet is an IP packet which specifies a source or destination address that is reserved for special-use by
#Internet Assigned Numbers Authority (IANA). If seen on the public internet,
#these packets cannot actually originate as claimed, or be delivered.
#*************************************************************************
# eth1 is wan port on server ##
#*************************************************************
# MARTIANS PACKETS LOG
#*************************************************************

# Log martians packet(Log anything claiming it's from a local or non-routable network)
# If using one of these local networks, remove it
iptables -A INPUT -s 10.0.0.0/8 -j LOG --log-prefix "IP DROP SPOOF A: "
iptables -A INPUT -s 172.16.0.0/12 -j LOG --log-prefix "IP DROP SPOOF B: "
iptables -A INPUT -s 192.168.0.0/16 -j LOG --log-prefix "IP DROP SPOOF C: "
iptables -A INPUT -s 169.254.0.0/16 -j LOG --log-prefix "IP DROP MULTICAST "
iptables -A INPUT -s 224.0.0.0/4 -j LOG --log-prefix "IP DROP MULTICAST D: "
iptables -A INPUT -s 240.0.0.0/5 -j LOG --log-prefix "IP DROP SPOOF E: "
iptables -A INPUT -s 240.0.0.0/4 -j LOG --log-prefix "IP DROP "
iptables -A INPUT -s 248.0.0.0/5 -j LOG --log-prefix "IP DROP RESERVED "
iptables -A INPUT -s 239.255.255.0/24 -j LOG --log-prefix "IP DROP "
iptables -A INPUT -s 255.255.255.255/32 -j LOG --log-prefix "IP DROP "
iptables -A INPUT -s 168.254.0.0/16 -j LOG --log-prefix "IP DROP "
iptables -A INPUT -s 0.0.0.0/8 -j LOG --log-prefix "IP DROP "
iptables -A INPUT -d 127.0.0.0/8 -j LOG --log-prefix "IP DROP " 

#***********************************************************************
# Reject spoofed packets
#***********************************************************************
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -j DROP
iptables -A INPUT -d 192.168.0.0/16 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/4 -j DROP
iptables -A INPUT -d 240.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 248.0.0.0/5 -j DROP
iptables -A INPUT -d 248.0.0.0/5 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255/32 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -d 127.0.0.0/8 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
#*****************************************************************************
# Stop smurf attacks
#*****************************************************************************
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
iptables -A INPUT -p icmp -m icmp -j DROP
#*****************************************************************************
# Drop all invalid packets
#*****************************************************************************
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

#****************************************************************************************************
# Drop excessive RST packets to avoid smurf attacks
#****************************************************************************************************
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP


#*****************************************************************************************************
# Once the day has passed, remove them from the portscan list
#*****************************************************************************************************
iptables -A INPUT   -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

#******************************************************************************
# These rules add scanners to the portscan list, and log the attempt.
#******************************************************************************
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

#**************************************************************************************************
# Require hashlimit , expire in 1 min(60000 ms)
#*****************************NOT SUPPORTED v1.4.7*************************************************
iptables -A INPUT -p tcp  -m state --state NEW -m hashlimit --haslimit 1/hour --hashlimit-burst 2 --hashlimit-mode scrip --hashlimit-name http --hashlimit-htable-expire 60000 -j ACCEPT
iptables -I INPUT -p tcp  -m hashlimit -m tcp --hashlimit-above 20/sec --hashlimit-mode srcip --hashlimit-name http -m state --state NEW -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST,ACK SYN -j DROP
iptables -A INPUT -p tcp -m state --state NEW -j ACCEPT 

iptables -t raw -D PREROUTING -p tcp -m tcp --syn -j CT --notrack
iptables -D INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -D INPUT -m conntrack --ctstate INVALID -j DROP

#**********************BRUTE FORCE ******************************************************
#filter for  brute-force attacks
#filter for brute-force attackers allowing new connection in 20 seconds
#requires xt_TARPIT
#****************************************************************************************
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
iptables -I INPUT -p tcp --dport http -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport http -m state --state NEW -m recent --update --seconds 20 --hitcount 10 -j DROP


#****************************PORT SCAN ****************************************************************
# Attempt to block portscans
# Anyone who tried to portscan is locked out for an entire day.
#****************************************************************************************************
iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP























