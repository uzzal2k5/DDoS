#https://www.upcloud.com/support/configuring-iptables-on-centos-6-5/
iptables -F
iptables -A INPUT -j ACCEPT
iptables -A OUTPUT -j ACCEPT
iptables -A FORWARD -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -i lo -j ACCEPT
#******* ACCEPTING WHAT WE NEED *********
iptables -A INPUT -p tcp --dport http -j ACCEPT
iptables -A INPUT -p tcp --dport ssh  -j ACCEPT

############## ANTI-DDOS RULES ##############################
#use the mangle table and the PREROUTING chain!

#*************** MSS ***************************** 
#Block Uncommon MSS( maximum segment size ) Values
#*************************************************
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

#********************************************************
# Block Packets With Bogus TCP Flags
#blocks packets that use bogus TCP flags
#********************************************************
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

#*************************************************
#Block Packets From Private Subnets (Spoofing)
#*************************************************
iptables -t mangle -A PREROUTING -s 10.0.0.0/8  -j DROP
iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 224.0.0.0/4 -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/4 -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
iptables -t mangle -A PREROUTING -s 248.0.0.0/5 -j DROP
iptables -t mangle -A PREROUTING -s 239.255.255.0/24 -j DROP
iptables -t mangle -A PREROUTING -s 255.255.255.255/32 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP

**************
# DROP ICMP
# mitigate Ping of Death (ping flood), ICMP flood and ICMP fragmentation flood.
# Stop smurf attacks
#*****************************************************************************
iptables -t mangle -A PREROUTING -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -t mangle -A PREROUTING -p icmp -m icmp --icmp-type timestamp-request -j DROP
iptables -t mangle -A PREROUTING -p icmp -j DROP

#*************  SYN PACKET *********************************************
# Block Invalid Packets
# blocks all packets that are not a SYN packet and don't belong to an established TCP connection.
#**********************************************************************
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

#*********************LIMIT RST PACKETS**********************
#limits incoming TCP RST packets to mitigate TCP RST floods 
#Effectiveness of this rule is questionable.
#************************************************************
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP


#************************************************
# Connection Limiting
#***********************************************
iptables -A INPUT -p tcp -m connlimit --connlimit-above 100 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP

#*******************************************
# This rule blocks fragmented packets
#*******************************************
iptables -t mangle -A PREROUTING -f -j DROP



#************SYNPROXY***************
#Mitigating SYN Floods With SYNPROXY
#available in its 3.10 default kernel
# Verify using  'watch -n1 cat /proc/net/stat/synproxy'
#***********************************

#iptables -A INPUT -p tcp  -m state --state NEW -m hashlimit --haslimit 1/hour --hashlimit-burst 2 --hashlimit-mode scrip --hashlimit-name http --hashlimit-htable-expire 60000 -j ACCEPT
#iptables -I INPUT -p tcp  -m hashlimit -m tcp --hashlimit-above 20/sec --hashlimit-mode srcip --hashlimit-name http -m state --state NEW -j DROP
#iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST,ACK SYN -j DROP
#iptables -A INPUT -p tcp -m state --state NEW -j ACCEPT 

#iptables -t raw -D PREROUTING -p tcp -m tcp --syn -j CT --notrack
#iptables -D INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
#iptables -D INPUT -m conntrack --ctstate INVALID -j DROP

#********** BRUTE FORCE*********
# SSH brute-force protection 
#*******************************
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

#********** PORT SCAN ******************
# Protection against port scanning 
#***************************************
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP
