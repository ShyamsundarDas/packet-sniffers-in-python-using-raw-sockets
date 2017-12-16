Basic Sniffer

Sniffers are programs that can capture/sniff/detect network traffic packet by packet and analyse them for various reasons. Commonly used in the field of network security. Wireshark is a very common packet sniffer/protocol analyzer. Packet sniffers can be written in python too. In this article we are going to write a few very simple sniffers in python for the linux platform. Linux because, although python is a portable, the programs wont run or give similar results on windows for example. This is due to difference in the implementation of the socket api.
---------------------------------------------------------------------------------------------------
Parsing the sniffed packet:-The code breaks down the packet into IP Header + TCP Header + Data.
Refer:-packetcap.py
The code sniff and parse a TCP packet.

Note :

1. The above sniffer picks up only TCP packets, because of the declaration :
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

For UDP and ICMP the declaration has to be :
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

You might be tempted to think of doing :
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

but this will not work , since IPPROTO_IP is a dummy protocol not a real one.

2. This sniffer picks up only incoming packets.

3. This sniffer delivers only IP frames , which means ethernet headers are not available.
---------------------------------------------------------------------------------------------------
Refer:-packetcapture.py

Sniff all data with ethernet header:

This line :
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

needs to be changed to :

s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))

Now the same socket will receive :

1. All incoming and outgoing traffic.

2. All Ethernet frames , which means all kinds of IP packets(TCP , UDP , ICMP) and even other kinds of packets(like ARP) if there are any.

3. It will also provide the ethernet header as a part of the received packet.
It parses the Ethernet header and also the UDP and ICMP headers.
