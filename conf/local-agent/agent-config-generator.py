#!/usr/bin/python
import argparse

# parse arguments with argparse package
parser = argparse.ArgumentParser(description='description: '
    'config generator for SoftOffload agent')
parser.add_argument('--mac', dest='mac', type=str, required=True, 
    help='wireless interface MAC address of this AP, e.g. '
        + '"00:00:00:00:00:01"')

# dhcp
parser.add_argument('--gateway_ip', dest='gateway_ip', type=str, 
    default="192.168.0.1", help='IP string for gateway of this AP, e.g. '
        + '"192.168.0.1"')
parser.add_argument('--mask', dest='mask', type=str, 
    default="255.255.255.0", help="DHCP address mask")
parser.add_argument('--dns', dest='dns', type=str, 
    default="8.8.8.8", help="DHCP dns option")
parser.add_argument('--start_ip', dest='start', type=str, 
    default="192.168.0.100", help="DHCP lease start IP")
parser.add_argument('--end_ip', dest='end', type=str, 
    default="192.168.0.250", help="DHCP lease end IP")

# agent
parser.add_argument('--agent_port', dest='agent_port', type=int, 
    default=6777, help="agent listening port for messages from master")
parser.add_argument('--agent_ip', dest='agent_ip', type=str, required=True, 
    help="agent src IP address for communicate to master")
parser.add_argument('--interval', dest='interval', type=int, 
    default=2, help="interval (second) to report agent statistics to master")

# master
parser.add_argument('--master_port', dest='master_port', type=int, 
    default=26284, help="udp port on master")
parser.add_argument('--master_ip', dest='master_ip', type=str, required=True, 
    help="master IP address, e.g. 192.168.3.1")

# device
parser.add_argument('--dev', dest='dev', type=str, required=True, 
    help="dev name for the wireless interface, e.g. wlan1")
parser.add_argument('--mon', dest='mon', type=str, required=True, 
    help="monitoring dev name for the wireless interface, e.g. mon.wlan1")

args = parser.parse_args()

# print config
print """// agent config

// dhcp ip lease pool for this AP
leases :: LeasePool( ETH %s, IP %s, 
                    MASK %s, DNS %s, 
                    START %s, END %s );
""" % (args.mac, args.gateway_ip, args.mask, args.dns, args.start, args.end)

print """
// local offload agent
sdn_agent::SdnAgent(MAC %s, CTRL_IP %s, 
                    AP_IP %s, INTERVAL %d, 
                    LEASES leases,
                    SHELL_PATH "this is not required anymore");

// receive messages from master server on port %d
agent_socket::Socket(UDP, 0.0.0.0, %d)
    -> [0]sdn_agent;

// send packets to master server
sdn_agent[0] -> master_socket::Socket(UDP, %s, %d);
""" % (args.mac, args.agent_ip, args.gateway_ip, args.interval, 
        args.agent_port, args.agent_port, args.master_ip, args.master_port)

print """
// send packets from agent to client
sdn_agent[1]
    -> q::Queue(1000)
    -> to_dev::ToDevice(%s);

// sniffer 802.11 packet
FromDevice(%s)
// -> prism2_decap :: Prism2Decap()
// -> extra_decap :: ExtraDecap()
// -> AthdescDecap()
    -> RadiotapDecap()
    -> extra_decap :: ExtraDecap()
    -> phyerr_filter :: FilterPhyErr()
    -> tx_filter :: FilterTX()
    -> dupe :: WifiDupeFilter() 
    -> wifi_cl :: Classifier(0/08%%0c 1/01%%03, //data
                         0/00%%0c); //mgt
""" % (args.dev, args.mon)

print """

wifi_cl [0] -> Discard;

wifi_cl [1]
    -> mgt_cl :: Classifier(0/a0%f0, // disassoc
                        0/c0%f0, // deauth
                        -);

mgt_cl[0] 
    -> Print(Disassoc) 
    -> [1]sdn_agent;

mgt_cl[1] 
    -> Print(Deauth) 
    -> [1]sdn_agent;

mgt_cl[2] -> Discard;

// OUTBOUND = true means capture packets from two directions
FromDevice(wlan1, OUTBOUND true)
    -> Classifier(12/0800)
    -> CheckIPHeader(14, CHECKSUM true)
    -> ip_class :: IPClassifier(icmp type echo-reply, dst udp port 67, dst udp port 6777, -)

ip_class[0]
    -> [4]sdn_agent; 
    // -> [1]server_offer::DHCPServerOffer(leases);

// dhcp packets
ip_class[1]
    -> CheckDHCPMsg
    -> dhcp_class :: DHCPClassifier( discover, request, release, -);

dhcp_class[0] -> Print(DISCOVER) 
    -> [0]server_offer::DHCPServerOffer(leases);

dhcp_class[1] -> Print(REQUEST)
    ->[2]sdn_agent;
    // -> [2]sdn_agent[1]
    // -> q::Queue(1000)
    // -> to_dev::ToDevice(wlan1);

dhcp_class[2] -> Print(RELEASE) 
    -> DHCPServerRelease(leases);
     
dhcp_class[3] -> Print(OTHER) -> Discard;

ip_class[2]
    -> Print
    -> [3]sdn_agent;

ip_class[3]
    -> [5]sdn_agent[2]
    -> Discard;

server_offer[0]
    -> q;
"""
