
// control::ControlSocket("TCP", 6777);

// dhcp ip lease pool for this AP
leases :: LeasePool( ETH 9c:d3:6d:10:a9:b8, IP 192.168.0.1, 
                    MASK 255.255.255.0, DNS 8.8.8.8, 
                    START 192.168.0.100, END 192.168.0.254 );

// local offload agent
sdn_agent::SdnAgent(MAC 9c:d3:6d:10:a9:b8, CTRL_IP 192.168.3.30, 
                    AP_IP 192.168.0.1, INTERVAL 2, 
                    LEASES leases,
                    SHELL_PATH "/home/yfliu/Development/sdn/click/elements/local/agent/change_hostapd_channel.sh");

// receive messages from master server on port 6777
agent_socket::Socket(UDP, 0.0.0.0, 6777)
    -> [0]sdn_agent;

// send packets to master server
sdn_agent[0] -> master_socket::Socket(UDP, 192.168.3.62, 26284);

// send packets from agent to client
sdn_agent[1]
    -> q::Queue(1000)
    -> to_dev::ToDevice(wlan1);

// sniffer 802.11 packet
FromDevice(mon.wlan1)
// -> prism2_decap :: Prism2Decap()
// -> extra_decap :: ExtraDecap()
// -> AthdescDecap()
    -> RadiotapDecap()
    -> extra_decap :: ExtraDecap()
    -> phyerr_filter :: FilterPhyErr()
    -> tx_filter :: FilterTX()
    -> dupe :: WifiDupeFilter() 
    -> wifi_cl :: Classifier(0/08%0c 1/01%03, //data
                         0/00%0c); //mgt

wifi_cl [0] -> Discard;

wifi_cl [1]
    // -> PrintWifi
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


