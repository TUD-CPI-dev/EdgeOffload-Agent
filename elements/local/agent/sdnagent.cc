/*
* sdnagent.{cc,hh} -- An agent for the wireless sdn system
* Yanhe Liu <yanhe.liu@cs.helsinki.fi>
*
* Copyright (c) 2015 University of Helsinki
*
* Permission is hereby granted, free of charge, to any person obtaining a
* copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, subject to the conditions
* listed in the Click LICENSE file. These conditions include: you must
* preserve this copyright notice, and you cannot mention the copyright
* holders in advertising related to the Software without their permission.
* The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
* notice is a summary of the Click LICENSE file; the license in that file is
* legally binding.
*/

#include <stdlib.h>
#include <sys/time.h>

#include <click/config.h>
#include <click/glue.hh>
#include <click/error.hh>
#include <click/args.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <clicknet/wifi.h>
#include <click/atomic.hh>

#include "sdnagent.hh"
#include "dhcp/dhcp_common.hh"
#include "dhcp/dhcpoptionutil.hh"

#define MESSAGE_END '\n'
#define ICMP_ID 1
#define MAX_PING_LOST_NUM 5

CLICK_DECLS

SdnAgent::SdnAgent() : _timer(this)
{
}

SdnAgent::~SdnAgent()
{
}

int
SdnAgent::initialize(ErrorHandler*)
{
    // _cmd = "/home/yfliu/Development/sdn/change_hostapd_channel.sh";

    _count = 0;
    _timer.initialize(this);
    _timer.schedule_after_sec(10);
    return 0;
}

/********** important change 10.07.2015 *************
*
* 1) rate statistics is not performed on click agent anymore
* due to inherent measurement errors of click
* 2) now this timer is only used to perform keep-alive pings
*
*****************************************************/

void
SdnAgent::run_timer(Timer*)
{
    uint32_t headroom = Packet::default_headroom;
    Packet *_packet;
    Packet *_ping_packet;
    StringAccum _sa;
    String _payload;
    // String r1, r2;

    /*
    // clear old agent rates if there is no client
    if (_client_table.empty()) {
        _byte_up_rate.update(0);
        _byte_down_rate.update(0);
    }

    // send agent rate messages to master controller
    r1 = String(_byte_up_rate.scaled_average());
    r2 = String(_byte_down_rate.scaled_average());
    if (r1 != "" && r2 != "") {
        _sa << "agentrate|" << r1 << "|" << r2 << "|\n";
        _payload = _sa.take_string();
        _packet = Packet::make(headroom, _payload.data(), _payload.length(), 0);
        output(0).push(_packet);
    } */
    
    // logic for client
    for (HashTable<EtherAddress, Client>::iterator it = _client_table.begin(); 
        it.live(); it++) {
        
        // no response to keep-alive ping
        if (it.value()._ping_lost_num == MAX_PING_LOST_NUM) {
            // generate the inform packet to master server
            _sa.clear();
            _sa << "clientdisconnect|" << it.value()._mac.unparse_colon().c_str() << "|\n";
            _payload = _sa.take_string();
            _packet = Packet::make(headroom, _payload.data(), _payload.length(), 0);
            // send inform packet to master
            output(0).push(_packet);
            _client_table.erase(it); // delete client from hash table
            click_chatter("%p{element}: client %s is not alive", 
                                this, it.value()._mac.unparse_colon().c_str());
            
            continue;
        }
        
        // send keep alive testing ping
        _ping_packet = make_ping_request(it.value()._ipaddr, it.value()._mac);
        // click_chatter("ping packet len: %d\n", _packet->length());
        output(1).push(_ping_packet);
        it.value()._ping_lost_num++;
        
        /*
        // send client rate
        _sa.clear();
        r1 = String((float)it.value()._byte_up_count / _interval);
        it.value()._byte_up_count = 0;
        r2 = String((float)it.value()._byte_down_count / _interval);
        it.value()._byte_down_count = 0;
        // r1 = String(it.value()._byte_up_rate.scaled_average());
        // r2 = String(it.value()._byte_down_rate.scaled_average());

        // debug
        // click_chatter("%d, %d", it.value()._byte_down_rate.scaled_average(), it.value()._byte_down_rate.rate());


        if (r1 != "" && r2 != "") {
            _sa << "clientrate|" << it.value()._mac.unparse_colon().c_str() <<
                "|" << it.value()._ipaddr.unparse().c_str() << "|" << r1 << 
                "|" << r2 << "|\n";
            _payload = _sa.take_string();
            _packet = Packet::make(headroom, _payload.data(), 
                                    _payload.length(), 0);
            output(0).push(_packet);
        }
        */
    }

    _count++;
    // _packet->kill();
    // _ping_packet->kill();
    _timer.reschedule_after_sec(_interval);
}

int
SdnAgent::configure(Vector<String> &conf, ErrorHandler *errh)
{ 
    _interval = 5;
    if (Args(conf, this, errh)
        .read_mp("MAC", _mac)
        .read_m("CTRL_IP", _ipaddr)
        .read_m("AP_IP", _ap_ipaddr)
        .read_m("INTERVAL", _interval)
        .read_mp("LEASES", ElementCastArg("DHCPLeaseTable"), _leases)
        .read_m("SHELL_PATH", _cmd)
        .complete() < 0) {
        return -1;
    }

  return 0;
}

void 
SdnAgent::add_client(EtherAddress eth, IPAddress ip)
{
    if (_client_table.find(eth) == _client_table.end()) {
        Client new_client;
        new_client._mac = eth;
        new_client._ipaddr = ip;
        new_client._ping_lost_num = 0;
        // new_client._byte_up_count = 0;
        // new_client._byte_down_count = 0;

        _client_table.set(eth, new_client);
    }

    return;
}

/** 
* This element has 3 input ports and 3 output ports.
*cket:
* In-port-0: ip encapsulated packets from master controller
* In-port-1: wifi disassociate/deauth packets
* In-port-2: dhcp packets
* In-port-3: packets sent from client to agent's specific control port
* In-port-4: icmp echo reply from client
* In-port-5: other ethernet encapsulated frame to/from client
*
* Out-port-0: management packets to master controller via a socket
* Out-port-1: packets to clients
* Out-port-2: other packets, let them through
* 
* Important changes 10.07.2015
* No action is performed for In-port-5 due to packet monitoring
* limitation of click
*/

void 
SdnAgent::push(int port, Packet *p)
{

    if (port == 0) {
        uint8_t *data = (uint8_t *) (p->data());
        uint8_t d[6], *ptr;
        int i, len;

        if (*data == 'c') {
            data++;
            for (i = 0; i < 6; i++) {
                d[i] = *data++;
                // click_chatter("%02x", d[i]);
            }
            EtherAddress mac_dst = EtherAddress(d);

            if (_client_table.find(mac_dst) != _client_table.end()) {
                Client *c = _client_table.get_pointer(mac_dst);
                IPAddress ip_dst = c->_ipaddr;
                click_chatter("%p{element}: server message to client %s", 
                                this, ip_dst.unparse().c_str());

                len = 0;
                for (ptr = data; *ptr != '\n' && *ptr != '\0'; ptr++) {
                    len++;
                }
                // click_chatter("%d", len);

                Packet *p_to_client = Packet::make(data, len);
                push_udp_to_client(p_to_client, ip_dst, mac_dst, 1);

            } else {
                click_chatter("%p{element}: can not find corresponding client, "
                                "ignore the message!", this);
            }
                
        } else if (*data == 'a') {
            ptr = ++data;
            String type = String(ptr, 2);
            if (type.equals("rm")) {
                data = data + 2;
                for (i = 0; i < 6; i++) {
                    d[i] = *data++;
                    // click_chatter("%02x", d[i]);
                }
                EtherAddress mac = EtherAddress(d);

                click_chatter("master cmd: remove client %s", mac.unparse_colon().c_str());
                if (_client_table.find(mac) != _client_table.end()) {
                    _client_table.erase(mac);
                }
            } else if (type.equals("ck")) { // check whether client exits
                uint32_t headroom =  Packet::default_headroom;
                Packet *_packet;
                StringAccum _data;
                String _payload;
                
                data = data + 2;
                for (i = 0; i < 6; i++) {
                    d[i] = *data++;
                    // click_chatter("%02x", d[i]);
                }
                EtherAddress mac = EtherAddress(d);

                click_chatter("master cmd: checking client %s", mac.unparse_colon().c_str());
                if (_client_table.find(mac) != _client_table.end()) {
                    // generate the inform packet for master server
                    Client *c = _client_table.get_pointer(mac);
                    _data << "client|" << mac.unparse_colon().c_str() << "|" << 
                        c->_ipaddr.unparse().c_str() << "\n";
                    _payload = _data.take_string();
                    _packet = Packet::make(headroom, _payload.data(), _payload.length(), 0);
                    output(0).push(_packet);
                }

            } else if (type.equals("cn")) {
                StringAccum sa;
                String command;
                String channel;
                data = data + 2;
                if (*data == '1') {
                    channel = String(++data, 1);
                } else if (*data == '2') {
                    channel = String(++data, 2);
                }

                sa << _cmd.c_str() << " " << channel;
                command = sa.take_string();
                
                click_chatter("%p{element}: receive master command to change channel", this);
                // click_chatter("%s", command.data());

                system(command.data());
            }
        }

    } else if (port == 1) { // wifi disconnection
        if (p->length() < sizeof(struct click_wifi)) {
            click_chatter("%p{element}: packet too small: %d vs %d\n",
                this,
                p->length(),
                sizeof(struct click_wifi));
        } else {
            // uint8_t dir;
            uint8_t type;
            uint8_t subtype;

            struct click_wifi *w = (struct click_wifi *) p->data();

            // dir = w->i_fc[1] & WIFI_FC1_DIR_MASK;
            type = w->i_fc[0] & WIFI_FC0_TYPE_MASK;
            subtype = w->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

            if (type != WIFI_FC0_TYPE_MGT) {
                click_chatter("%p{element}: received non-management packet\n", this);
                return;
            }

            if (subtype == WIFI_FC0_SUBTYPE_DEAUTH 
                || subtype == WIFI_FC0_SUBTYPE_DISASSOC) {
                disconnect_responder(w);
            }
        }  

    } else if (port == 2) {

        send_dhcp_ack_or_nak(1, p);

    } else if (port == 3) { // packets from client to agent control port
        uint32_t header_len = sizeof(click_ether) + sizeof(click_udp) 
                                + sizeof(click_ip);
        uint8_t *data = (uint8_t *) (p->data() + header_len);
        uint32_t len = p->length() - header_len;
        
        // if occasionally another packet data starts with "s|", there will be
        // a packet miss-judgement
        if (*data++ == 's' && *data++ == '|') {
            click_chatter("%c", *data);
            Packet *_packet = Packet::make(Packet::default_headroom, data, len-2, 0);
            click_chatter("%p{element}: client message to master", this);
            output(0).push(_packet);
        } else {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            double time_in_mill = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
            click_chatter("reconnection: %f\n", time_in_mill);
        }
    } else if (port == 4) { // icmp
        const click_ether *eth = p->ether_header();
        const click_ip *ip_header = p->ip_header();
        const click_icmp_echo *icmp_header = reinterpret_cast<const click_icmp_echo *>(p->icmp_header());

        if (p->has_network_header() && ip_header->ip_p == IP_PROTO_ICMP
                && p->transport_length() >= (int)sizeof(click_icmp_echo)
                && icmp_header->icmp_type == ICMP_ECHOREPLY
                && icmp_header->icmp_identifier == ICMP_ID
                && icmp_header->icmp_sequence == _icmp_sequence) {

            EtherAddress eth_src = EtherAddress((unsigned char *)eth->ether_shost);
            if (_client_table.find(eth_src) != _client_table.end()) {
                Client *c = _client_table.get_pointer(eth_src);
                (c->_ping_lost_num) = 0;
            }
        }
        
    } else if (port == 5) { // statisitcs, not used anymore
        /*
        // _byte_rate.update(p->length()); // overall rate

        // here is a bug
        // if no packet in, the _byte_rate will be the same, and 
        // never be updated

        click_ether *eh = (click_ether *) p->data();
        EtherAddress eth_src = EtherAddress((unsigned char *)eh->ether_shost);
        EtherAddress eth_dst = EtherAddress((unsigned char *)eh->ether_dhost);

        if (_client_table.find(eth_src) != _client_table.end()) {
            Client *c = _client_table.get_pointer(eth_src);
            // c->_byte_up_rate.update(p->length());
            c->_byte_up_count += (long)p->length();
            _byte_up_rate.update(p->length());
            click_chatter("up packet len: %d\n", p->length());
        } else if (_client_table.find(eth_dst) != _client_table.end()) {
            Client *c = _client_table.get_pointer(eth_dst);
            // c->_byte_down_rate.update(p->length());
            c->_byte_down_count += (long)p->length();
            _byte_down_rate.update(p->length());
            click_chatter("down packet length: %d\n", p->length());
        }
        */

        // do nothing
        output(2).push(p); 
    }

    p->kill();
}

void 
SdnAgent::send_dhcp_ack_or_nak(int port, Packet *p)
{
    click_ether *eh = (click_ether *) p->data();
    dhcpMessage *req_msg
        = (dhcpMessage*)(p->data() + sizeof(click_ether) +
                 sizeof(click_udp) + sizeof(click_ip));
    Packet *q = 0;
    IPAddress ciaddr = IPAddress(req_msg->ciaddr);
    EtherAddress eth(req_msg->chaddr);
    IPAddress requested_ip = IPAddress(0);
    Lease *lease = _leases->rev_lookup(eth);
    IPAddress server = IPAddress(0);
    const uint8_t *o = DHCPOptionUtil::fetch(p, DHO_DHCP_SERVER_IDENTIFIER, 4);
    if (o)
        server = IPAddress(o);
    
    o = DHCPOptionUtil::fetch(p, DHO_DHCP_REQUESTED_ADDRESS, 4);
    if (o)
        requested_ip = IPAddress(o);

    if (!ciaddr && !requested_ip) {
        /* this is outside of the spec, but dhclient seems to
           do this, so just give it an address */
        if (!lease) {
            lease = _leases->new_lease_any(eth);
        }
        if (lease) {
            q = make_ack_packet(p, lease);
        }
    } else if (server && !ciaddr && requested_ip) {
        /* SELECTING */
        if(lease && lease->_ip == requested_ip) {
            q = make_ack_packet(p, lease);
            lease->_valid = true;
        }
    } else if (!server && requested_ip && !ciaddr) {
        /* INIT-REBOOT */
        bool network_is_correct = true;
        if (!network_is_correct) {
            q = make_nak_packet(p, lease);
        } else {      
            if (lease && lease->_ip == requested_ip) {
                if (lease->_end <  Timestamp::now() ) {
                    q = make_nak_packet(p, lease);
                } else {
                    lease->_valid = true;
                    q = make_ack_packet(p, lease);
                }
            }
        }
    } else if (!server && !requested_ip && ciaddr) {
        /* RENEW or REBIND */
        if (lease) {
            lease->_valid = true;
            lease->extend();
            q = make_ack_packet(p, lease);
        }
    } else {
        click_chatter("%s:%d\n", __FILE__, __LINE__);
    }
    
    if (q) {
        
        Packet *o = DHCPOptionUtil::push_dhcp_udp_header(q, _leases->_ip);
        WritablePacket *s = o->push_mac_header(14);
        
        click_ether *eh2 = (click_ether *)s->data();
        memcpy(eh2->ether_shost, _leases->_eth.data(), 6);
        memcpy(eh2->ether_dhost, eh->ether_shost, 6);
        memset(eh2->ether_dhost, 0xff, 6);
        eh2->ether_type = htons(ETHERTYPE_IP);
        output(port).push(s);
    }
}

Packet*
SdnAgent::make_ack_packet(Packet *p, Lease *lease)
{
    dhcpMessage *req_msg 
      = (dhcpMessage*)(p->data() + sizeof(click_ether) + 
               sizeof(click_udp) + sizeof(click_ip));
    WritablePacket *ack_q = Packet::make(sizeof(dhcpMessage));
    memset(ack_q->data(), '\0', ack_q->length());
    dhcpMessage *dhcp_ack =
        reinterpret_cast<dhcpMessage *>(ack_q->data());
    uint8_t *options_ptr;

    // add for sdn testing
    uint32_t headroom =  Packet::default_headroom;
    Packet *_packet;
    StringAccum _data;
    String _payload;

    dhcp_ack->op = DHCP_BOOTREPLY;
    dhcp_ack->htype = ARPHRD_ETHER;
    dhcp_ack->hlen = 6;
    dhcp_ack->hops = 0;
    dhcp_ack->xid = req_msg->xid; 
    dhcp_ack->secs = 0;
    dhcp_ack->flags = 0;
    dhcp_ack->ciaddr = req_msg->ciaddr;
    dhcp_ack->yiaddr = lease->_ip;
    dhcp_ack->siaddr = 0;
    dhcp_ack->flags = req_msg->flags;
    dhcp_ack->giaddr = req_msg->giaddr;
    memcpy(dhcp_ack->chaddr, req_msg->chaddr, 16);
    dhcp_ack->magic = DHCP_MAGIC;  
    
    options_ptr = dhcp_ack->options;
    *options_ptr++ = DHO_DHCP_MESSAGE_TYPE;
    *options_ptr++ = 1;
    *options_ptr++ = DHCP_ACK;
    *options_ptr++ = DHO_DHCP_LEASE_TIME;
    *options_ptr++ = 4;
    uint32_t duration = lease->_duration.sec(); 
    duration = htonl(duration);
    memcpy(options_ptr, &duration, 4);
    options_ptr += 4;
    *options_ptr++ = DHO_DHCP_SERVER_IDENTIFIER;
    *options_ptr++ = 4;
    uint32_t server_ip = _leases->_ip;
    memcpy(options_ptr, &server_ip, 4);
    options_ptr += 4;
  
    // subnet mask
    *options_ptr++ = DHO_SUBNET_MASK;
    uint32_t server_mask = _leases->_subnet;
    *options_ptr++ = 4;
    memcpy(options_ptr, &server_mask, 4);
    options_ptr += 4;
    
    // router
    *options_ptr++ = DHO_ROUTERS;
    uint32_t router = _leases->_ip;
    *options_ptr++ = 4;
    memcpy(options_ptr, &router, 4);
    options_ptr += 4;

    // dns
    *options_ptr++ = DHO_DOMAIN_NAME_SERVERS;
    uint32_t dns = _leases->_dns;
    *options_ptr++ = 4;
    memcpy(options_ptr, &dns, 4);
    options_ptr += 4;
    
    *options_ptr = DHO_END;


    // generate the inform packet for master server
    EtherAddress eth_src = EtherAddress((unsigned char *)req_msg->chaddr);
    IPAddress ip_src = IPAddress(lease->_ip);
    if (_client_table.find(eth_src) == _client_table.end()) {
        _data << "client|" << eth_src.unparse_colon().c_str() << "|" << 
            ip_src.unparse().c_str() << "\n";
        _payload = _data.take_string();
        _packet = Packet::make(headroom, _payload.data(), _payload.length(), 0);
        output(0).push(_packet);
    }

    // add client info to agent hash table
    add_client(eth_src, ip_src);
    
    return ack_q;
}

Packet*
SdnAgent::make_nak_packet(Packet *p, Lease *)
{
    dhcpMessage *req_msg =
      (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));
  
    WritablePacket *nak_q = Packet::make(sizeof(dhcpMessage));
    memset(nak_q->data(), '\0', nak_q->length());
    dhcpMessage *dhcp_nak =
        reinterpret_cast<dhcpMessage *>(nak_q->data());
    uint8_t *options_ptr;
    
    dhcp_nak->op = DHCP_BOOTREPLY;
    dhcp_nak->htype = ARPHRD_ETHER;
    dhcp_nak->hlen = 6;
    dhcp_nak->hops = 0;
    dhcp_nak->xid = req_msg->xid;
    dhcp_nak->secs = 0;
    dhcp_nak->flags = 0;
    dhcp_nak->ciaddr = 0;
    dhcp_nak->yiaddr = 0;
    dhcp_nak->siaddr = 0;
    dhcp_nak->flags = req_msg->flags;
    dhcp_nak->giaddr = req_msg->giaddr;
    memcpy(dhcp_nak->chaddr, req_msg->chaddr, 16);
    dhcp_nak->magic = DHCP_MAGIC;
    
    options_ptr = dhcp_nak->options;
    *options_ptr++ = DHO_DHCP_MESSAGE_TYPE;
    *options_ptr++ = 1;
    *options_ptr++ = DHCP_NACK;
    *options_ptr++ = DHO_DHCP_SERVER_IDENTIFIER;
    *options_ptr++ = 4;
    uint32_t server_ip = _leases->_ip;
    memcpy(options_ptr, &server_ip, 4);
    options_ptr += 4;
    *options_ptr = DHO_END;
    
    return nak_q;
}

void 
SdnAgent::disconnect_responder(struct click_wifi *w)
{
    uint32_t headroom =  Packet::default_headroom;
    Packet *_packet;
    StringAccum _sa;
    String _payload;

    EtherAddress dst = EtherAddress(w->i_addr1);
    EtherAddress src = EtherAddress(w->i_addr2);

    if (dst != _mac) {
        click_chatter("%p{element}: disconnecting packet with weird addr\n", this);
        return;
    }

    if (_client_table.find(src) != _client_table.end()) {
        
        // generate the inform packet for master server
        _sa << "clientdisconnect|" << src.unparse_colon().c_str() << "|\n";
        _payload = _sa.take_string();
        _packet = Packet::make(headroom, _payload.data(), _payload.length(), 0);
        // send inform packet to master
        output(0).push(_packet);
        click_chatter("%p{element}: inform disconnection to master\n", this);

        // remove the corresponding client
        _client_table.erase(src);
    }

}

void
SdnAgent::push_udp_to_client(Packet *p_in, IPAddress ip_dst, 
                            EtherAddress eth_dst, int port)
{
    WritablePacket *p = p_in->push(sizeof(click_udp) + sizeof(click_ip));
    click_ip *ip = reinterpret_cast<click_ip *>(p->data());
    click_udp *udp = reinterpret_cast<click_udp *>(ip + 1);

    // set up IP header
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) >> 2;
    ip->ip_len = htons(p->length());
    static atomic_uint32_t id;
    ip->ip_id = htons(id.fetch_and_add(1));
    ip->ip_p = IP_PROTO_UDP;
    ip->ip_src = _ipaddr;
    ip->ip_dst = ip_dst;
    ip->ip_tos = 0;
    ip->ip_off = 0;
    ip->ip_ttl = 250;

    ip->ip_sum = 0;
    ip->ip_sum = click_in_cksum((unsigned char *)ip, sizeof(click_ip));
    p->set_dst_ip_anno(ip_dst);
    p->set_ip_header(ip, sizeof(click_ip));

    // set up UDP header
    udp->uh_sport = htons(UDP_AGENT_PORT);
    udp->uh_dport = htons(UDP_CLIENT_PORT);
    uint16_t len = p->length() - sizeof(click_ip);
    udp->uh_ulen = htons(len);
    udp->uh_sum = 0;
    unsigned csum = click_in_cksum((unsigned char *)udp, len);
    udp->uh_sum = click_in_cksum_pseudohdr(csum, ip, len);

    // set ethernet header
    WritablePacket *s = p->push_mac_header(14);
    click_ether *eth = (click_ether *)s->data();
    memcpy(eth->ether_shost, _mac.data(), 6);
    memcpy(eth->ether_dhost, eth_dst.data(), 6);
    eth->ether_type = htons(ETHERTYPE_IP);
    output(port).push(s);
}

Packet *
SdnAgent::make_ping_request(IPAddress ip_dst, EtherAddress eth_dst)
{
    // String data = "this is just some random stuff";
    String data = String();
    size_t headersize = sizeof(click_ether) + sizeof(click_ip) 
                                + sizeof(click_icmp_echo);
    
    WritablePacket *p = Packet::make(headersize + data.length());
    
    memset(p->data(), '\0', headersize);
    memcpy(p->data() + headersize, data.data(), data.length());

    click_ip *nip = reinterpret_cast<click_ip *>(p->data());
    nip->ip_v = 4;
    nip->ip_hl = sizeof(click_ip) >> 2;
    nip->ip_len = htons(p->length());
    uint16_t ip_id = (_count % 0xFFFF) + 1; // ensure ip_id != 0
    nip->ip_id = htons(ip_id);
    nip->ip_p = IP_PROTO_ICMP; /* ICMP */
    nip->ip_ttl = 200;
    nip->ip_src = _ap_ipaddr;
    nip->ip_dst = ip_dst;
    nip->ip_sum = click_in_cksum((unsigned char *)nip, sizeof(click_ip));

    click_icmp_echo *icp = (struct click_icmp_echo *) (nip + 1);
    icp->icmp_type = ICMP_ECHO;
    icp->icmp_code = 0;
    icp->icmp_identifier = ICMP_ID;
    icp->icmp_sequence = htons(ip_id);
    icp->icmp_cksum = click_in_cksum((unsigned char *)icp, sizeof(click_icmp_sequenced) + data.length());
    if (icp->icmp_sequence != _icmp_sequence) {
        // save sequence for future checking
        _icmp_sequence = icp->icmp_sequence;
    }

    p->set_dst_ip_anno(ip_dst);
    p->set_ip_header(nip, sizeof(click_ip));
    p->timestamp_anno().assign_now();

    // set ethernet header
    WritablePacket *e = p->push_mac_header(14);
    click_ether *eth = (click_ether *)e->data();
    memcpy(eth->ether_shost, _mac.data(), 6);
    memcpy(eth->ether_dhost, eth_dst.data(), 6);
    eth->ether_type = htons(ETHERTYPE_IP);
    
    return p;
}



CLICK_ENDDECLS
EXPORT_ELEMENT(SdnAgent)
ELEMENT_REQUIRES(DHCPOptionUtil)
