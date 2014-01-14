/*
* sdnagent.{cc,hh} -- An agent for the wireless sdn system
* Yanhe Liu <yanhe.liu@cs.helsinki.fi>
* Aaron Yi DING <yding@cs.helsinki.fi>
* Sasu Tarkoma <sasu.tarkoma@cs.helsinki.fi>
*
* Copyright (c) 2013 University of Helsinki
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


#include <click/config.h>
#include "sdnagent.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <click/args.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>

#include "dhcp/dhcp_common.hh"
#include "dhcp/dhcpoptionutil.hh"

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
    _timer.initialize(this);
    _timer.schedule_now();
    return 0;
}

void
SdnAgent::run_timer(Timer*)
{
    uint32_t headroom =  Packet::default_headroom;
    Packet *_packet;
    StringAccum _sa;
    String _payload;
    String r1, r2;

    // send messages to master controller
    r1 = _byte_up_rate.unparse_rate();
    r2 = _byte_down_rate.unparse_rate();
    if (r1 != "" && r2 != "") {
        _sa << "agentrate " << r1 << " " << r2 << " \n";
        _payload = _sa.take_string();
        _packet = Packet::make(headroom, _payload.data(), _payload.length(), 0);
        output(0).push(_packet);
    }

    for (HashTable<EtherAddress, Client>::iterator it = _client_table.begin(); 
        it.live(); it++) {
        
        _sa.clear();
        r1 = it.value()._byte_up_rate.unparse_rate();
        r2 = it.value()._byte_down_rate.unparse_rate();
        if (r1 != "" && r2 != "") {
            _sa << "clientrate " << it.value()._mac.unparse_colon().c_str() <<
                " " << it.value()._ipaddr.unparse().c_str() << " " << r1 << 
                " " << r2 << " \n";
            _payload = _sa.take_string();
            _packet = Packet::make(headroom, _payload.data(), 
                                    _payload.length(), 0);
            output(0).push(_packet);
        }
    }

    _packet->kill();
    _timer.reschedule_after_sec(_interval);
}

int
SdnAgent::configure(Vector<String> &conf, ErrorHandler *errh)
{ 
    _interval = 10;
    if (Args(conf, this, errh)
        .read_mp("MAC", _mac)
        .read_m("IP", _ipaddr)
        .read_m("INTERVAL", _interval)
        .read_mp("LEASES", ElementCastArg("DHCPLeaseTable"), _leases)
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

        _client_table.set(eth, new_client);
    }

    return;
}

/** 
* This element has 3 input ports and 3 output ports.
*
* In-port-0: ip encapsulated packets from master controller
* In-port-1: dhcp packets (not added by far)
* In-port-2: any other ethernet encapsulated frame
*
* Out-port-0: management packets to master controller via a socket
* Out-port-1: dhcp manages (no added by far)
* Out-port-2: other packets, let them through
*/

void
SdnAgent::push(int port, Packet *p)
{
    StringAccum _sa;

    if (port == 0) {
        _sa << "Received Messages from Controller!";
        click_chatter("%s", _sa.c_str());
    } else if (port == 1) {
        send_dhcp_ack_or_nak(1, p);
    } else if (port == 2) { // other packets
        // _byte_rate.update(p->length()); // overall rate

        click_ether *eh = (click_ether *) p->data();
        EtherAddress eth_src = EtherAddress((unsigned char *)eh->ether_shost);
        EtherAddress eth_dst = EtherAddress((unsigned char *)eh->ether_dhost);

        if (_client_table.find(eth_src) != _client_table.end()) {
            Client *c = _client_table.get_pointer(eth_src);
            c->_byte_up_rate.update(p->length());
            _byte_up_rate.update(p->length());
        } else if (_client_table.find(eth_dst) != _client_table.end()) {
            Client *c = _client_table.get_pointer(eth_dst);
            c->_byte_down_rate.update(p->length());
            _byte_down_rate.update(p->length());
        }

        output(2).push(p);
    }

    p->kill();

    return;
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
        _data << "client " << eth_src.unparse_colon().c_str() << " " << 
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



CLICK_ENDDECLS
EXPORT_ELEMENT(SdnAgent)
ELEMENT_REQUIRES(DHCPOptionUtil)
