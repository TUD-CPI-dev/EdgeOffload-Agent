#ifndef AGENT_DHCPACKNAK_HH
#define AGENT_DHCPACKNAK_HH

#include <click/element.hh>
#include <click/etheraddress.hh>
#include "leasetable.hh"

/*
 * =c
 * AgentDHCPServerACKorNAK(LEASES)
 *
 * =s DHCP
 *
 * Handles incoming DHCP_REQUEST. Sends out DHCP_ACK or DHCP_NAK
 * accordingly, and informs the master server
 *
 * =d
 *
 *
 * =e
 *
 * =a
 * DHCPServerLeases, DHCPServerACKorNACK, DHCPServerOffer
 *
 *
 */

class AgentDHCPACKorNAK : public Element
{
    public:
        AgentDHCPACKorNAK();
        ~AgentDHCPACKorNAK();

        const char *class_name() const { return "AgentDHCPACKorNAK"; }
        const char *port_count() const { return "1/2"; }
        const char *processing() const { return PUSH; }

        int configure(Vector<String> &conf, ErrorHandler *errh);
        virtual void push(int port, Packet *p);
        Packet *make_ack_packet(Packet *p, Lease *lease);
        Packet *make_nak_packet(Packet *p, Lease *lease);

    private:
        DHCPLeaseTable *_leases;
};
#endif
