#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "querier.hh"
#include "messages.hh"

#include <clicknet/ether.h>
#include <clicknet/ip.h>

CLICK_DECLS
Querier::Querier()
{}

Querier::~ Querier()
{}

int Querier::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "ROUTER_STATES", cpkM, cpElementCast, "IGMPRouterStates", &_states, cpEnd) < 0) return -1;
	return 0;
}

void Querier::push(int port, Packet *p) {
	click_chatter("Got a packet of size %d",p->length());
	output(port).push(p);
}

Packet* Querier::createGeneralQueryPacket() {
	int headroom = sizeof(click_ether);
	int headerSize = sizeof(click_ip);
	int messageSize = sizeof(struct Query);
	int packetSize = headerSize + messageSize;
	WritablePacket* q = Packet::make(headroom, 0, packetSize, 0);

	if (!q) {
		return 0;
	}

	memset(q->data(), '\0', packetSize);

	click_ip* iph = (click_ip*) q->data();
	iph->ip_v = 4;
	iph->ip_hl = sizeof(click_ip) >> 2;
	iph->ip_len = htons(q->length());
	iph->ip_p = IP_PROTO_IGMP;
	iph->ip_ttl = 1;
	iph->ip_src = _states->_source;
	iph->ip_dst = _states->_destination;
	iph->ip_sum = click_in_cksum((unsigned char*) iph, sizeof(click_ip));

	Query* query = (Query *)(iph + 1);
	query->type = 0x11;
	query->max_resp_code = 10;
	query->checksum = htons(0);
	query->group_address = IPAddress("0.0.0.0");
	query->resvSQRV = (0 << 4) | (0 << 3) | (2);
//	query->resv = 0;
//	query->S = 0;
//	query->QRV = 2;
	query->QQIC = 125;
    query->number_of_sources = htons(0);

	query->checksum = click_in_cksum((unsigned char*) query, messageSize);

	q->set_dst_ip_anno(_states->_destination);

	return q;
}

int Querier::generalQueryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh) {
	Querier* me = (Querier *) e;

	if (cp_va_kparse(conf, me, errh, cpEnd) < 0) {
		return -1;
	}

	me->push(0, me->createGeneralQueryPacket());
	me->push(1, me->createGeneralQueryPacket());
	me->push(2, me->createGeneralQueryPacket());
}


void Querier::add_handlers() {
	add_write_handler("general_query", &generalQueryHandler, (void *) 0);
	//add_write_handler("group_query", &queryHandler, (void *) 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Querier)
