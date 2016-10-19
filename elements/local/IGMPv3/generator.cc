#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "generator.hh"
#include "messages.hh"
#include <clicknet/ether.h>
#include <clicknet/ip.h>

CLICK_DECLS
Generator::Generator()
{}

Generator::~ Generator()
{}

int Generator::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	return 0;
}

void Generator::push(int, Packet *p) {
	click_chatter("Got a packet of size %d",p->length());
	output(0).push(p);
}

Packet* Generator::createPacket(in_addr src, in_addr dst) {
	int headroom = sizeof(click_ether);
	WritablePacket* q = Packet::make(headroom, 0, sizeof(click_ip) + sizeof(struct Query), 0);

	if (!q) {
		return 0;
	}

	memset(q->data(), '\0', sizeof(click_ip) + sizeof(struct Query));

	click_ip* iph = (click_ip*) q->data();
	iph->ip_v = 4;
	iph->ip_hl = sizeof(click_ip) >> 2;
	iph->ip_len = htons(q->length());
	iph->ip_p = IP_PROTO_IGMP;
	iph->ip_ttl = 1;
	iph->ip_src = src;
	iph->ip_dst = dst;
	iph->ip_sum = click_in_cksum((unsigned char*) iph, sizeof(click_ip));

	Query* query = (Query *)(iph + 1);
	query->type = 0x11;

	q->set_dst_ip_anno(dst);

	return q;
}

int Generator::handle(const String &conf, Element* e, void* thunk, ErrorHandler* errh) {
	Generator* me = (Generator *) e;

	in_addr src;
	in_addr dst;

	if (cp_va_kparse(conf, me, errh,
		"SRC", cpkM, cpIPAddress, &src,
		"DST", cpkM, cpIPAddress, &dst,
		cpEnd) < 0) {
		return -1;
	}

	me->push(0, me->createPacket(src, dst));
}

void Generator::add_handlers() {
	add_write_handler("test", &handle, (void *) 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Generator)
