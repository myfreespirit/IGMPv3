#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "generator.hh"
#include "messages.hh"
#include <clicknet/ether.h>
#include <clicknet/udp.h>
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

Packet* Generator::createQueryPacket(in_addr src, in_addr dst) {
	int headroom = sizeof(click_ether) + sizeof(click_udp);
	int packetSize = sizeof(click_ip) + sizeof(struct Query);
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
	iph->ip_src = src;
	iph->ip_dst = dst;
	iph->ip_sum = click_in_cksum((unsigned char*) iph, sizeof(click_ip));

	Query* query = (Query *)(iph + 1);
	query->type = 0x11;
	query->max_resp_code = 0;
	query->checksum = htons(0);
	query->group_address = IPAddress("0.0.0.0");  // TODO this is only for General Query variant
	query->resv = 0;
	query->S = 0;  // TODO timers
	query->QRV = 1;  // TODO choose a valid value
	query->QQIC = 0;  // TODO choose a valid value
    query->number_of_sources = htons(0);  // TODO this is only for General Query variant
    //query->source_addresses = Vector<in_addr>;

	q->set_dst_ip_anno(dst);

	return q;
}

Packet* Generator::createReportPacket(in_addr src, in_addr dst) {
	int headroom = sizeof(click_ether) + sizeof(click_udp);
	int packetSize = sizeof(click_ip) + sizeof(struct Report) + sizeof(struct GroupRecord);  // TODO size of packet with Vector size
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
	iph->ip_src = src;
	iph->ip_dst = dst;
	iph->ip_sum = click_in_cksum((unsigned char*) iph, sizeof(click_ip));

    Report* report = (Report *) (iph + 1);
    report->type = 0x22;
    report->checksum = htons(0);
    report->number_of_group_records = htons(1);  // TODO
    
    // Group Record
    GroupRecord* groupRecord = (GroupRecord* ) (report + 1);
    //GroupRecord groupRecord;
    groupRecord->type = 3;  // TODO other values
    groupRecord->aux_data_len = 0;
    groupRecord->number_of_sources = htons(1);  // TODO save source list
    groupRecord->multicast_address = IPAddress("192.168.1.1");  // TODO retrieve multicast server address from elsewhere
    // groupRecord.source_addresses = Vector<in_addr>;  // TODO
    
    //report->group_records.resize(1);
    //report->group_records.at(0) = groupRecord;
    
	q->set_dst_ip_anno(dst);

	return q;
}

int Generator::queryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh) {
	Generator* me = (Generator *) e;

	in_addr src;
	in_addr dst;

	if (cp_va_kparse(conf, me, errh,
		"SRC", cpkM, cpIPAddress, &src,
		"DST", cpkM, cpIPAddress, &dst,
		cpEnd) < 0) {
		return -1;
	}

	me->push(0, me->createQueryPacket(src, dst));
}

int Generator::reportHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh) {
	Generator* me = (Generator *) e;

	in_addr src;
	in_addr dst;

	if (cp_va_kparse(conf, me, errh,
		"SRC", cpkM, cpIPAddress, &src,
		"DST", cpkM, cpIPAddress, &dst,
		cpEnd) < 0) {
		return -1;
	}

	me->push(0, me->createReportPacket(src, dst));
}

void Generator::add_handlers() {
	add_write_handler("query", &queryHandler, (void *) 0);
	add_write_handler("report", &reportHandler, (void *) 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Generator)
