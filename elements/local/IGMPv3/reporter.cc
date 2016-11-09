#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>

#include "reporter.hh"
#include "messages.hh"
#include "states/interfacestate.hh"

#include <clicknet/ether.h>
#include <clicknet/ip.h>

CLICK_DECLS
Reporter::Reporter(){}
Reporter::~ Reporter(){}

int Reporter::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_source, "DST", cpkM, cpIPAddress, &_destination, cpEnd) < 0) return -1;
	return 0;
}

void Reporter::push(int, Packet *p) {
	click_chatter("Report sent of size %d",p->length());
	output(0).push(p);
}

Packet* Reporter::createJoinReport(IPAddress groupAddress)
{
	int headroom = sizeof(click_ether);
	int packetSize = sizeof(click_ip) + sizeof(struct Report) + sizeof(struct GroupRecord);
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
	iph->ip_src = _source;
	iph->ip_dst = _destination;
	iph->ip_sum = click_in_cksum((unsigned char*) iph, sizeof(click_ip));

    Report* report = (Report *) (iph + 1);
    report->type = 0x22;
    report->checksum = htons(0);
    report->number_of_group_records = htons(1);

    GroupRecord* groupRecord = (GroupRecord* ) (report + 1);
    groupRecord->type = 2;
    groupRecord->aux_data_len = 0;
    groupRecord->number_of_sources = htons(0);
    groupRecord->multicast_address = groupAddress;

	report->checksum = click_in_cksum((unsigned char*) report, sizeof(Report) + sizeof(GroupRecord));
    q->set_dst_ip_anno(_destination);

	return q;
}

int Reporter::joinGroup(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
	Reporter* me = (Reporter *) e;

	unsigned int port = 1234;
	unsigned int interface = 0;
	FilterMode filter = EXCLUDE;
	String sFilter;
	Vector<String> vSources;
	std::set<String> sources;

	IPAddress groupAddress = IPAddress("225.1.1.1");

	if (cp_va_kparse(conf, me, errh,
			"PORT", cpkN, cpUnsigned, &port,
			"INTERFACE", cpkN, cpUnsigned, &interface,
			"GROUP", cpkN, cpIPAddress, &groupAddress,
			"FILTER", cpkN, cpString, &sFilter,
			"SRC", cpkN, cpArguments, &vSources,
			cpEnd) < 0)
		return -1;

	if(sFilter == "INCLUDE")
		filter = INCLUDE;

	for(int i=0; i<vSources.size(); i++){
		sources.insert(vSources.at(i));
		click_chatter("%s",vSources.at(i).c_str());
	}

	me->push(0, me->createJoinReport(groupAddress));
	return 0;
}

void Reporter::add_handlers()
{
	add_write_handler("join_group", &joinGroup, (void *) 0);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Reporter)
