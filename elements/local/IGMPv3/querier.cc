#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "querier.hh"
#include "messages.hh"

#include <clicknet/ether.h>
#include <clicknet/ip.h>

CLICK_DECLS

Querier::Querier()
{
}

Querier::~Querier()
{
}

int Querier::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh, "ROUTER_STATES", cpkM, cpElementCast, "IGMPRouterStates", &_states, cpEnd) < 0) return -1;
	return 0;
}

void Querier::push(int interface, Packet *p)
{
	click_ip* iph = (click_ip*) p->data();
	Report* report = (Report*) (iph + 1); 
	GroupRecord* groupRecord = (GroupRecord*) (report + 1);
	unsigned int groupType = groupRecord->type;

	click_chatter("Router received a packet from %s on port/interface %d", IPAddress(iph->ip_src).unparse().c_str(), interface);
	
	if (groupType == CHANGE_TO_INCLUDE_MODE || groupType == CHANGE_TO_EXCLUDE_MODE) {
		click_chatter("Recognized FILTER-MODE-CHANGE report for group %s", IPAddress(groupRecord->multicast_address).unparse().c_str());
		int totalSources = ntohs(groupRecord->number_of_sources);
		Vector<IPAddress> vSources;
		Addresses* addresses = (Addresses*) (groupRecord + 1);
		for (int i = 0; i < totalSources; i++) {
			click_chatter("Extracted %s source IPAddress", IPAddress(addresses->array[i]).unparse().c_str());
			vSources.push_back(addresses->array[i]);
		}
		QUERY_MODE queryMode = _states->updateFilterChange(interface, groupRecord->multicast_address, groupType, vSources);

		if (queryMode == GROUP_QUERY) {
			sendQuery(interface, groupRecord->multicast_address);
		}
	} else {
		click_chatter("Recognized CURRENT-STATE report for %d groups", ntohs(report->number_of_group_records));

		int totalGroups = ntohs(report->number_of_group_records);
		for (int g = 0; g < totalGroups; g++) {
			int totalSources = ntohs(groupRecord->number_of_sources);
			Vector<IPAddress> vSources;
			Addresses* addresses = (Addresses*) (groupRecord + 1);
			for (int i = 0; i < totalSources; i++) {
				click_chatter("Extracted %s source IPAddress", IPAddress(addresses->array[i]).unparse().c_str());
				vSources.push_back(addresses->array[i]);
			}
			_states->updateCurrentState(interface, groupRecord->multicast_address, groupType, vSources);
			groupRecord = (GroupRecord*) (addresses + totalSources);
		}
	}
}

void Querier::sendQuery(unsigned int interface, IPAddress group = IPAddress("0.0.0.0"))
{
	int headroom = sizeof(click_ether);
	int headerSize = sizeof(click_ip);
	int messageSize = sizeof(struct Query);
	int packetSize = headerSize + messageSize;
	WritablePacket* q = Packet::make(headroom, 0, packetSize, 0);

	if (!q) {
        click_chatter("ERROR: Querier was unable to create a new WritablePacket.");
		return;
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

	// TODO get specific values from infobase element (QRV, QQIC, etc)
	Query* query = (Query *) (iph + 1);
	query->type = IGMP_TYPE_QUERY;
	query->max_resp_code = (group == IPAddress("0.0.0.0")) ? 100 : 10;
	query->checksum = htons(0);
	query->group_address = group;
	query->resvSQRV = (0 << 4) | (0 << 3) | (_states->_qrv);
//	query->resv = 0;
//	query->S = 0;
//	query->QRV = _states->_qrv;
	query->QQIC = 125;
    query->number_of_sources = htons(0);

	query->checksum = click_in_cksum((unsigned char*) query, messageSize);

	q->set_dst_ip_anno(_states->_destination);
	click_chatter("Router sent a query on interface %u for group %s", interface, group.unparse().c_str());
	output(interface).push(q);
}

int Querier::generalQueryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh) {
	Querier* me = (Querier *) e;

	if (cp_va_kparse(conf, me, errh, cpEnd) < 0) {
		return -1;
	}

	me->sendQuery(0);
	me->sendQuery(1);
	me->sendQuery(2);
}

int Querier::groupQueryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh) {
	Querier* me = (Querier *) e;

	unsigned int interface;
	IPAddress group;

	if (cp_va_kparse(conf, me, errh,
			"INTERFACE", cpkM, cpUnsigned, &interface,
			"GROUP", cpkM, cpIPAddress, &group,
			cpEnd) < 0) {
		return -1;
	}

	me->sendQuery(interface, group);
}

void Querier::add_handlers() {
	add_write_handler("general_query", &generalQueryHandler, (void *) 0);
	add_write_handler("group_query", &groupQueryHandler, (void *) 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Querier)
