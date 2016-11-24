#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>

#include "reporter.hh"
#include "messages.hh"

#include <clicknet/ether.h>
#include <clicknet/ip.h>

CLICK_DECLS

Reporter::Reporter()
{
}

Reporter::~ Reporter()
{
}

int Reporter::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh, "CLIENT_STATES", cpkM, cpElementCast, "IGMPClientStates", &_states, cpEnd) < 0) return -1;
	return 0;
}

void Reporter::replyToGeneralQuery()
{
	// skip non existent interface states
    if (_states->_interfaceStates.size() == 0) {
        return;
    }
    
	// assume general query arrived at interface 0
	int interface = 0;
    int numberOfGroups = _states->_interfaceStates.at(interface).size();
    click_chatter("client is member of %d groups on interface %d", numberOfGroups, interface);
    if (numberOfGroups == 0)
        return;
        
	int totalSources = 0;
    for (int i = 0; i < numberOfGroups; i++) {
	    totalSources += this->_states->_interfaceStates.at(interface).at(i)._sources.size();
	}

    int headroom = sizeof(click_ether);
	int headerSize = sizeof(click_ip);
	int messageSize = sizeof(struct Report) + sizeof(struct GroupRecord) * numberOfGroups + sizeof(struct Addresses) * totalSources;
	int packetSize = headerSize + messageSize;

	WritablePacket* q = Packet::make(headroom, 0, packetSize, 0);

	if (!q) {
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
	
    Report* report = (Report *) (iph + 1);
    report->type = IGMP_TYPE_REPORT;
    report->checksum = htons(0);
    report->number_of_group_records = htons(numberOfGroups);  // TODO check for fragmentation needs
    
	set<String> srcs;
	GroupRecord* groupRecord = (GroupRecord*) (report + 1);
    for (int i = 0; i < numberOfGroups; i++) {
        groupRecord->type = this->_states->_interfaceStates.at(interface).at(i)._filter;
        groupRecord->aux_data_len = 0;
        groupRecord->multicast_address = this->_states->_interfaceStates.at(interface).at(i)._groupAddress;

		// fill source list of matching (interface, group)
		srcs = this->_states->_interfaceStates.at(interface).at(i)._sources;
        groupRecord->number_of_sources = htons(srcs.size());
	    set<String>::iterator it = srcs.begin();
		Addresses* addresses = (Addresses*) (groupRecord + 1);
	    for (int i = 0; i < srcs.size(); i++) {
			addresses->array[i] = IPAddress(*it);
		    std::advance(it, 1);
	    }
		groupRecord = (GroupRecord*) (addresses + srcs.size());
    }

    report->checksum = click_in_cksum((unsigned char*) report, messageSize);
    
	q->set_dst_ip_anno(_states->_destination);
    
	output(0).push(q);
}

void Reporter::push(int, Packet *p)
{
	click_chatter("Received a packet of size %d",p->length());

	click_ip* iph = (click_ip*) p->data();
	Query* query = (Query*) (iph + 1); 

	if (query->type == IGMP_TYPE_QUERY) {
		if (query->group_address == IPAddress("0.0.0.0")) {
			click_chatter("Received general query");
			this->replyToGeneralQuery();
		}
		else{
			click_chatter("Received query for group %s", IPAddress(query->group_address).unparse().c_str());	
		}
	}
}

Packet* Reporter::createJoinReport(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, set<String> sources)
{
	_states->saveSocketState(port, interface, groupAddress, filter, sources);
	_states->saveInterfaceState(port, interface, groupAddress, filter, sources);

	int totalSources = 0;
	Vector<InterfaceState>::const_iterator cit = _states->_interfaceStates.at(interface).begin();
	for (; cit != _states->_interfaceStates.at(interface).end(); cit++) {
		if (cit->_groupAddress == groupAddress) {
			totalSources = cit->_sources.size();
			break;
		}
	}

	int headroom = sizeof(click_ether);
	int headerSize = sizeof(click_ip);
	int messageSize = sizeof(struct Report) + sizeof(struct GroupRecord) + sizeof(IPAddress) * totalSources;
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

    Report* report = (Report *) (iph + 1);
    report->type = IGMP_TYPE_REPORT;
    report->checksum = htons(0);
    report->number_of_group_records = htons(1);  // TODO check for fragmentation needs

    GroupRecord* groupRecord = (GroupRecord*) (report + 1);
    groupRecord->aux_data_len = 0;
    groupRecord->multicast_address = groupAddress;

	// find source list of matching interface, group
	set<String> srcs;
	Vector<InterfaceState> iStates = _states->_interfaceStates.at(interface);
	bool isStateRemoved = true;
	for (Vector<InterfaceState>::const_iterator it = iStates.begin(); it != iStates.end(); it++) {
		if (it->_groupAddress == groupAddress) {
			srcs = it->_sources;
			groupRecord->type = it->_filter + 2;
			isStateRemoved = false;
			break;
		}
	}
	if (isStateRemoved) {
		groupRecord->type = CHANGE_TO_INCLUDE_MODE; 
	}
    groupRecord->number_of_sources = htons(srcs.size());

	Addresses* addresses = (Addresses*) (groupRecord + 1);
	set<String>::iterator it = srcs.begin();
	for (int i = 0; i < srcs.size(); i++) {
		addresses->array[i] = IPAddress(*it);
		std::advance(it, 1);
	}

	report->checksum = click_in_cksum((unsigned char*) report, messageSize);

    q->set_dst_ip_anno(_states->_destination);

	return q;
}

int Reporter::leaveGroup(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
	Reporter* me = (Reporter *) e;

	// default values for arguments
	unsigned int port = 1234;
	unsigned int interface = 0;
	IPAddress groupAddress = IPAddress("225.1.1.1");
	FilterMode filter = MODE_IS_INCLUDE;
	set<String> sources;

	// overwrite given arguments
	if (cp_va_kparse(conf, me, errh,
			"PORT", cpkN, cpUnsigned, &port,
			"INTERFACE", cpkN, cpUnsigned, &interface,
			"GROUP", cpkN, cpIPAddress, &groupAddress,
			cpEnd) < 0)
		return -1;

	/* // TEST DISABLED TO TEST WHETHER CLIENT IGNORES MULTICAST PACKETS ON OTHER INTERFACES
	if (interface != 0) {
		errh->error("[ERROR IGMPReporter]: invalid INTERFACE value (%u) provided for client with address %s, expected 0", interface, me->_states->_source.unparse().c_str());
		return -1;
	}
	*/

	// TODO verify group address is a valid mcast address

	me->output(interface).push(me->createJoinReport(port, interface, groupAddress, filter, sources));
	return 0;
}

int Reporter::joinGroup(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
	Reporter* me = (Reporter *) e;

	// default values for arguments
	unsigned int port = 1234;
	unsigned int interface = 0;
	IPAddress groupAddress = IPAddress("225.1.1.1");
	String sFilter;
	FilterMode filter = MODE_IS_EXCLUDE;
	Vector<String> vSources;
	set<String> sources;

	// overwrite given arguments
	if (cp_va_kparse(conf, me, errh,
			"PORT", cpkN, cpUnsigned, &port,
			"INTERFACE", cpkN, cpUnsigned, &interface,
			"GROUP", cpkN, cpIPAddress, &groupAddress,
			"FILTER", cpkN, cpString, &sFilter,
			"SRC", cpkN, cpArguments, &vSources,
			cpEnd) < 0)
		return -1;

	/* // TEST DISABLED TO TEST WHETHER CLIENT IGNORES MULTICAST PACKETS ON OTHER INTERFACES
	if (interface != 0) {
		errh->error("[ERROR IGMPReporter]: invalid INTERFACE value (%u) provided for client with address %s, expected 0", interface, me->_states->_source.unparse().c_str());
		return -1;
	}
	*/

	// TODO verify group address is a valid mcast address

	if (sFilter == "INCLUDE") {
		filter = MODE_IS_INCLUDE;
	} else if(sFilter != "EXCLUDE" && sFilter != "") {
		errh->error("[ERROR IGMPReporter]: invalid FILTER mode (%s) provided, expected either EXCLUDE or INCLUDE", sFilter.c_str());
		return -1;
	}

	for (int i = 0; i < vSources.size(); i++) {
		sources.insert(vSources.at(i));
	}

	me->output(interface).push(me->createJoinReport(port, interface, groupAddress, filter, sources));
	return 0;
}

void Reporter::add_handlers()
{
	add_write_handler("join_group", &joinGroup, (void *) 0);
	add_write_handler("leave_group", &leaveGroup, (void *) 0);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Reporter)
