#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <algorithm>

#include "reporter.hh"
#include "messages.hh"
#include "states/interfacestate.hh"

#include <clicknet/ether.h>
#include <clicknet/ip.h>

CLICK_DECLS
Reporter::Reporter(){}
Reporter::~ Reporter(){}

int Reporter::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "CLIENT_STATES", cpkM, cpElementCast, "IGMPClientStates", &_states, cpEnd) < 0) return -1;
	return 0;
}

void Reporter::push(int, Packet *p) {
	click_chatter("Report sent of size %d",p->length());
	output(0).push(p);
}

// RFC 3376 page 5
void Reporter::saveSocketState(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, std::set<String> sources)
{
	// update socket state
	Vector<SocketState> vCopySocketStates = _states->_socketStates.get(port);
	
	if (filter == MODE_IS_INCLUDE && sources.size() == 0) {
		// delete entry with matching interface and groupAddress if present
		for (Vector<SocketState>::iterator it = vCopySocketStates.begin(); it != vCopySocketStates.end(); ++it) {
			if (it->_interface == interface && it->_groupAddress == groupAddress) {
				vCopySocketStates.erase(it);
				click_chatter("Removed socket state entry for interface %u and group %s", interface, groupAddress.unparse().c_str());
				break;
			}
		}
	} else {
		bool isPresent = false;
		// update entry matching given interface and groupAddress or create a new one if not present
		for (Vector<SocketState>::iterator it = vCopySocketStates.begin(); it != vCopySocketStates.end(); ++it) {
			if (it->_interface == interface && it->_groupAddress == groupAddress) {
				it->_filter = filter;
				it->_sources = sources;
				click_chatter("Updated socket state entry for interface %u and group %s", interface, groupAddress.unparse().c_str());
				isPresent = true;
				break;
			}
		}

		if (!isPresent) {
			// create new entry with given arguments
			SocketState newState;
			newState._interface = interface;
			newState._groupAddress = groupAddress;
			newState._filter = filter;
			newState._sources = sources;

			vCopySocketStates.push_back(newState);
			click_chatter("Added socket state entry for interface %u and group %s", interface, groupAddress.unparse().c_str());
			// isPresent = true;
		}
	}

	_states->_socketStates[port] = vCopySocketStates;
}

// RFC 3376 pages 5-7, 20 (consider "non-existent" state for joins / leaves)
void Reporter::saveInterfaceState(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, std::set<String> sources) {
	Vector<SocketState> vCopySocketStates = _states->_socketStates.get(port);

	bool isModeExclude = false;
	std::set<String> excludeSources;
	std::set<String> includeSources;

	for (Vector<SocketState>::const_iterator it = vCopySocketStates.begin(); it != vCopySocketStates.end(); ++it) {
		if (it->_interface == interface && it->_groupAddress == groupAddress) {
			if (it->_filter == MODE_IS_EXCLUDE) {
				if (!isModeExclude) {
					// first entry for EXCLUDE filter mode
					excludeSources.insert(it->_sources.begin(), it->_sources.end());
					isModeExclude = true;
				} else {
					std::set<String> temp;
					// intersection of source lists for EXCLUDE filter mode
					std::set_intersection(excludeSources.begin(), excludeSources.end(),
											it->_sources.begin(), it->_sources.end(),
											std::inserter(temp, temp.begin()));
					excludeSources = temp;
				}
			} else {
				includeSources.insert(it->_sources.begin(), it->_sources.end());  // union of source lists for INCLUDE filter mode
			}
		}
	}

	InterfaceState state;
	state._groupAddress = groupAddress;
	if (isModeExclude) {
		state._filter = MODE_IS_EXCLUDE;  // TODO
		// intersection of source lists from EXCLUDE FILTER minus union of source lists from INCLUDE FILTER
		std::set_difference(excludeSources.begin(), excludeSources.end(),
							includeSources.begin(), includeSources.end(),
							std::inserter(state._sources, state._sources.begin()));
	} else {
		state._filter = MODE_IS_INCLUDE;  // TODO
		state._sources = includeSources;
	}

	if (_states->_interfaceStates.size() > interface) {
		_states->_interfaceStates.at(interface) = state;
	} else {
		_states->_interfaceStates.insert(_states->_interfaceStates.begin() + interface, state);  // TODO verify it inserts the state at the right place
   	}
}

Packet* Reporter::createJoinReport(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, std::set<String> sources)
{
	int headroom = sizeof(click_ether);
	int headerSize = sizeof(click_ip);
	int messageSize = sizeof(struct Report) + sizeof(struct GroupRecord);
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
    report->type = 0x22;
    report->checksum = htons(0);
    report->number_of_group_records = htons(1);  // TODO check for fragmentation needs

	saveSocketState(port, interface, groupAddress, filter, sources);
	saveInterfaceState(port, interface, groupAddress, filter, sources);

    GroupRecord* groupRecord = (GroupRecord* ) (report + 1);
    groupRecord->type = 2;  // TODO
    groupRecord->aux_data_len = 0;
    groupRecord->number_of_sources = htons(0);  // TODO
    groupRecord->multicast_address = groupAddress;
	// TODO source list
	// TODO packetsize

	report->checksum = click_in_cksum((unsigned char*) report, messageSize);

    q->set_dst_ip_anno(_states->_destination);

	return q;
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
	std::set<String> sources;

	// overwrite given arguments
	if (cp_va_kparse(conf, me, errh,
			"PORT", cpkN, cpUnsigned, &port,
			"INTERFACE", cpkN, cpUnsigned, &interface,
			"GROUP", cpkN, cpIPAddress, &groupAddress,
			"FILTER", cpkN, cpString, &sFilter,
			"SRC", cpkN, cpArguments, &vSources,
			cpEnd) < 0)
		return -1;

	if (interface != 0) {
		errh->error("[ERROR IGMPReporter]: invalid INTERFACE value (%u) provided for client with address %s, expected 0", interface, me->_states->_source.unparse().c_str());
		return -1;
	}

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

	me->push(0, me->createJoinReport(port, interface, groupAddress, filter, sources));
	return 0;
}

void Reporter::add_handlers()
{
	add_write_handler("join_group", &joinGroup, (void *) 0);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Reporter)
