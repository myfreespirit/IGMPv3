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
	if (cp_va_kparse(conf, this, errh, "CLIENT_STATES", cpkM, cpElementCast, "IGMPClientStates", &_states, cpEnd) < 0) return -1;
	return 0;
}

void Reporter::push(int, Packet *p) {
	click_chatter("Report sent of size %d",p->length());
	output(0).push(p);
}

bool Reporter::checkExcludeMode(unsigned int interface, IPAddress groupAddress)
{
	HashTable<int, Vector<SocketState> >::const_iterator it =_states->_socketStates.begin();
	for(;it != _states->_socketStates.end(); it++ ){
		Vector<SocketState> sStates = it.value();

		for(unsigned int i=0;i<sStates.size();i++){
			if(sStates.at(i)._interface == interface && sStates.at(i)._groupAddress == groupAddress){
				if(sStates.at(i)._filter == MODE_IS_EXCLUDE){
					return true;
				}
			}
		}

	}
	return false;
}

// RFC 3376 page 5
void Reporter::saveSocketState(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter,
		std::set<String> sources)
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
		// update entry matching given interface and groupAddress or create a new one if not present
		bool isPresent = false;
		for(Vector<SocketState>::iterator it = vCopySocketStates.begin(); it != vCopySocketStates.end(); it++){
			if(it->_interface == interface && it->_groupAddress == groupAddress){
				it->_filter = filter;
				std::set<String> excludeSources;
				std::set<String> includeSources;

				if(filter == MODE_IS_INCLUDE){
					includeSources = sources;
				}
				else{
					excludeSources = sources;
				}


				this->getSourceLists(interface, groupAddress, port, excludeSources, includeSources);
				if(this->checkExcludeMode(interface, groupAddress)){
					it->_sources = this->_difference(excludeSources, includeSources);
				}
				else{
					it->_sources = includeSources;
				}
				isPresent = true;
				click_chatter("Updated socket state entry for interface %u and group %s", interface, groupAddress.unparse().c_str());

				break;
			}
		}


		if(!isPresent){
			SocketState newState;
			newState._interface = interface;
			newState._groupAddress = groupAddress;
			newState._filter = filter;
			newState._sources = sources;
			vCopySocketStates.push_back(newState);
			click_chatter("Added socket state entry for interface %u and group %s", interface, groupAddress.unparse().c_str());
		}


	}

	_states->_socketStates[port] = vCopySocketStates;
}

std::set<String> Reporter::_intersect(std::set<String> a, std::set<String> b)
{
	std::set<String> result;
	for(std::set<String>::iterator it=a.begin(); it != a.end(); it++){
		for(std::set<String>::iterator it2=b.begin(); it2 != b.end(); it2++){
			if((*it) == (*it2)){
				result.insert(it2,*it2);
			}
		}

	}

	click_chatter("%d,%d,%d", result.size(), a.size(), b.size());

		for(std::set<String>::iterator it=result.begin(); it != result.end(); it++){
			click_chatter("%s", it->c_str());
		}
	return result;
}

std::set<String> Reporter::_union(std::set<String> a, std::set<String> b)
{
	std::set<String> result;
	for(std::set<String>::iterator it=a.begin(); it != a.end(); it++){
		result.insert(result.end(),*it);
	}

	for(std::set<String>::iterator it2=b.begin(); it2 != b.end(); it2++){
		result.insert(result.end(),*it2);
	}

	return result;
}

std::set<String> Reporter::_difference(std::set<String> a, std::set<String> b)
{
	std::set<String> result;
	for(std::set<String>::iterator it=a.begin(); it != a.end(); it++){
		bool foundMatch = false;
		for(std::set<String>::iterator it2=b.begin(); it2 != b.end(); it2++){
			if((*it) == (*it2)){
				foundMatch = true;
				break;
			}
		}
		if(!foundMatch){
			result.insert(it, *it);
		}

	}
	return result;
}

void Reporter::getSourceLists(unsigned int interface, IPAddress groupAddress,
		unsigned int port, std::set<String>& excludeSources, std::set<String>& includeSources)
{
	Vector<SocketState> vCopySocketStates = _states->_socketStates.get(port);
	bool isModeExclude = false;
	for (Vector<SocketState>::const_iterator it = vCopySocketStates.begin();
			it != vCopySocketStates.end(); ++it) {
		if (it->_interface == interface && it->_groupAddress == groupAddress) {
			if (it->_filter == MODE_IS_EXCLUDE) {
				if (!isModeExclude && excludeSources.size() == 0) {
					// first entry for EXCLUDE filter mode
					excludeSources.insert(it->_sources.begin(),
							it->_sources.end());
					isModeExclude = true;
				} else {
					std::set < String > temp;
					// intersection of source lists for EXCLUDE filter mod
					excludeSources = this->_intersect(excludeSources,
							it->_sources);
					//excludeSources = temp;
				}
			} else {
				includeSources = this->_union(includeSources, it->_sources); // union of source lists for INCLUDE filter mode
			}
		}
	}
}

// RFC 3376 pages 5-7, 20 (consider "non-existent" state for joins / leaves)
void Reporter::saveInterfaceState(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, std::set<String> sources) {

	std::set<String> excludeSources;
	std::set<String> includeSources;

	getSourceLists(interface, groupAddress, port, excludeSources, includeSources);

	InterfaceState state;
	state._groupAddress = groupAddress;
	if (checkExcludeMode(interface, groupAddress)) {
		state._filter = MODE_IS_EXCLUDE;
		// intersection of source lists from EXCLUDE FILTER minus union of source lists from INCLUDE FILTER
		state._sources = this->_difference(excludeSources, includeSources);
	} else {
		state._filter = MODE_IS_INCLUDE;
		state._sources = includeSources;
	}

	if (_states->_interfaceStates.size() > interface) {

		for(int i=0; i<_states->_interfaceStates.at(interface).size();i++){
			if(_states->_interfaceStates.at(interface).at(i)._groupAddress == groupAddress){
				_states->_interfaceStates.at(interface).at(i) = state;
				return;
			}
		}

		_states->_interfaceStates.at(interface).push_back(state) ;
		//_states->_interfaceStates.at(interface).push_back(state);
	} else {
		//_states->_interfaceStates.at(interface).insert(_states->_interfaceStates.at(interface).begin() + interface, state);  // TODO verify it inserts the state at the right place
		_states->_interfaceStates.resize(interface + 1);
		_states->_interfaceStates.at(interface).push_back(state);

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
