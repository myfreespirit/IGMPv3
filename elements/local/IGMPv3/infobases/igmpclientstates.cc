#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>

#include "igmpclientstates.hh"
#include "../utils/setoperations.hh"

using namespace setoperations;

CLICK_DECLS

IGMPClientStates::IGMPClientStates() : _rrv(2), _uri(1)
{
    // Client's are members of all-hosts multicast group on which they receive Queries from multicast routers
    
	_interfaceStates.resize(1);
	InterfaceState iState = InterfaceState(IPAddress("224.0.0.1"), MODE_IS_EXCLUDE, std::set<String>());
	_interfaceStates.at(0).push_back(iState);

	Vector<SocketState> vSockets = _socketStates.get(1234);
	SocketState sState = SocketState(0, IPAddress("224.0.0.1"), MODE_IS_EXCLUDE, std::set<String>());
	vSockets.push_back(sState);
	_socketStates[1234] = vSockets;
}

IGMPClientStates::~IGMPClientStates()
{
}

int IGMPClientStates::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh, 
			"SRC", cpkM, cpIPAddress, &_source, 
			"DST", cpkM, cpIPAddress, &_destination,
			cpEnd) < 0)
		return -1;

	return 0;
}

void IGMPClientStates::push(int, Packet *p)
{
	output(0).push(p);
}

bool IGMPClientStates::checkExcludeMode(unsigned int interface, IPAddress groupAddress)
{
	HashTable<int, Vector<SocketState> >::const_iterator it = _socketStates.begin();
	for (; it != _socketStates.end(); it++) {
		Vector<SocketState> sStates = it.value();

		for (unsigned int i = 0; i < sStates.size(); i++) {
			if (sStates.at(i)._interface == interface && sStates.at(i)._groupAddress == groupAddress) {
				if (sStates.at(i)._filter == MODE_IS_EXCLUDE) {
					return true;
				}
			}
		}
	}
	return false;
}

// gather exclude and include source lists by considering all entries in the socket states for given (interface, groupAddress) record
void IGMPClientStates::getSourceLists(unsigned int interface, IPAddress groupAddress, set<String>& excludeSources, set<String>& includeSources)
{
	bool isModeExclude = false;
	for (HashTable<int, Vector<SocketState> >::const_iterator it = _socketStates.begin(); it != _socketStates.end(); ++it) {
		for (int i = 0; i < it.value().size(); i++) {
			SocketState state = it.value().at(i);
			if (state._interface == interface && state._groupAddress == groupAddress) {
				if (state._filter == MODE_IS_EXCLUDE) {
					if (!isModeExclude && excludeSources.size() == 0) {
						// first entry for EXCLUDE filter mode (to prevent intersection on empty set)
						excludeSources.insert(state._sources.begin(), state._sources.end());
						isModeExclude = true;
					} else {
						// intersection of source lists for EXCLUDE filter mode
						excludeSources = set_intersect(excludeSources, state._sources);
					}
				} else {
					// union of source lists for INCLUDE filter mode
					includeSources = set_union(includeSources, state._sources);
				}
			}
		}
	}
}

// RFC 3376 page 5
REPORT_MODE IGMPClientStates::saveSocketState(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, set<String> sources)
{
	bool hasExcludeFilterBefore = checkExcludeMode(interface, groupAddress);
 
	Vector<SocketState> vCopySocketStates = _socketStates.get(port);

	if (filter == MODE_IS_INCLUDE && sources.size() == 0) {
		// delete entry with matching interface and groupAddress if present
		for (Vector<SocketState>::iterator it = vCopySocketStates.begin(); it != vCopySocketStates.end(); ++it) {
			if (it->_interface == interface && it->_groupAddress == groupAddress) {
				vCopySocketStates.erase(it);
				// click_chatter("Removed socket state entry on port %u, interface %u and group %s", port, interface, groupAddress.unparse().c_str());
				break;
			}
		}
	} else {
		// update entry matching given interface and groupAddress or create a new one if not present
		bool isPresent = false;
		for (Vector<SocketState>::iterator it = vCopySocketStates.begin(); it != vCopySocketStates.end(); it++) {
			if (it->_interface == interface && it->_groupAddress == groupAddress) {
				it->_filter = filter;
				it->_sources = sources;
				isPresent = true;
				// click_chatter("Updated socket state entry on port %u, interface %u and group %s", port, interface, groupAddress.unparse().c_str());
				break;
			}
		}

		if (!isPresent) {
			SocketState newState;
			newState._interface = interface;
			newState._groupAddress = groupAddress;
			newState._filter = filter;
			newState._sources = sources;
			vCopySocketStates.push_back(newState);
			// click_chatter("Added socket state entry on port %u, interface %u and group %s", port, interface, groupAddress.unparse().c_str());
		}
	}

	// update socket state
	_socketStates[port] = vCopySocketStates;

	bool hasExcludeFilterAfter = checkExcludeMode(interface, groupAddress);
	if (hasExcludeFilterBefore != hasExcludeFilterAfter) {
		return FILTER_MODE_CHANGE_REPORT;
	} else {
		return NO_REPORT;
	}
}


// RFC 3376 pages 5-7, 20 (consider "non-existent" state for joins / leaves)
// Instead of re-evaluating the states for all interfaces each time, we will simply update the affected entries.
void IGMPClientStates::saveInterfaceState(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, set<String> sources)
{
	set<String> excludeSources;
	set<String> includeSources;
	// gather new source list for given (interface, groupAddress) pair
	getSourceLists(interface, groupAddress, excludeSources, includeSources);

	InterfaceState state;
	// prepare updated state
	state._groupAddress = groupAddress;
	if (checkExcludeMode(interface, groupAddress)) {
		state._filter = MODE_IS_EXCLUDE;
		// intersection of source lists from EXCLUDE FILTER minus union of source lists from INCLUDE FILTER
		state._sources = set_difference(excludeSources, includeSources);
	} else {
		state._filter = MODE_IS_INCLUDE;
		// union of source lists from INCLUDE FILTER
		state._sources = includeSources;
	}

	// remove old entry on leave
	if (filter == MODE_IS_INCLUDE && sources.size() == 0) {
		if (interface >= _interfaceStates.size()) {
            // leaving a group on an interface before joining it is useless
			return;
        }

		Vector<InterfaceState> vInterfaces = _interfaceStates.at(interface);
		Vector<InterfaceState>::iterator it;
		for (it = vInterfaces.begin(); it != vInterfaces.end(); it++) {
			if (it->_groupAddress == groupAddress) {
				vInterfaces.erase(it);
				_interfaceStates.at(interface) = vInterfaces;
				break;
			}
		}
		// TODO: this exception is probably deadcode, we might need to rollback to previous interface state (backtracked above)
		if (state._filter != MODE_IS_INCLUDE || includeSources.size() > 0) {
            // click_chatter("TODO: IGMPClientStates::saveInterfaceState which use case is this backtracking?");
			_interfaceStates.at(interface).push_back(state);
		}
		return;
	}
	
	// check whether we have sufficient amount of containers for all interfaces
	if (_interfaceStates.size() > interface) {
		// find matching entry and update it
		for (int i = 0; i < _interfaceStates.at(interface).size(); i++) {
			if (_interfaceStates.at(interface).at(i)._groupAddress == groupAddress) {
				_interfaceStates.at(interface).at(i) = state;
				return;
			}
		}
		// in case no such entry was present, add a new one
		_interfaceStates.at(interface).push_back(state);
	} else {
		// resize container to support more interfaces and add new state
		_interfaceStates.resize(interface + 1);
		_interfaceStates.at(interface).push_back(state);
	}
}

bool IGMPClientStates::isMemberOf(unsigned int interface, IPAddress group) const
{
    if (interface >= _interfaceStates.size())
		return false;

	Vector<InterfaceState> states = _interfaceStates.at(interface);
	Vector<InterfaceState>::const_iterator it;
	for (it = states.begin(); it != states.end(); it++) {
		if (it->_groupAddress == group) {
			return true;
		}
	}

    return false;
}

void IGMPClientStates::getGroupRecordData(int interface, IPAddress group, FilterMode& filter, set<String>& sources)
{
	Vector<InterfaceState> states = _interfaceStates.at(interface);
	Vector<InterfaceState>::const_iterator it;
	for (it = states.begin(); it != states.end(); it++) {
		if (it->_groupAddress == group) {
            filter = it->_filter;
            sources = it->_sources;
			break;
		}
	}
}

bool IGMPClientStates::isMulticastAllowed(unsigned int interface, IPAddress group, IPAddress source) const
{
	if (interface >= _interfaceStates.size())
		return false;

	Vector<InterfaceState> states = _interfaceStates.at(interface);
	Vector<InterfaceState>::const_iterator it;
	std::set<String> sources;
	for (it = states.begin(); it != states.end(); it++) {
		if (it->_groupAddress == group) {
			sources = it->_sources;
			break;
		}
	}

	FilterMode filter = it->_filter;
	for (std::set<String>::const_iterator it2 = sources.begin(); it2 != sources.end(); it2++) {
		if (filter == MODE_IS_EXCLUDE) {
			if (IPAddress(*it2) == source) {
				return false;
			}
		} else if (filter == MODE_IS_INCLUDE) {
			if (IPAddress(*it2) == source) {
				return true;
			}
		}
	}

	return (filter == MODE_IS_EXCLUDE) ? true : false;
}

String IGMPClientStates::socketStates(Element* e, void* thunk)
{
	IGMPClientStates* me = (IGMPClientStates*) e;

	String output;

	output += "\n";
	output += "\t SOCKET \t | I | \t GROUP \t | FILTER  | SOURCES \n";

	for (HashTable<int, Vector<SocketState> >::const_iterator it = me->_socketStates.begin(); it != me->_socketStates.end(); ++it) {
		for (int i = 0; i < it.value().size(); i++) {
			SocketState state = it.value().at(i);
			output += "\t" + me->_source.unparse() + ":" + String(it.key()) + " | ";
			output += String(state._interface) + " | ";
			output += state._groupAddress.unparse() + " | ";
			output += (state._filter == MODE_IS_EXCLUDE) ? "EXCLUDE | " : "INCLUDE | ";
			output += (!state._sources.empty()) ? *(state._sources.begin()) : " NONE";
			output += "\n";

			if (state._sources.size() > 1) {
				for (set<String>::const_iterator it2 = ++(state._sources.begin()); it2 != state._sources.end(); ++it2) {
					output += "\t \t \t |   | \t \t | \t   | ";
					output += *it2 + "\n";
				}
			}

			output += "\n";
		}
	}
	output += "\n";

	return output;
}

String IGMPClientStates::interfaceStates(Element* e, void* thunk)
{
	IGMPClientStates* me = (IGMPClientStates*) e;

	String output;
	
	output += "\n";
	output += "\t \t \t I | \t GROUP \t | FILTER  | SOURCES \n";

	for (int i = 0; i < me->_interfaceStates.size(); i++) {
		Vector<InterfaceState> vStates = me->_interfaceStates.at(i);
		
		for(int j=0; j < vStates.size(); j++){
			InterfaceState state = vStates.at(j);
			output += "\t \t \t " + String(i) + " | ";
		   	output += "  " + state._groupAddress.unparse() + " | ";
			output += (state._filter == MODE_IS_EXCLUDE) ? "EXCLUDE | " : "INCLUDE | ";
			output += (!state._sources.empty()) ? *(state._sources.begin()) : " NONE";
			output += "\n";
			if (state._sources.size() > 1) {
				for (set<String>::const_iterator it = ++(state._sources.begin()); it != state._sources.end(); ++it) {
					output += "\t \t \t   | \t \t | \t   | ";
					output += *it + "\n";
				}
			}
			output += "\n";
		}
	}
	output += "\n";

	return output;
}

String IGMPClientStates::getRRV(Element* e, void* thunk)
{
    IGMPClientStates* me = (IGMPClientStates*) e;

    String output = String(me->_rrv) + "\n";

    return output;
}

String IGMPClientStates::getURI(Element* e, void* thunk)
{
    IGMPClientStates* me = (IGMPClientStates*) e;

    String output = String(me->_uri) + "s\n";

    return output;
}

int IGMPClientStates::setRRV(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
    IGMPClientStates* me = (IGMPClientStates *) e;

    unsigned int rrv;

    if (cp_va_kparse(conf, me, errh,
                    "VAL", cpkM + cpkP, cpUnsigned, &rrv,
                    cpEnd) < 0) {
            return -1;
    }

    if (rrv == 0) {
        return errh->error("RRV must not be equal to 0.");
    } else if (rrv == 1) {
        errh->warning("RRV should not be equal to 1.");
    }

    me->_rrv = rrv;

    return 0;
}

int IGMPClientStates::setURI(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
    IGMPClientStates* me = (IGMPClientStates *) e;

    unsigned int uri;

    if (cp_va_kparse(conf, me, errh,
                    "VAL", cpkM + cpkP, cpUnsigned, &uri,
                    cpEnd) < 0) {
            return -1;
    }

    me->_uri = uri;

    return 0;
}

void IGMPClientStates::add_handlers()
{
	add_read_handler("sockets", &socketStates, (void *) 0);
	add_read_handler("interfaces", &interfaceStates, (void *) 0);
    add_read_handler("rrv", &getRRV, (void *) 0);
	add_read_handler("uri", &getURI, (void *) 0);

    add_write_handler("rrv", &setRRV, (void *) 0);
	add_write_handler("uri", &setURI, (void *) 0);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPClientStates)
