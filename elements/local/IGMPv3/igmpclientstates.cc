#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>

#include "igmpclientstates.hh"


CLICK_DECLS

IGMPClientStates::IGMPClientStates(){}
IGMPClientStates::~IGMPClientStates(){}

int IGMPClientStates::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, 
			"SRC", cpkM, cpIPAddress, &_source, 
			"DST", cpkM, cpIPAddress, &_destination,
			cpEnd) < 0)
		return -1;

	return 0;
}

void IGMPClientStates::push(int, Packet *p) {
	output(0).push(p);
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
				for (std::set<String>::const_iterator it2 = ++(state._sources.begin()); it2 != state._sources.end(); ++it2) {
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
	output += " I | \t GROUP | FILTER  | SOURCES \n";

	for (int i = 0; i < me->_interfaceStates.size(); i++) {
		Vector<InterfaceState> vStates = me->_interfaceStates.at(i);
		
		for(int j=0; j < vStates.size(); j++){
			InterfaceState state = vStates.at(j);
			output += " " + String(i) + " | ";
		   	output += state._groupAddress.unparse() + " | ";
			output += (state._filter == MODE_IS_EXCLUDE) ? "EXCLUDE | " : "INCLUDE | ";
			output += (!state._sources.empty()) ? *(state._sources.begin()) : " NONE";
			output += "\n";
			if (state._sources.size() > 1) {
				for (std::set<String>::const_iterator it = ++(state._sources.begin()); it != state._sources.end(); ++it) {
					//output += "   | \t \t | \t  |  ";
					output += " " + String(i) + " | ";
				   	output += state._groupAddress.unparse() + " | ";
					output += (state._filter == MODE_IS_EXCLUDE) ? "EXCLUDE | " : "INCLUDE | ";
					output += *it + "\n";
				}
			}
			output += "\n";

		}



	}

	output += "\n";

	return output;
}

void IGMPClientStates::add_handlers()
{
	add_read_handler("sockets", &socketStates, (void *) 0);
	add_read_handler("interfaces", &interfaceStates, (void *) 0);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPClientStates)
