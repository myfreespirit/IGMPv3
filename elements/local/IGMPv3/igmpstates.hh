#ifndef CLICK_IGMPSTATES_HH
#define CLICK_IGMPSTATES_HH

#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/vector.hh>

#include "states/interfacestate.hh"
#include "states/socketstate.hh"


CLICK_DECLS

class IGMPStates : public Element {
public:
	IPAddress _source;
	IPAddress _destination;
	HashTable<int, SocketState> _socketStates;
	Vector<InterfaceState> _interfaceStates;

	IGMPStates();
	~IGMPStates();
	const char *class_name() const  { return "IGMPStates"; }
	const char *port_count() const  { return "0/0"; }
	const char *processing() const  { return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);
		
	void push(int, Packet*);
};


CLICK_ENDDECLS
#endif
