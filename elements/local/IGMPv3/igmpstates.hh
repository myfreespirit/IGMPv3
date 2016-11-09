#ifndef CLICK_IGMPSTATES_HH
#define CLICK_IGMPSTATES_HH

#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/vector.hh>

#include "states/interfacestate.hh"
#include "states/socketstate.hh"


CLICK_DECLS

class IGMPStates{
public:
	HashTable<int, SocketState> _socketStates;
	Vector<InterfaceState> _interfaceStates;

};


CLICK_ENDDECLS
#endif
