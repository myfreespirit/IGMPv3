#ifndef CLICK_IGMPCLIENTSTATES_HH
#define CLICK_IGMPCLIENTSTATES_HH

#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/vector.hh>

#include "states/interfacestate.hh"
#include "states/socketstate.hh"


CLICK_DECLS

class IGMPClientStates : public Element {
public:
	IGMPClientStates();
	~IGMPClientStates();

	const char *class_name() const  { return "IGMPClientStates"; }
	const char *port_count() const  { return "0/0"; }
	const char *processing() const  { return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);
		
	void push(int, Packet*);

	/**
	 * handlers
	 */
	static String socketStates(Element* e, void* thunk);
	static String interfaceStates(Element* e, void* thunk);
	void add_handlers();

	/**
	 * data members
	 */
	IPAddress _source;
	IPAddress _destination;
	HashTable<int, Vector<SocketState> > _socketStates;
	Vector<InterfaceState> _interfaceStates;
};


CLICK_ENDDECLS
#endif
