#ifndef CLICK_IGMPROUTERSTATES_HH
#define CLICK_IGMPROUTERSTATES_HH

#include <click/element.hh>
#include <click/vector.hh>

CLICK_DECLS

class IGMPRouterStates : public Element {
public:
	IGMPRouterStates();
	~IGMPRouterStates();

	const char *class_name() const  { return "IGMPRouterStates"; }
	const char *port_count() const  { return "0/0"; }
	const char *processing() const  { return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);

	void push(int, Packet*);


	/**
	 * data members
	 */
	IPAddress _source;
	IPAddress _subnet1;
	IPAddress _subnet2;
};


CLICK_ENDDECLS
#endif
