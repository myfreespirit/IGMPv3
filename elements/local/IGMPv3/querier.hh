#ifndef CLICK_QUERIER_HH
#define CLICK_QUERIER_HH
#include <click/element.hh>
#include "igmprouterstates.hh"

CLICK_DECLS

class Querier : public Element {
	public:
		Querier();
		~Querier();
		
		const char *class_name() const	{ return "Querier"; }
		const char *port_count() const	{ return "3/3"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		
		void push(int, Packet *);
		void sendQuery(unsigned int interface, IPAddress group);

		static int generalQueryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
		static int groupQueryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
		void add_handlers();

		IGMPRouterStates* _states;
};

CLICK_ENDDECLS
#endif
