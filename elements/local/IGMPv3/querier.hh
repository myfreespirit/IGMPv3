
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
		const char *port_count() const	{ return "0/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		
		void push(int, Packet *);
		Packet* createGeneralQueryPacket(in_addr src, in_addr dst);
		//Packet* createReportPacket(in_addr, in_addr);

		static int generalQueryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
		void add_handlers();
		IGMPRouterStates* _states;
};

CLICK_ENDDECLS
#endif
