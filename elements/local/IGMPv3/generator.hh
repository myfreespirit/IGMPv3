
#ifndef CLICK_GENERATOR_HH
#define CLICK_GENERATOR_HH
#include <click/element.hh>
CLICK_DECLS

class Generator : public Element { 
	public:
		Generator();
		~Generator();
		
		const char *class_name() const	{ return "Generator"; }
		const char *port_count() const	{ return "0/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		
		void push(int, Packet *);
		Packet* createQueryPacket(in_addr, in_addr);
		Packet* createReportPacket(in_addr, in_addr);

		static int queryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
		static int reportHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
		void add_handlers();
};

CLICK_ENDDECLS
#endif
