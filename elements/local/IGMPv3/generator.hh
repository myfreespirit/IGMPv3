
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
		Packet* createPacket(in_addr, in_addr);

		static int handle(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
		void add_handlers();
};

CLICK_ENDDECLS
#endif
