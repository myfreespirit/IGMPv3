#ifndef CLICK_MULTICASTSENDER_HH
#define CLICK_MULTICASTSENDER_HH

#include <click/element.hh>
#include "infobases/igmprouterstates.hh"

CLICK_DECLS

class MulticastSender : public Element {
	public:
		MulticastSender();
		~MulticastSender();
		
		const char *class_name() const	{ return "MulticastSender"; }
		const char *port_count() const	{ return "1/3"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		
		void push(int, Packet *);

	private:
		IGMPRouterStates* _states;
};

CLICK_ENDDECLS

#endif
