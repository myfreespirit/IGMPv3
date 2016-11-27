#ifndef CLICK_MULTICASTRECEIVER_HH
#define CLICK_MULTICASTRECEIVER_HH

#include <click/element.hh>
#include "infobases/igmpclientstates.hh"

CLICK_DECLS

class MulticastReceiver : public Element {
	public:
		MulticastReceiver();
		~MulticastReceiver();
		
		const char *class_name() const	{ return "MulticastReceiver"; }
		const char *port_count() const	{ return "1/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		
		void push(int, Packet *);

	private:
		IGMPClientStates* _states;
};

CLICK_ENDDECLS

#endif
