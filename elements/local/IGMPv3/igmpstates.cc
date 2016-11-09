#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>

#include "igmpstates.hh"


CLICK_DECLS
IGMPStates::IGMPStates(){}
IGMPStates::~IGMPStates(){}

int IGMPStates::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_source, "DST", cpkM, cpIPAddress, &_destination, cpEnd) < 0) return -1;
	return 0;
}

void IGMPStates::push(int, Packet *p) {
	output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPStates)
