
#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>

#include "igmprouterstates.hh"


CLICK_DECLS

IGMPRouterStates::IGMPRouterStates()
{
}

IGMPRouterStates::~IGMPRouterStates()
{
}

int IGMPRouterStates::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh,
			"SRC", cpkM, cpIPAddress, &_source,
			"DST", cpkM, cpIPAddress, &_destination,
			//"SUB2", cpkM, cpIPAddress, &_subnet2,
			cpEnd) < 0)
		return -1;

	return 0;
}

void IGMPRouterStates::push(int, Packet *p)
{
	output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPRouterStates)
