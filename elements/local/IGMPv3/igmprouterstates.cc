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
			cpEnd) < 0)
		return -1;

	return 0;
}

void IGMPRouterStates::push(int, Packet *p)
{
	output(0).push(p);
}

// RFC 3376, page 32 + 33
void IGMPRouterStates::updateRecords(unsigned int interface, IPAddress groupAddress, unsigned int filter, Vector<IPAddress> sources) {
	if (interface >= _records.size()) {
		_records.resize(interface + 1);
	}
	
	// if record with given group didn't exist yet, it will be added as INCLUDE {} rightaway
	RouterRecord routerRecord = _records.at(interface)[groupAddress];
	if (routerRecord._filter == MODE_IS_INCLUDE) {
		if (filter == CHANGE_TO_EXCLUDE_MODE) {
			routerRecord._filter = MODE_IS_EXCLUDE;
			// _forwardingSet is already {}
			// routerRecord._blockingSet = sources;  // TODO
			// TODO set group timer for routerRecord
		} else {
			// from INCLUDE to ALLOW | BLOCK | TO_IN isn't required in our version
		}
	} else {
		// router-filter-mode is EXCLUDE	
		if (filter == CHANGE_TO_INCLUDE_MODE) {
			// router-filter-mode remains EXCLUDE
			//routerRecord._forwaringSet = sources;  // TODO
			//routerRecord._blockingSet = sources;  // TODO
			// TODO send group specific query for groupAddress
		} else {
			// from EXCLUDE to ALLOW | BLOCK | TO_EX isn't required in our version
		}
	}
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPRouterStates)
