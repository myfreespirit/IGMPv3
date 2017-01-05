#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <algorithm>

#include "igmprouterstates.hh"
#include "../utils/vectoroperations.hh"

using namespace vectoroperations;

CLICK_DECLS


IGMPRouterStates::IGMPRouterStates() : _qrv(2), _qic(125), _qri(100)
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

// @requires _records must be big enough (interface)
// @requires _records must already contain a record for given groupAddress
Vector<IPAddress> IGMPRouterStates::getSourceAddresses(unsigned int interface, IPAddress groupAddress, FilterMode filter)
{
	Vector<SourceRecord> vSourceRecords;
	if (filter == MODE_IS_INCLUDE) {
		vSourceRecords = _records.at(interface)[groupAddress]._forwardingSet;
	} else if (filter == MODE_IS_EXCLUDE) {
		vSourceRecords = _records.at(interface)[groupAddress]._blockingSet;
	}

	Vector<IPAddress> vSources;
	int total = vSourceRecords.size();
	for (int i = 0; i < total; i++) {
		vSources.push_back(vSourceRecords.at(i)._sourceAddress);
	}

	return vSources;
}

/*
 * Deletes froms records all matching sources from set x
 */
void IGMPRouterStates::removeSourceRecords(Vector<SourceRecord>& records, Vector<IPAddress> x)
{
	Vector<SourceRecord>::iterator it;
	Vector<IPAddress>::const_iterator it2;
	for (it = records.begin(); it != records.end(); it++) {
		for (it2 = x.begin(); it2 != x.end(); it2++) {
			if (it->_sourceAddress == *it2) {
				records.erase(it);
				it--;
				break;
			}
		}
	}
}

Vector<SourceRecord> IGMPRouterStates::transformToSourceRecords(Vector<IPAddress> a)
{
	Vector<SourceRecord> result;
	for (Vector<IPAddress>::iterator it = a.begin(); it != a.end(); it++) {
		SourceRecord sr(*it);		
		result.push_back(sr);
	}

	return result;
}

// RFC 3376, page 30 - 31
// @ REQUIRES that the received packet contains CURRENT STATE group record types
void IGMPRouterStates::updateCurrentState(unsigned int interface, IPAddress groupAddress, unsigned int filter, Vector<IPAddress> sources)
{
	if (interface >= _records.size()) {
		_records.resize(interface + 1);
	}

	// if record with given group didn't exist yet, it will be added as INCLUDE {} rightaway
	RouterRecord routerRecord = _records.at(interface)[groupAddress];
	click_chatter("router's filter mode: %d, client's: %u", routerRecord._filter, filter);
	
	Vector<IPAddress> routerForwardingSources = getSourceAddresses(interface, groupAddress, MODE_IS_INCLUDE);

	if (routerRecord._filter == MODE_IS_INCLUDE) {	
		if (filter == MODE_IS_INCLUDE) {
			// router's filter mode remains include
			
			Vector<IPAddress> newForwarding = vector_union(routerForwardingSources, sources);
			routerRecord._forwardingSet = transformToSourceRecords(newForwarding);

			// TODO set source timer for set B to GMI
		} else {
			// client-filter-mode is EXCLUDE
			
			Vector<IPAddress> newForwarding = vector_intersect(sources, routerForwardingSources); 
			Vector<IPAddress> newBlocking = vector_difference(sources, routerForwardingSources); 
			Vector<IPAddress> toDeleteFromForwards = vector_difference(routerForwardingSources, sources);
			
			routerRecord._forwardingSet = transformToSourceRecords(newForwarding);
			routerRecord._blockingSet = transformToSourceRecords(newBlocking);
			removeSourceRecords(routerRecord._forwardingSet, toDeleteFromForwards);
			routerRecord._filter = MODE_IS_EXCLUDE;

			// TODO set source timer for set (B-A) to 0
			// TODO set group timer to GMI
		}
	} else {
		// router-filter-mode is and remains EXCLUDE
		Vector<IPAddress> routerBlockingSources = getSourceAddresses(interface, groupAddress, MODE_IS_EXCLUDE);

		if (filter == MODE_IS_INCLUDE) {
			Vector<IPAddress> newForwarding = vector_union(routerForwardingSources, sources); 
			Vector<IPAddress> newBlocking = vector_difference(routerBlockingSources, sources); 	

			routerRecord._forwardingSet = transformToSourceRecords(newForwarding);
			routerRecord._blockingSet = transformToSourceRecords(newBlocking);

			// TODO set source timer for set A to GMI
		} else {
			// client-filter-mode is EXCLUDE

			Vector<IPAddress> newForwarding = vector_difference(sources, routerBlockingSources);
			Vector<IPAddress> newBlocking = vector_intersect(sources, routerBlockingSources);
			Vector<IPAddress> toDeleteFromForwards = vector_difference(routerForwardingSources, sources);
			Vector<IPAddress> toDeleteFromBlocks = vector_difference(routerBlockingSources, sources);

			routerRecord._forwardingSet = transformToSourceRecords(newForwarding);
			routerRecord._blockingSet = transformToSourceRecords(newBlocking);

			routerRecord._forwardingSet = transformToSourceRecords(newForwarding);
			routerRecord._blockingSet = transformToSourceRecords(newBlocking);
			removeSourceRecords(routerRecord._forwardingSet, toDeleteFromForwards);
			removeSourceRecords(routerRecord._blockingSet, toDeleteFromBlocks);

			// TODO set source timers for set (A-X-Y) to GMI
			// TODO set group timer to GMI
		}
	}
			
	_records.at(interface)[groupAddress] = routerRecord;

	click_chatter("NEW ROUTER FILTER:%d, ALLOW:%d, BLOCK:%d", routerRecord._filter, routerRecord._forwardingSet.size(), routerRecord._blockingSet.size());
}

// RFC 3376, page 31 - 33
QUERY_MODE IGMPRouterStates::updateFilterChange(unsigned int interface, IPAddress groupAddress, unsigned int filter, Vector<IPAddress> sources)
{
	QUERY_MODE result = NO_QUERY;

	if (interface >= _records.size()) {
		_records.resize(interface + 1);
	}
	
	// if record with given group didn't exist yet, it will be added as INCLUDE {} rightaway
	RouterRecord routerRecord = _records.at(interface)[groupAddress];
	click_chatter("router's filter mode: %d, client's: %u", routerRecord._filter, filter);
	Vector<IPAddress> routerForwardingSources = getSourceAddresses(interface, groupAddress, MODE_IS_INCLUDE);

	if (routerRecord._filter == MODE_IS_INCLUDE) {
		if (filter == CHANGE_TO_EXCLUDE_MODE) {
			// TODO set group timer for routerRecord
			// TODO set source timer for difference set (B-A)

			Vector<IPAddress> newForwarding = vector_intersect(sources, routerForwardingSources); 
			Vector<IPAddress> newBlocking = vector_difference(sources, routerForwardingSources); 	
			Vector<IPAddress> toDeleteForwards = vector_difference(routerForwardingSources, sources);

			routerRecord._forwardingSet = transformToSourceRecords(newForwarding);
			routerRecord._blockingSet = transformToSourceRecords(newBlocking);
			removeSourceRecords(routerRecord._forwardingSet, toDeleteForwards);
			routerRecord._filter = MODE_IS_EXCLUDE;
		} else {
			// from INCLUDE to ALLOW | BLOCK | TO_IN isn't required in our version
		}
	} else {
		// router-filter-mode is EXCLUDE	
		if (filter == CHANGE_TO_INCLUDE_MODE) {
			// router-filter-mode remains EXCLUDE

			Vector<IPAddress> routerBlockingSources = getSourceAddresses(interface, groupAddress, MODE_IS_EXCLUDE);

			Vector<IPAddress> newForwarding = vector_union(routerForwardingSources, sources); 
			Vector<IPAddress> newBlocking = vector_difference(routerBlockingSources, sources); 
			
			routerRecord._forwardingSet = transformToSourceRecords(newForwarding);
			routerRecord._blockingSet = transformToSourceRecords(newBlocking);

			// TODO set source timer for sources A
			result = GROUP_QUERY;
		} else {
			// from EXCLUDE to ALLOW | BLOCK | TO_EX isn't required in our version
		}
	}

	_records.at(interface)[groupAddress] = routerRecord;

	click_chatter("NEW ROUTER FILTER:%d, ALLOW:%d, BLOCK:%d", routerRecord._filter, routerRecord._forwardingSet.size(), routerRecord._blockingSet.size());

	return result;
}

bool IGMPRouterStates::isMulticastAllowed(unsigned int interface, IPAddress group, IPAddress source)
{
	if (interface >= _records.size())
		return false;
	
	FilterMode filter = _records.at(interface).get(group)._filter;

	if (filter == MODE_IS_EXCLUDE) {
	    Vector<SourceRecord> blockedSourceList = _records.at(interface).get(group)._blockingSet;
        Vector<SourceRecord>::const_iterator it;
        for (it = blockedSourceList.begin(); it != blockedSourceList.end(); it++) {
            if (it->_sourceAddress == source) {
                return false;
            }
        } 
        return true;
    } else if (filter == MODE_IS_INCLUDE) {
	    Vector<SourceRecord> allowedSourceList = _records.at(interface).get(group)._forwardingSet;
        Vector<SourceRecord>::const_iterator it;
        for (it = allowedSourceList.begin(); it != allowedSourceList.end(); it++) {
            if (it->_sourceAddress == source) {
                return true;
            }
        } 
        return false;
 
    }
}

String IGMPRouterStates::recordStates(Element* e, void* thunk)
{
	IGMPRouterStates* me = (IGMPRouterStates*) e;

	String output;
	
	output += "\n";
	output += "\t I | \t GROUP \t | G.Tmr | FILTER  | ALLOW | S.Tmr | BLOCK | S.Tmr \n";

	int amountOfInterfaces = me->_records.size();
	for (int i = 0; i < amountOfInterfaces; i++) {
		HashTable<IPAddress, RouterRecord>::const_iterator it;
		for (it = me->_records.at(i).begin(); it != me->_records.at(i).end(); it++) {
			IPAddress group = it.key();
			RouterRecord record = it.value();
			int amountOfAllows = record._forwardingSet.size();
			int amountOfBlocks = record._blockingSet.size();

			output += "\t " + String(i) + " | ";
			output += " " + group.unparse() + "  | ";
			output += "X sec | ";
			output += (record._filter == MODE_IS_INCLUDE) ? "INCLUDE | " : "EXCLUDE | ";
			
			output += (amountOfAllows) ? record._forwardingSet.at(0)._sourceAddress.unparse() : " \t  ";
			output += " | ";
			output += "X sec | ";
			output += (amountOfBlocks) ? record._blockingSet.at(0)._sourceAddress.unparse() : " \t  ";
			output += " | ";
			output += "X sec \n";

			// TODO refactor output, so it won't duplicate unnecessary fields
			//  	that will also FIX empty source set records that aren't displayed
			for (int k = 1; k < std::max(amountOfAllows, amountOfBlocks); k++) {
				output += "\t   | ";
				output += " \t \t  | ";
				output += "      | ";
				output += "        | ";

				output += (k < amountOfAllows) ? record._forwardingSet.at(k)._sourceAddress.unparse() : " \t  ";
				output += " | ";
				
				output += "X sec | ";
				
				output += (k < amountOfBlocks) ? record._blockingSet.at(k)._sourceAddress.unparse() : " \t  ";
				output += " | ";
				
				output += "X sec \n";
			}
			output += "\n";
		}
		output += "\n";
	}

	output += "\n";

	return output;
}

String IGMPRouterStates::getQRV(Element* e, void* thunk)
{
    IGMPRouterStates* me = (IGMPRouterStates*) e;

    String output = String(me->_qrv) + "\n";

    return output;
}

String IGMPRouterStates::getQIC(Element* e, void* thunk)
{
    IGMPRouterStates* me = (IGMPRouterStates*) e;

    String output = String(me->_qic) + " (= " + String(me->codeToSeconds(me->_qic)) + "s)\n";

    return output;
}

String IGMPRouterStates::getQRI(Element* e, void* thunk)
{
    IGMPRouterStates* me = (IGMPRouterStates*) e;

    String output = String(me->_qri) + " (= " + String(me->codeToSeconds(me->_qri)) + "s)\n";

    return output;
}

int IGMPRouterStates::setQRV(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
    IGMPRouterStates* me = (IGMPRouterStates *) e;

    unsigned int qrv;

    if (cp_va_kparse(conf, me, errh,
                    "VAL", cpkM + cpkP, cpUnsigned, &qrv,
                    cpEnd) < 0) {
            return -1;
    }

    if (qrv == 0) {
        return errh->error("QRV must not be equal to 0.");
    } else if (qrv == 1) {
        errh->warning("QRV should not be equal to 1.");
    } else if (qrv > 7) {
        qrv = 2;  // use default, as QRV is only 3 bits long
        errh->warning("Max value for QRV is 7. Setting it to default: 2.");
    }

    me->_qrv = qrv;

    return 0;
}

int IGMPRouterStates::setQIC(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
	IGMPRouterStates* me = (IGMPRouterStates *) e;

    unsigned int qic;

	if (cp_va_kparse(conf, me, errh,
			"VAL", cpkM + cpkP, cpUnsigned, &qic,
			cpEnd) < 0) {
		return -1;
	}

    if (qic <= me->_qri) {
        return errh->error("QIC must be greater than QRI.");
    }

    me->_qic = qic;

    return 0;
}

int IGMPRouterStates::setQRI(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
	IGMPRouterStates* me = (IGMPRouterStates *) e;

    unsigned int qri;

	if (cp_va_kparse(conf, me, errh,
			"VAL", cpkM + cpkP, cpUnsigned, &qri,
			cpEnd) < 0) {
		return -1;
	}

    if (qri >= me->_qic) {
        return errh->error("QRI must be less than QIC.");
    }

    me->_qri = qri;

    return 0;
}

void IGMPRouterStates::add_handlers()
{
	add_read_handler("records", &recordStates, (void *) 0);
    add_read_handler("qrv", &getQRV, (void *) 0);
    add_read_handler("qic", &getQIC, (void *) 0);
    add_read_handler("qri", &getQRI, (void *) 0);

    add_write_handler("qrv", &setQRV, (void *) 0);
    add_write_handler("qic", &setQIC, (void *) 0);
    add_write_handler("qri", &setQRI, (void *) 0);
}

double IGMPRouterStates::codeToSeconds(unsigned int code)
{
    if (code < 128) {
        return code / 10.0;
    }

    uint8_t exp = (code & 112) >> 4;
    uint8_t mant = (code & 15);
    return ((mant | 0x10) << (exp + 3)) / 10.0;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPRouterStates)
