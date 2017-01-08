#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/timer.hh>

#include <algorithm>

#include "igmprouterstates.hh"
#include "../utils/vectoroperations.hh"

using namespace vectoroperations;

CLICK_DECLS


IGMPRouterStates::IGMPRouterStates() : _qrv(2), _qic(125), _qri(100), _sqic(_qic/4), _sqc(_qrv), _lmqi(10), _lmqc(_qrv)
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

void IGMPRouterStates::handleExpiryGroup(Timer*, void* data)
{
    GroupTimerState* timerState = (GroupTimerState*) data;
	assert(timerState);  // the cast must be good
	timerState->me->expireGroup(timerState);
}

void IGMPRouterStates::expireGroup(GroupTimerState* timerState)
{
    int interface = timerState->interface;
    IPAddress group = timerState->group;
    FilterMode filter = timerState->filter;

    if (filter == MODE_IS_EXCLUDE) {
        // router's fitler mode transitions to INCLUDE after group timer expires[RFC3376] p.33
        RouterRecord* record = &_records.at(interface)[group];

        if (record->_forwardingSet.size() == 0) {
            // all source timers expired, delete Record
            _records.at(interface).erase(group);
            _groupTimers.at(interface).erase(group);
        } else {
            record->_filter = MODE_IS_INCLUDE;

            // remove source records with source timer == 0
            record->_blockingSet.clear();
        }
    }
}

void IGMPRouterStates::scheduleGMI(int interface, IPAddress groupAddress, int delay)
{
    RouterRecord* record = &_records.at(interface)[groupAddress];
    if (_groupTimerStates.size() <= interface) {
        _groupTimerStates.resize(interface + 1);
    }
    GroupTimerState* groupTimerState = _groupTimerStates.at(interface)[groupAddress];
    if (groupTimerState == NULL) {
        groupTimerState = new GroupTimerState();
        groupTimerState->me = this;
    }
    groupTimerState->interface = interface;
    groupTimerState->group = groupAddress;
    groupTimerState->filter = record->_filter;
    _groupTimerStates.at(interface)[groupAddress] = groupTimerState;

    if (_groupTimers.size() <= interface) {
        _groupTimers.resize(interface + 1);
    }
    Timer* groupTimer = _groupTimers.at(interface)[groupAddress];
    if (groupTimer == NULL) {
        groupTimer = new Timer(&handleExpiryGroup, groupTimerState);
        groupTimer->initialize(this);
    }
    groupTimer->schedule_after_sec(delay);
    _groupTimers.at(interface)[groupAddress] = groupTimer;
    click_chatter("remaining GMI: %d s\n", computeRemainingGMI(interface, groupAddress));
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
            // NOOP as B is an empty set
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
            // NOOP as B-A is an empty set

			// schedule group timer to GMI
            scheduleGMI(interface, groupAddress, computeGMI());
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
            // NOOP as A is an empty set
		} else {
			// client-filter-mode is EXCLUDE

			Vector<IPAddress> newForwarding = vector_difference(sources, routerBlockingSources);
			Vector<IPAddress> newBlocking = vector_intersect(sources, routerBlockingSources);
			Vector<IPAddress> toDeleteFromForwards = vector_difference(routerForwardingSources, sources);
			Vector<IPAddress> toDeleteFromBlocks = vector_difference(routerBlockingSources, sources);

			routerRecord._forwardingSet = transformToSourceRecords(newForwarding);
			routerRecord._blockingSet = transformToSourceRecords(newBlocking);
			removeSourceRecords(routerRecord._forwardingSet, toDeleteFromForwards);
			removeSourceRecords(routerRecord._blockingSet, toDeleteFromBlocks);

			// TODO set source timers for set (A-X-Y) to GMI
            // NOOP as A-X-Y is empty set
            
			// set group timer to GMI
            scheduleGMI(interface, groupAddress, computeGMI());
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
			// TODO set source timer for difference set (B-A) to 0
            // NOOP as B-A is an empty set

			Vector<IPAddress> newForwarding = vector_intersect(sources, routerForwardingSources); 
			Vector<IPAddress> newBlocking = vector_difference(sources, routerForwardingSources); 	
			Vector<IPAddress> toDeleteForwards = vector_difference(routerForwardingSources, sources);

			routerRecord._forwardingSet = transformToSourceRecords(newForwarding);
			routerRecord._blockingSet = transformToSourceRecords(newBlocking);
			removeSourceRecords(routerRecord._forwardingSet, toDeleteForwards);
			routerRecord._filter = MODE_IS_EXCLUDE;
            
			// set group timer to GMI for Record
            scheduleGMI(interface, groupAddress, computeGMI());
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

			// TODO set source timer for sources A to 0
            // NOOP as A is an empty set
			
            result = GROUP_QUERY;
            scheduleGMI(interface, groupAddress, computeLMQT()); 
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
			output += " " + String(me->computeRemainingGMI(i, group)) + "s | ";
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

    String output = String(me->_qri) + " (= " + String(me->codeToSeconds(me->_qri)/10.0) + "s)\n";

    return output;
}

int IGMPRouterStates::computeGMI()
{
    return _qrv * codeToSeconds(_qic) + codeToSeconds(_qri)/10.0;
}

int IGMPRouterStates::computeRemainingGMI(int interface, IPAddress group)
{
    if (_groupTimers.size() <= interface || _groupTimers.at(interface)[group] == NULL) {
        return 0;
    }

    return (_groupTimers.at(interface)[group]->expiry_steady() - Timestamp::now_steady()).sec();
}

String IGMPRouterStates::getGMI(Element* e, void* thunk)
{
    IGMPRouterStates* me = (IGMPRouterStates*) e;

    String output = String(me->computeGMI()) + "s\n";

    return output;
}

String IGMPRouterStates::getSQIC(Element* e, void* thunk)
{
    IGMPRouterStates* me = (IGMPRouterStates*) e;

    String output = String(me->_sqic) + " (= " + String(me->codeToSeconds(me->_sqic)) + "s)\n";

    return output;
}

String IGMPRouterStates::getSQC(Element* e, void* thunk)
{
    IGMPRouterStates* me = (IGMPRouterStates*) e;

    String output = String(me->_sqc) + "\n";

    return output;
}

String IGMPRouterStates::getLMQI(Element* e, void* thunk)
{
    IGMPRouterStates* me = (IGMPRouterStates*) e;

    double lmqiTime = me->codeToSeconds(me->_lmqi)/10.0;

    String output = String(me->_lmqi) + " (= " + String(lmqiTime) + "s)\n";

    return output;
}

String IGMPRouterStates::getLMQC(Element* e, void* thunk)
{
    IGMPRouterStates* me = (IGMPRouterStates*) e;

    String output = String(me->_lmqc) + "\n";

    return output;
}

double IGMPRouterStates::computeLMQT()
{
    return _lmqc * codeToSeconds(_lmqi)/10.0;
}

String IGMPRouterStates::getLMQT(Element* e, void* thunk)
{
    IGMPRouterStates* me = (IGMPRouterStates*) e;

    String output = String(me->computeLMQT()) + "s\n";

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

    if (me->codeToSeconds(qic) <= me->codeToSeconds(me->_qri)/10.0) {
        return errh->error("QIC must be greater than QRI in seconds equivalent.");
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

    if (me->codeToSeconds(qri)/10.0 >= me->codeToSeconds(me->_qic)) {
        return errh->error("QRI must be less than QIC in seconds equivalent.");
    }

    me->_qri = qri;

    return 0;
}

int IGMPRouterStates::setLMQI(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
	IGMPRouterStates* me = (IGMPRouterStates *) e;

	if (cp_va_kparse(conf, me, errh,
			"VAL", cpkM + cpkP, cpUnsigned, &me->_lmqi,
			cpEnd) < 0) {
		return -1;
	}

    return 0;
}

int IGMPRouterStates::setLMQC(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
    IGMPRouterStates* me = (IGMPRouterStates *) e;

    unsigned int lmqc;

    if (cp_va_kparse(conf, me, errh,
                    "VAL", cpkM + cpkP, cpUnsigned, &lmqc,
                    cpEnd) < 0) {
            return -1;
    }

    if (lmqc == 0) {
        return errh->error("LMQC must not be equal to 0.");
    } else if (lmqc == 1) {
        errh->warning("LMQC should not be equal to 1.");
    } else if (lmqc > 7) {
        lmqc = 2;  // use default, as LMQC is only 3 bits long
        errh->warning("Max value for LMQC is 7. Setting it to default: 2.");
    }

    me->_lmqc = lmqc;

    return 0;
}

void IGMPRouterStates::add_handlers()
{
	add_read_handler("records", &recordStates, (void *) 0);
    add_read_handler("qrv", &getQRV, (void *) 0);
    add_read_handler("qic", &getQIC, (void *) 0);
    add_read_handler("qri", &getQRI, (void *) 0);
    add_read_handler("gmi", &getGMI, (void *) 0);
    add_read_handler("sqic", &getSQIC, (void *) 0);
    add_read_handler("sqc", &getSQC, (void *) 0);
    add_read_handler("lmqi", &getLMQI, (void *) 0);
    add_read_handler("lmqc", &getLMQC, (void *) 0);
    add_read_handler("lmqt", &getLMQT, (void *) 0);

    add_write_handler("qrv", &setQRV, (void *) 0);
    add_write_handler("qic", &setQIC, (void *) 0);
    add_write_handler("qri", &setQRI, (void *) 0);
    add_write_handler("lmqi", &setLMQI, (void *) 0);
    add_write_handler("lmqc", &setLMQC, (void *) 0);
}

double IGMPRouterStates::codeToSeconds(unsigned int code)
{
    if (code < 128) {
        return code;
    }

    uint8_t exp = (code & 112) >> 4;
    uint8_t mant = (code & 15);
    return (mant | 0x10) << (exp + 3);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPRouterStates)
