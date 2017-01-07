#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "querier.hh"
#include "messages.hh"

#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <click/timer.hh>

CLICK_DECLS

Querier::Querier() 
{
}

Querier::~Querier()
{
}

int Querier::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh, "ROUTER_STATES", cpkM, cpElementCast, "IGMPRouterStates", &_states, cpEnd) < 0) return -1;

    // Initialize timerstates
    _generalTimerState = new GeneralTimerState();
    _generalTimerState->me = this;
    _generalTimerState->counter = _states->_sqc;
    // Initialize timers
    _generalTimer = new Timer(&handleGeneralExpiry, _generalTimerState);
    _generalTimer->initialize(this);
    _generalTimer->schedule_after_sec(_states->_sqic);

	return 0;
}

void Querier::push(int interface, Packet *p)
{
	click_ip* iph = (click_ip*) p->data();
	Report* report = (Report*) (iph + 1); 
	GroupRecord* groupRecord = (GroupRecord*) (report + 1);
	unsigned int groupType = groupRecord->type;

	click_chatter("Router received a packet from %s on port/interface %d", IPAddress(iph->ip_src).unparse().c_str(), interface);
	
	if (groupType == CHANGE_TO_INCLUDE_MODE || groupType == CHANGE_TO_EXCLUDE_MODE) {
		click_chatter("Recognized FILTER-MODE-CHANGE report for group %s", IPAddress(groupRecord->multicast_address).unparse().c_str());
		int totalSources = ntohs(groupRecord->number_of_sources);
		Vector<IPAddress> vSources;
		Addresses* addresses = (Addresses*) (groupRecord + 1);
		for (int i = 0; i < totalSources; i++) {
			click_chatter("Extracted %s source IPAddress", IPAddress(addresses->array[i]).unparse().c_str());
			vSources.push_back(addresses->array[i]);
		}
		QUERY_MODE queryMode = _states->updateFilterChange(interface, groupRecord->multicast_address, groupType, vSources);

		if (queryMode == GROUP_QUERY) {
            // When a client leaves a group, we need to send a Group-Specific Query for that multicast address on received interface.
			sendQuery(interface, groupRecord->multicast_address);
		}
	} else if (groupType == MODE_IS_INCLUDE || groupType == MODE_IS_EXCLUDE) {
		click_chatter("Recognized CURRENT-STATE report for %d groups", ntohs(report->number_of_group_records));

		int totalGroups = ntohs(report->number_of_group_records);
		for (int g = 0; g < totalGroups; g++) {
			int totalSources = ntohs(groupRecord->number_of_sources);
			Vector<IPAddress> vSources;
			Addresses* addresses = (Addresses*) (groupRecord + 1);
			for (int i = 0; i < totalSources; i++) {
				click_chatter("Extracted %s source IPAddress", IPAddress(addresses->array[i]).unparse().c_str());
				vSources.push_back(addresses->array[i]);
			}
			_states->updateCurrentState(interface, groupRecord->multicast_address, groupType, vSources);
			groupRecord = (GroupRecord*) (addresses + totalSources);
		}
    } else if (groupType == ALLOW_NEW_SOURCES || groupType == BLOCK_OLD_SOURCES) {
        // wasn't required to implement ([RFC 3376] page 17)
    } else {
        // Unrecognized Record Type values MUST be silently ignored.
    }
}

void Querier::sendQuery(unsigned int interface, IPAddress group = IPAddress("0.0.0.0"))
{
	int headroom = sizeof(click_ether) + sizeof(click_ip);
	int messageSize = sizeof(struct Query);
	int packetSize = messageSize;
	WritablePacket* q = Packet::make(headroom, 0, packetSize, 0);

	if (!q) {
        click_chatter("ERROR: Querier was unable to create a new WritablePacket.");
		return;
	}

	memset(q->data(), '\0', packetSize);

	Query* query = (Query *) q->data();
	query->type = IGMP_TYPE_QUERY;
	query->checksum = htons(0);
	query->group_address = group;
    if (group == IPAddress()) {
        // General Query
        query->max_resp_code = _states->_qri;
        // 4 bits Reserved, 1 bit Supressed, 3 bits QRV
    	query->resvSQRV = (0 << 4) | (0 << 3) | (_states->_qrv);
    } else {
        // Group Specific Query
        query->max_resp_code = _states->_lmqi;
        // 4 bits Reserved, 1 bit Supressed, 3 bits QRV
    	query->resvSQRV = (0 << 4) | (0 << 3) | (_states->_lmqc);
    }
	query->QQIC = (_generalTimerState->counter > 1) ? _states->_sqic : _states->_qic;
    query->number_of_sources = htons(0);

	query->checksum = click_in_cksum((unsigned char*) query, messageSize);

	q->set_dst_ip_anno(_states->_destination);

	click_chatter("Router sent a query on interface %u for group %s", interface, group.unparse().c_str());

	output(interface).push(q);
}

int Querier::generalQueryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh) {
	Querier* me = (Querier *) e;

	if (cp_va_kparse(conf, me, errh, cpEnd) < 0) {
		return -1;
	}

	me->sendQuery(0);
	me->sendQuery(1);
	me->sendQuery(2);
}

int Querier::groupQueryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh) {
	Querier* me = (Querier *) e;

	unsigned int interface;
	IPAddress group;

	if (cp_va_kparse(conf, me, errh,
			"INTERFACE", cpkM, cpUnsigned, &interface,
			"GROUP", cpkM, cpIPAddress, &group,
			cpEnd) < 0) {
		return -1;
	}

	me->sendQuery(interface, group);
}

void Querier::add_handlers() {
	add_write_handler("general_query", &generalQueryHandler, (void *) 0);
	add_write_handler("group_query", &groupQueryHandler, (void *) 0);
}

void Querier::handleGeneralExpiry(Timer*, void* data)
{
	GeneralTimerState* timerState = (GeneralTimerState*) data;
	assert(timerState);  // the cast must be good
	timerState->me->expireGeneral(timerState);
}

void Querier::expireGeneral(GeneralTimerState* timerState)
{
    // Send out General Queries on each interface
	sendQuery(0);
	sendQuery(1);
	sendQuery(2);

    int sec;
    // Schedule timer for next general query transmission
    if (timerState->counter > 1) {
        // Startup procedure, all startup queries are sent out when counter == 1
		sec = _states->_sqic;
        timerState->counter--;
    } else {
        // Normal procedure
        sec = _states->_qic;
	}

   	_generalTimer->schedule_after_sec(sec);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Querier)
