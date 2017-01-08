#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/timestamp.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>

#include "reporter.hh"
#include "messages.hh"
#include "utils/filtermode.hh"

#include <stdlib.h>
#include <time.h>

CLICK_DECLS

Reporter::Reporter()
{
}

Reporter::~Reporter()
{
}

int Reporter::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh, "CLIENT_STATES", cpkM, cpElementCast, "IGMPClientStates", &_states, cpEnd) < 0) return -1;

	return 0;
}

void Reporter::reportGroupState(IPAddress group)
{
	// skip non existent interface states
    if (_states->_interfaceStates.size() == 0) {
        return;
    }

	if (group == IPAddress("224.0.0.1"))
		return;
    
    int groupIndex;
	int totalSources;
	FilterMode filter;
	set<String> sources;
	int interface = 0;  // assume group query arrived at interface 0

	for (groupIndex = 0; groupIndex < _states->_interfaceStates.at(interface).size(); groupIndex++) {
		if (_states->_interfaceStates.at(interface).at(groupIndex)._groupAddress == group) {
			filter = _states->_interfaceStates.at(interface).at(groupIndex)._filter;
			sources = _states->_interfaceStates.at(interface).at(groupIndex)._sources;
			totalSources = sources.size();
            break;
		}
	}

	// check if client is a member of that group first
	if (groupIndex == _states->_interfaceStates.at(interface).size())
		return;

    int headroom = sizeof(click_ether) + sizeof(click_ip);
    int messageSize = sizeof(struct Report) + sizeof(struct GroupRecord) + sizeof(struct Addresses) * totalSources;
	int packetSize = messageSize;

	WritablePacket* q = Packet::make(headroom, 0, packetSize, 0);

	if (!q) {
        click_chatter("ERROR: Reporter was unable to create a new WritablePacket to send reply to Group-Specific-Query.");
		return;
	}

	memset(q->data(), '\0', packetSize);

    Report* report = (Report *) q->data();
    report->type = IGMP_TYPE_REPORT;
    report->checksum = htons(0);
    report->number_of_group_records = htons(1); 

	GroupRecord* groupRecord = (GroupRecord*) (report + 1);
	groupRecord->type = filter; 
	groupRecord->aux_data_len = 0;
	groupRecord->multicast_address = group; 

	// fill source list of matching (interface, group)
	groupRecord->number_of_sources = htons(totalSources);
	set<String>::iterator it = sources.begin();
	Addresses* addresses = (Addresses*) (groupRecord + 1);
	for (int i = 0; i < totalSources; i++) {
		addresses->array[i] = IPAddress(*it);
		std::advance(it, 1);
	}

    report->checksum = click_in_cksum((unsigned char*) report, messageSize);
    
	q->set_dst_ip_anno(_states->_destination);

	output(interface).push(q);
}

void Reporter::reportCurrentState()
{
	// skip non existent interface states
    if (_states->_interfaceStates.size() == 0) {
        return;
    }
    
    int interface = 0;  // assume general query arrived at interface 0
    int numberOfGroups = _states->_interfaceStates.at(interface).size() - 1;  // subtract the all hosts membership group
    click_chatter("%s is member of %d groups on interface %d", _states->_source.unparse().c_str(), numberOfGroups, interface);
    if (numberOfGroups == 0)
        return;
        
	int totalSources = 0;
    for (int i = 1; i <= numberOfGroups; i++) {
	    totalSources += this->_states->_interfaceStates.at(interface).at(i)._sources.size();
	}

    int headroom = sizeof(click_ether) + sizeof(click_ip);
	int messageSize = sizeof(struct Report) + sizeof(struct GroupRecord) * numberOfGroups + sizeof(struct Addresses) * totalSources;
	int packetSize = messageSize;

	WritablePacket* q = Packet::make(headroom, 0, packetSize, 0);

	if (!q) {
        click_chatter("ERROR: Reporter was unable to create a new WritablePacket to send reply to General Query.");
		return;
	}

	memset(q->data(), '\0', packetSize);

    Report* report = (Report *) q->data();
    report->type = IGMP_TYPE_REPORT;
    report->checksum = htons(0);
    report->number_of_group_records = htons(numberOfGroups);  // TODO check for fragmentation needs
    
	set<String> srcs;
	GroupRecord* groupRecord = (GroupRecord*) (report + 1);
    for (int i = 1; i <= numberOfGroups; i++) {
        groupRecord->type = this->_states->_interfaceStates.at(interface).at(i)._filter;
        groupRecord->aux_data_len = 0;
        groupRecord->multicast_address = this->_states->_interfaceStates.at(interface).at(i)._groupAddress;

		// fill source list of matching (interface, group)
		srcs = this->_states->_interfaceStates.at(interface).at(i)._sources;
        groupRecord->number_of_sources = htons(srcs.size());
	    set<String>::iterator it = srcs.begin();
		Addresses* addresses = (Addresses*) (groupRecord + 1);
	    for (int i = 0; i < srcs.size(); i++) {
			addresses->array[i] = IPAddress(*it);
		    std::advance(it, 1);
	    }
		groupRecord = (GroupRecord*) (addresses + srcs.size());
    }

    report->checksum = click_in_cksum((unsigned char*) report, messageSize);
    
	q->set_dst_ip_anno(_states->_destination);
    
	output(interface).push(q);
}

void Reporter::handleExpiryGeneral(Timer*, void* data)
{
	TimerState* timerState = (TimerState*) data;
	assert(timerState);  // the cast must be good
	timerState->me->expireGeneral(timerState);
}

void Reporter::handleExpiryFilter(Timer*, void* data)
{
	FilterTimerState* timerState = (FilterTimerState*) data;
	assert(timerState);  // the cast must be good
	timerState->me->expireFilter(timerState);
}

void Reporter::setQRVCounter(int interface, Packet* p)
{
    click_ip* iph = (click_ip*) p->data();
    Query* q = (Query*)(iph + 1);

	int counter = q->resvSQRV & 7;  // QRV is filled in 3 LSB

	// resize on first general query on particular interface
	if (_generalTimerStates.size() <= interface) {
		_generalTimerStates.resize(interface + 1);
	}
	if (_generalTimers.size() <= interface) {
		_generalTimers.resize(interface + 1);
	}

	// initialize timerstate and timer if it was deleted after last report on previous general query
	if (_generalTimerStates.at(interface) == NULL) {
		_generalTimerStates.at(interface) = new TimerState();
		_generalTimerStates.at(interface)->me = this;
	}
	if (_generalTimers.at(interface) == NULL) {
		_generalTimers.at(interface) = new Timer(&handleExpiryGeneral, _generalTimerStates.at(interface));
		_generalTimers.at(interface)->initialize(this);
	}
    // it's possible for a General Query to reset the counter if the client wasn't able to send out all QRV reports by the time of a new request
    _generalTimerStates.at(interface)->counter = counter;
    _generalTimerStates.at(interface)->interface = interface;
}

void Reporter::expireGeneral(TimerState* timerState)
{
    reportCurrentState();
    int counter = --timerState->counter;
	int interface = timerState->interface;

    if (counter > 0) {
        // Schedule timer for next report transmission
		srand(time(NULL) + rand());
		int value = rand() % (_generalMaxRespTime + 1);
   		_generalTimers.at(interface)->schedule_after_sec(value);
    } else {
		// free up memory after last report on general query
		delete _generalTimerStates.at(interface);
		_generalTimerStates.at(interface) = NULL;

		delete _generalTimers.at(interface);
		_generalTimers.at(interface) = NULL;
	}
}

void Reporter::expireFilter(FilterTimerState* timerState)
{
	unsigned int port = timerState->port; 
    unsigned int interface = timerState->interface;
    IPAddress groupAddress = timerState->group;
    FilterMode filter = timerState->filter;
    set<String> sources = timerState->sources;

	reportFilterModeChange(port, interface, groupAddress, filter, sources);

    int counter = --timerState->counter;
    if (counter > 0) {
        // Schedule timer for retransmission
		srand(time(NULL) + rand());
		int value = rand() % (_states->_uri + 1);
   		_filterTimers.at(interface)->schedule_after_sec(value);
    } else {
		// free up memory after last report
		delete _filterTimerStates.at(interface);
		_filterTimerStates.at(interface) = NULL;

		delete _filterTimers.at(interface);
		_filterTimers.at(interface) = NULL;
	}
}

void Reporter::setMaxRespTime(Packet* p)
{
	click_ip* iph = (click_ip*) p->data();
	Query* query = (Query*) (iph + 1);

    if (query->max_resp_code < 128) {
		this->_generalMaxRespTime = query->max_resp_code;
	} else {
		uint8_t exp = (query->max_resp_code & 112) >> 4;
		uint8_t mant = (query->max_resp_code & 15);
		this->_generalMaxRespTime = (mant | 0x10) << (exp + 3);
	}

    this->_generalMaxRespTime = this->_generalMaxRespTime / 10;
}

void Reporter::scheduleGeneralTimer(int interface, Packet* p)
{
    if ((_states->_interfaceStates.size() <= interface) || (_states->_interfaceStates.at(interface).size() == 1)) {
        // the system has no state to report to General Query (we do not report all-hosts multicast group address)
        return;
    }

    // pick a random delay within [0, Max Resp Time]
    srand(time(NULL) + rand());
	int delay = rand() % (_generalMaxRespTime + 1);

    // check for pending response
    if (_generalTimers.size() > interface && _generalTimers.at(interface) != NULL) {
        Timestamp scheduledOld = _generalTimers.at(interface)->expiry_steady();
        Timestamp scheduledNew = Timestamp::now_steady() + Timestamp(delay);
        if (scheduledOld < scheduledNew) {
            // pending response to General Query is scheduled sooner than new delay
            click_chatter("%s's previous response to General Query is scheduled sooner than new delay, leaving as it is.\n", _states->_source.unparse().c_str());
            setQRVCounter(interface, p);  // reset the counter
            return;
        }
    }

    click_chatter("%s is scheduling new response to General Query.\n", _states->_source.unparse().c_str());
    // there's no pending response for previous General Query
    setQRVCounter(interface, p);
    // Schedule timer on General Query reception
    _generalTimers.at(interface)->schedule_after_sec(delay);

    return;
}

void Reporter::push(int interface, Packet *p)
{
	click_ip* iph = (click_ip*) p->data();
	Query* query = (Query*) (iph + 1); 

    setMaxRespTime(p);
	if (query->type == IGMP_TYPE_QUERY) {
		if (query->group_address == IPAddress()) {
			click_chatter("%s recognized general query", _states->_source.unparse().c_str());
            scheduleGeneralTimer(interface, p);
        } else {
			click_chatter("%s recognized group specific query for %s", _states->_source.unparse().c_str(), IPAddress(query->group_address).unparse().c_str());
			reportGroupState(query->group_address);
		}
	}
}

void Reporter::reportFilterModeChange(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, set<String> sources)
{
	int totalSources = 0;
	Vector<InterfaceState>::const_iterator cit = _states->_interfaceStates.at(interface).begin();
	for (; cit != _states->_interfaceStates.at(interface).end(); cit++) {
		if (cit->_groupAddress == groupAddress) {
			totalSources = cit->_sources.size();
			break;
		}
	}

	int headroom = sizeof(click_ether) + sizeof(click_ip);
	int messageSize = sizeof(struct Report) + sizeof(struct GroupRecord) + sizeof(struct Addresses) * totalSources;
	int packetSize = messageSize;

	WritablePacket* q = Packet::make(headroom, 0, packetSize, 0);

	if (!q) {
        click_chatter("ERROR: Reporter was unable to create a new WritablePacket to send a Filter Mode Change Report.");
		return;
	}

	memset(q->data(), '\0', packetSize);

    Report* report = (Report *) q->data();
    report->type = IGMP_TYPE_REPORT;
    report->checksum = htons(0);
    report->number_of_group_records = htons(1);  // TODO check for fragmentation needs

    GroupRecord* groupRecord = (GroupRecord*) (report + 1);
    groupRecord->aux_data_len = 0;
    groupRecord->multicast_address = groupAddress;

	// find source list of matching (interface, group) and fill in grouprecord's type
	set<String> srcs;
	Vector<InterfaceState> iStates = _states->_interfaceStates.at(interface);
	bool isStateRemoved = true;
	for (Vector<InterfaceState>::const_iterator it = iStates.begin(); it != iStates.end(); it++) {
		if (it->_groupAddress == groupAddress) {
			srcs = it->_sources;
			groupRecord->type = it->_filter + 2;  // filter is either MODE_IS_INCLUDE or MODE_IS_EXCLUDE, but we know there was a change
			isStateRemoved = false;
			break;
		}
	}
	if (isStateRemoved) {
		groupRecord->type = CHANGE_TO_INCLUDE_MODE; 
	}
    groupRecord->number_of_sources = htons(srcs.size());

    // Fill in source list
	Addresses* addresses = (Addresses*) (groupRecord + 1);
	set<String>::iterator it = srcs.begin();
	for (int i = 0; i < srcs.size(); i++) {
		addresses->array[i] = IPAddress(*it);
		std::advance(it, 1);
	}

	report->checksum = click_in_cksum((unsigned char*) report, messageSize);

    q->set_dst_ip_anno(_states->_destination);

	output(interface).push(q);
}

void Reporter::saveStates(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, set<String> sources)
{
	REPORT_MODE reportMode = _states->saveSocketState(port, interface, groupAddress, filter, sources);
	_states->saveInterfaceState(port, interface, groupAddress, filter, sources);

	if (reportMode == FILTER_MODE_CHANGE_REPORT) {
        // immediate transmission of the first Filter Mode Change Report 
		reportFilterModeChange(port, interface, groupAddress, filter, sources);

        // resize data structures on first Filter Mode Change Report on this interface
        if (_filterTimerStates.size() <= interface) {
            _filterTimerStates.resize(interface + 1);
        }
        if (_filterTimers.size() <= interface) {
            _filterTimers.resize(interface + 1);
        }

        // initialize timerstate and timer if they are not present anymore
        if (_filterTimerStates.at(interface) == NULL) {
            _filterTimerStates.at(interface) = new FilterTimerState();
            _filterTimerStates.at(interface)->me = this;
        }
        if (_filterTimers.at(interface) == NULL) {
            _filterTimers.at(interface) = new Timer(&handleExpiryFilter, _filterTimerStates.at(interface));
            _filterTimers.at(interface)->initialize(this);
        }
        // in case of transmission of a new Filter Mode Change Report State, the fields need to be reset
        _filterTimerStates.at(interface)->counter = _states->_rrv - 1;
        _filterTimerStates.at(interface)->port = port;
        _filterTimerStates.at(interface)->interface = interface;
        _filterTimerStates.at(interface)->group = groupAddress;
        _filterTimerStates.at(interface)->filter = filter;
        _filterTimerStates.at(interface)->sources = sources;
 
        // schedule timer between (0, [Unsolicited Reporter Interval]) seconds
        srand(time(NULL) + rand());
        int value = rand() % (_states->_uri + 1);
        _filterTimers.at(interface)->schedule_after_sec(value);
	}
	/*
	   else if (reportMode == SOURCE_LIST_CHANGE_REPORT) {
			reportSourceListChange(port, interface, groupAddress, filter, sources);
	   } 
	 */
}

int Reporter::leaveGroup(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
	Reporter* me = (Reporter *) e;

	// default values for arguments
	unsigned int port = 1234;
	unsigned int interface = 0;
	IPAddress groupAddress = IPAddress("225.0.0.1");
	FilterMode filter = MODE_IS_INCLUDE;
	set<String> sources;

	// overwrite given arguments
	if (cp_va_kparse(conf, me, errh,
			"PORT", cpkN, cpUnsigned, &port,
			"INTERFACE", cpkN, cpUnsigned, &interface,
			"GROUP", cpkN, cpIPAddress, &groupAddress,
			cpEnd) < 0)
		return -1;

	if (interface != 0) {
		errh->error("[ERROR IGMPReporter]: invalid INTERFACE value (%u) provided for client with address %s, expected 0", interface, me->_states->_source.unparse().c_str());
		return -1;
	}

	if (groupAddress == IPAddress("224.0.0.1")) {
		errh->error("[ERROR IGMPReporter]: cannot leave group 224.0.0.1!");
		return -1;
	}

	// TODO verify group address is a valid mcast address
	
	me->saveStates(port, interface, groupAddress, filter, sources);
	
	return 0;
}

int Reporter::joinGroup(const String &conf, Element* e, void* thunk, ErrorHandler* errh)
{
	Reporter* me = (Reporter *) e;

	// default values for arguments
	unsigned int port = 1234;
	unsigned int interface = 0;
	IPAddress groupAddress = IPAddress("225.0.0.1");
	String sFilter;
	FilterMode filter = MODE_IS_EXCLUDE;
	Vector<String> vSources;
	set<String> sources;

	// overwrite given arguments
	if (cp_va_kparse(conf, me, errh,
			"PORT", cpkN, cpUnsigned, &port,
			"INTERFACE", cpkN, cpUnsigned, &interface,
			"GROUP", cpkN, cpIPAddress, &groupAddress,
			"FILTER", cpkN, cpString, &sFilter,
			"SRC", cpkN, cpArguments, &vSources,
			cpEnd) < 0)
		return -1;

	if (interface != 0) {
		errh->error("[ERROR IGMPReporter]: invalid INTERFACE value (%u) provided for client with address %s, expected 0", interface, me->_states->_source.unparse().c_str());
		return -1;
	}

	// TODO verify group address is a valid mcast address

	if (sFilter == "INCLUDE") {
		filter = MODE_IS_INCLUDE;
	} else if(sFilter != "EXCLUDE" && sFilter != "") {
		errh->error("[ERROR IGMPReporter]: invalid FILTER mode (%s) provided, expected either EXCLUDE or INCLUDE", sFilter.c_str());
		return -1;
	}

	for (int i = 0; i < vSources.size(); i++) {
		sources.insert(vSources.at(i));
	}

	me->saveStates(port, interface, groupAddress, filter, sources);

	return 0;
}

void Reporter::add_handlers()
{
	add_write_handler("join_group", &joinGroup, (void *) 0);
	add_write_handler("leave_group", &leaveGroup, (void *) 0);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Reporter)
