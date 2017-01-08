#ifndef CLICK_REPORTER_HH
#define CLICK_REPORTER_HH

#include <click/timer.hh>
#include <click/element.hh>
#include <set>
#include "infobases/igmpclientstates.hh"

using std::set;

CLICK_DECLS

struct TimerState;
struct FilterTimerState; 

class Reporter: public Element {
public:
	Reporter();
	~Reporter();

	const char *class_name() const	{ return "Reporter"; }
	const char *port_count() const	{ return "1/1"; }
	const char *processing() const	{ return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);

	void push(int, Packet*);

	/**
	 * handlers
	 */
	static int joinGroup(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
	static int leaveGroup(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
	void add_handlers();

private:
	void saveStates(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, set<String> sources);
	void reportCurrentState();
	void reportGroupState(IPAddress group);
	void reportFilterModeChange(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, set<String> sources);
	// void reportSourceListChange(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, set<String> sources);
	void setMaxRespTime(Packet* p);
    void setQRVCounter(int interface, Packet* p);

	static void handleExpiryGeneral(Timer*, void* data);
	static void handleExpiryFilter(Timer*, void* data);
    void expireGeneral(TimerState* timerState);
    void expireFilter(FilterTimerState* timerState);

	// DATA MEMBERS
	IGMPClientStates* _states;  // infobase

    // Timers used to respond to General Queries
	Vector<TimerState*> _generalTimerStates;
	Vector<Timer*> _generalTimers;

    // TODO: Timers used to respond to Group-Specific Queries
    
    // Timers used to transmit Filter-Mode-Change Reports
	Vector<FilterTimerState*> _filterTimerStates;
	Vector<Timer*> _filterTimers;

	int _generalMaxRespTime;
};

struct TimerState {
	Reporter* me;
	int counter;

	int interface;
};

struct FilterTimerState {
    Reporter* me;
    int counter;  // amount of retransmissions left

    unsigned int port;
    unsigned int interface;
    IPAddress group;
    FilterMode filter;
    set<String> sources;
};

CLICK_ENDDECLS
#endif
