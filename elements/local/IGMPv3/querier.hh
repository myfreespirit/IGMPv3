#ifndef CLICK_QUERIER_HH
#define CLICK_QUERIER_HH
#include <click/element.hh>
#include "infobases/igmprouterstates.hh"

CLICK_DECLS

struct GeneralTimerState;
struct GroupSpecificTimerState;

class Querier : public Element {
	public:
		Querier();
		~Querier();
		
		const char *class_name() const	{ return "Querier"; }
		const char *port_count() const	{ return "3/3"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		
		void push(int, Packet *);
		void sendQuery(unsigned int interface, IPAddress group);

		static int generalQueryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
		static int groupQueryHandler(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
		void add_handlers();

		IGMPRouterStates* _states;

    private:
        void expireGeneral(GeneralTimerState* timerState);
        void expireGroup(GroupSpecificTimerState* timerState);
        static void handleGeneralExpiry(Timer*, void* data); 
        static void handleGroupExpiry(Timer*, void* data); 
        void scheduleGroupTimer(int interface, IPAddress group);

        GeneralTimerState* _generalTimerState;
        Timer* _generalTimer;
        // per interface, per group
        Vector<HashTable<IPAddress, Timer*> > _groupTimers;
        Vector<HashTable<IPAddress, GroupSpecificTimerState*> > _groupTimerStates;
};

struct GeneralTimerState {
    Querier* me;
    int counter;  // all startup queries are sent out when counter reaches 1 
};

struct GroupSpecificTimerState {
    Querier* me;

    int counter;  // amount of transmissions remaining
    int delay;  // timer delay in seconds

    int interface;
    IPAddress group;
};

CLICK_ENDDECLS
#endif
