#ifndef CLICK_QUERIER_HH
#define CLICK_QUERIER_HH
#include <click/element.hh>
#include "infobases/igmprouterstates.hh"

CLICK_DECLS

struct GeneralTimerState;

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
        static void handleGeneralExpiry(Timer*, void* data); 

        GeneralTimerState* _generalTimerState;
        Timer* _generalTimer;
};

struct GeneralTimerState {
    Querier* me;
    int counter;  // all startup queries are sent out when counter reaches 1 
};

CLICK_ENDDECLS
#endif
