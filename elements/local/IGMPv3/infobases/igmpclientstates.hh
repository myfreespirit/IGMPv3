#ifndef CLICK_IGMPCLIENTSTATES_HH
#define CLICK_IGMPCLIENTSTATES_HH

#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/vector.hh>
#include <set>

#include "../states/interfacestate.hh"
#include "../states/socketstate.hh"
#include "../utils/filtermode.hh"

using std::set;

CLICK_DECLS

class IGMPClientStates : public Element {
public:
	IGMPClientStates();
	~IGMPClientStates();

	const char *class_name() const  { return "IGMPClientStates"; }
	const char *port_count() const  { return "0/0"; }
	const char *processing() const  { return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);
		
	void push(int, Packet*);

	bool checkExcludeMode(unsigned int interface, IPAddress groupAddress);
	void getSourceLists(unsigned int interface, IPAddress groupAddress, set<String>& excludeSources, set<String>& includeSources);
	REPORT_MODE saveSocketState(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, set<String> sources);
	void saveInterfaceState(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, set<String> sources);

	bool isMulticastAllowed(unsigned int interface, IPAddress group, IPAddress source);

	void add_handlers();
	/**
	 * read handlers
	 */
	static String socketStates(Element* e, void* thunk);
	static String interfaceStates(Element* e, void* thunk);
    static String getRRV(Element* e, void* thunk);
    static String getURI(Element* e, void* thunk);

	/**
	 * write handlers
	 */
    static int setRRV(const String& conf, Element* e, void* thunk, ErrorHandler* errh);
    static int setURI(const String& conf, Element* e, void* thunk, ErrorHandler* errh);

	/**
	 * data members
	 */
	IPAddress _source;
	IPAddress _destination;
	HashTable<int, Vector<SocketState> > _socketStates;
	Vector<Vector<InterfaceState> >_interfaceStates;

    unsigned int _rrv;  // Reporter's Robustness Variable 
    unsigned int _uri;  // Unsolicited Report Interval (seconds)
};


CLICK_ENDDECLS
#endif
