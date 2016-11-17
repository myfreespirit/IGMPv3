#ifndef CLICK_REPORTER_HH
#define CLICK_REPORTER_HH

#include <click/element.hh>
#include <set>
#include "igmpclientstates.hh"


CLICK_DECLS

class Reporter: public Element {
public:
	Reporter();
	~Reporter();

	const char *class_name() const	{ return "Reporter"; }
	const char *port_count() const	{ return "0/1"; }
	const char *processing() const	{ return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);

	void push(int, Packet*);
	
	Packet* createJoinReport(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, std::set<String> sources);
	Packet* createLeaveReport(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, std::set<String> sources);

	/**
	 * handlers
	 */
	static int joinGroup(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
	static int leaveGroup(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
	
	void add_handlers();

private:
	bool checkExcludeMode(unsigned int interface, IPAddress groupAddress);
	void saveSocketState(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, std::set<String> sources);
	void saveInterfaceState(unsigned int port, unsigned int interface, IPAddress groupAddress, FilterMode filter, std::set<String> sources);

	std::set<String> _intersect(std::set<String> a, std::set<String> b);
	std::set<String> _union(std::set<String> a, std::set<String> b);
	std::set<String> _difference(std::set<String> a, std::set<String> b);

	void getSourceLists(unsigned int interface, IPAddress groupAddress, std::set<String>& excludeSources, std::set<String>& includeSources);
	void getSourceLists(unsigned int interface, IPAddress groupAddress, unsigned int port, std::set<String>& excludeSources, std::set<String>& includeSources);

	IGMPClientStates* _states;
};


CLICK_ENDDECLS
#endif
