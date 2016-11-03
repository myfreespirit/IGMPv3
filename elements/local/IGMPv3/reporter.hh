#ifndef CLICK_REPORTER_HH
#define CLICK_REPORTER_HH
#include <click/element.hh>

CLICK_DECLS

class Reporter: public Element{
public:
	Reporter();
	~Reporter();
	const char *class_name() const	{ return "Reporter"; }
	const char *port_count() const	{ return "0/1"; }
	const char *processing() const	{ return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);

	void push(int, Packet*);
	/**
	 * handler
	 */
	static int joinGroup(const String &conf, Element* e, void* thunk, ErrorHandler* errh);
	Packet* createJoinReport(IPAddress groupAddress);
	void add_handlers();
private:
	IPAddress _source;
	IPAddress _destination;

};


CLICK_ENDDECLS
#endif
