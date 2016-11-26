#ifndef CLICK_IGMPROUTERSTATES_HH
#define CLICK_IGMPROUTERSTATES_HH

#include <click/element.hh>
#include <click/vector.hh>
#include <click/hashtable.hh>
#include "states/routerrecord.hh"

CLICK_DECLS

class IGMPRouterStates : public Element {
public:
	IGMPRouterStates();
	~IGMPRouterStates();

	const char *class_name() const  { return "IGMPRouterStates"; }
	const char *port_count() const  { return "0/0"; }
	const char *processing() const  { return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);

	void push(int, Packet*);

	void updateRecords(unsigned int interface, IPAddress groupAddress, unsigned int filter, Vector<IPAddress> sources);

	/**
	 * handlers
	 */
	static String recordStates(Element* e, void* thunk);
	void add_handlers();

	/**
	 * data members
	 */
	IPAddress _source;
	IPAddress _destination;
	Vector<HashTable<IPAddress, RouterRecord> > _records;  // per interface, per group

private:
	// collects all source addresses either from _forwardingSet or _blockingSet depening on given filter for a router record with given interface and groupAddress
	Vector<IPAddress> getSourceAddresses(unsigned int interface, IPAddress groupAddress, FilterMode filter);
	Vector<SourceRecord> transformToSourceRecords(Vector<IPAddress> a);
};


CLICK_ENDDECLS
#endif
