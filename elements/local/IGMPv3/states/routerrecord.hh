#ifndef ROUTER_RECORD_HH
#define ROUTER_RECORD_HH

#include "sourcerecord.hh"
#include "../utils/filtermode.hh"

// RFC 3376 page 5
class RouterRecord {
public:
	RouterRecord()
	{
	}

	RouterRecord(FilterMode filter) : _filter(filter) 
   	{
   	}

	// _groupTimer
	FilterMode _filter;
	Vector<SourceRecord> _setA;
	Vector<SourceRecord> _setB;
};

#endif
