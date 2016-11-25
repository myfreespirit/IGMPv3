#ifndef ROUTER_RECORD_HH
#define ROUTER_RECORD_HH

#include "sourcerecord.hh"
#include "../utils/filtermode.hh"

// RFC 3376 page 26 
class RouterRecord {
public:
	RouterRecord() : _filter(MODE_IS_INCLUDE)
	{
	}

	RouterRecord(FilterMode filter) : _filter(filter) 
   	{
   	}

	// _groupTimer  // to transition from EXCLUDE to INCLUDE router-filter-mode
	FilterMode _filter;

	// RFC 3376 page 30
	Vector<SourceRecord> _forwardingSet;  // grouptimers > 0 && when the set is empty, record is removed if INCLUDE
	Vector<SourceRecord> _blockingSet;    // grouptimers == 0 && only for EXCLUDE router-filter-mode records
};

#endif
