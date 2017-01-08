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

	FilterMode _filter;

	// RFC 3376 page 30
	Vector<SourceRecord> _forwardingSet;  // source timers > 0 && when the set is empty, record is removed if INCLUDE
	Vector<SourceRecord> _blockingSet;    // source timers == 0 && only for EXCLUDE router-filter-mode records
};

#endif
