#ifndef GROUP_RECORD_HH
#define GROUP_RECORD_HH

#include "sourcerecord.hh"
#include "../utils/filtermode.hh"

// RFC 3376 page 5
class GroupRecord {
public:
	GroupRecord()
	{
	}

	GroupRecord(FilterMode filter) : _filter(filter) 
   	{
   	}

	// _groupTimer
	FilterMode _filter;
	Vector<SourceRecord> _includeSources;
	Vector<SourceRecord> _excludeSources;
};

#endif
