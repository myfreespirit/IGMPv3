#ifndef INTERFACE_STATE_HH
#define INTERFACE_STATE_HH

#include <click/ipaddress.hh>
#include <click/string.hh>
#include <set>

// RFC 3376 page 16
enum FilterMode {
	MODE_IS_INCLUDE = 1,
   	MODE_IS_EXCLUDE,
	CHANGE_TO_INCLUDE_MODE,
	CHANGE_TO_EXCLUDE_MODE
};

// RFC 3376 page 5
struct InterfaceState {
	InterfaceState() : _groupAddress(IPAddress("225.1.1.1")), _filter(MODE_IS_EXCLUDE)
	{
	}

	InterfaceState(IPAddress groupAddress, FilterMode filter, std::set<String> sources) {
		_groupAddress = groupAddress;
		_filter = filter;
		_sources = sources;
	}

	IPAddress _groupAddress;
	FilterMode _filter;
	std::set<String> _sources;
};


#endif
