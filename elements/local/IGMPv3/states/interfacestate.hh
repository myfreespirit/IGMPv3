#ifndef INTERFACE_STATE_HH
#define INTERFACE_STATE_HH

#include <click/ipaddress.hh>
#include <click/string.hh>
#include <set>

enum FilterMode{
	INCLUDE, EXCLUDE
};

struct InterfaceState{
	IPAddress _groupAddress;
	FilterMode _filter;
	std::set<String> _sources;
};


#endif
