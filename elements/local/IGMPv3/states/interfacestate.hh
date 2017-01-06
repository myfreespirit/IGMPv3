#ifndef INTERFACE_STATE_HH
#define INTERFACE_STATE_HH

#include <click/ipaddress.hh>
#include <click/string.hh>
#include <set>
#include "../utils/filtermode.hh"

/* RFC 3376, page 5
 * InterfaceState records the desired multicast reception state for a particular interface.
 * That state consists of a multicast-address, a filter-mode and a source list.
 * Is derived from the per-socket state.
 */
struct InterfaceState {
    /*
     * Default Constructor
     */
	InterfaceState() : _groupAddress(IPAddress("225.0.0.1")), _filter(MODE_IS_EXCLUDE)
	{
	}

    /* 
     * Parameterized Constructor
     */
	InterfaceState(IPAddress groupAddress, FilterMode filter, std::set<String> sources) :
        _groupAddress(groupAddress), _filter(filter), _sources(sources)
    {
	}

    /*
     *  Public data members
     */
	IPAddress _groupAddress;
	FilterMode _filter;
	std::set<String> _sources;
};


#endif
