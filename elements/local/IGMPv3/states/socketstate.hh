#ifndef SOCKET_STATE_HH
#define SOCKET_STATE_HH

#include "interfacestate.hh"

/*  RFC 3376, page 5
 *  SocketState records the desired multicast reception state for a particular socket.
 *  That state consists of interface and InterfaceState,
 */
class SocketState: public InterfaceState {
public:
    /*
     * Default Constructor
     */
	SocketState() : InterfaceState(), _interface(0)
	{
	}

    /*
     * Parameterized Constructor
     */
	SocketState(unsigned int interface, IPAddress groupAddress, FilterMode filter, std::set<String> sources)
	: InterfaceState(groupAddress, filter, sources), _interface(interface)
   	{
   	}

    /*
     *  Public Data Members
     */
	unsigned int _interface;
};

#endif
