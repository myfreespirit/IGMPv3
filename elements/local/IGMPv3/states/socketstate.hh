#ifndef SOCKET_STATE_HH
#define SOCKET_STATE_HH

#include "interfacestate.hh"

// RFC 3376 page 5
class SocketState: public InterfaceState {
public:
	SocketState() : InterfaceState(), _interface(0)
	{
	}

	SocketState(unsigned int interface, IPAddress groupAddress, FilterMode filter, std::set<String> sources)
	: InterfaceState(groupAddress, filter, sources), _interface(interface)
   	{
   	}

	unsigned int _interface;
};

#endif
