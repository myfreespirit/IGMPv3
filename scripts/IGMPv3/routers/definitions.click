///===========================================================================///
/// Definitions of the different hosts and related address information.

// The idea is that instead of sending the data to a unicast address, it should be sent to 
// a multicast address and all clients subscribed to this multicast group receive the UDP 
// packet and print this out.

AddressInfo(multicast_client_address 192.168.2.2) 