/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
/// !!!!!!! DO NOT CHANGE THIS FILE: Any changes will be removed prior to the project defense  !!!!!!!!
/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 

///================================================================///
/// igpnetwork.click
///
/// This script implements a small IP network inside click. Several
/// compound elements are used to create the different network entities.
///
/// This script is part of the assignment of the 
/// course 'Telecommunicatiesystemen 2016-2017'. The assignment explains
/// in more detail the network architecture.
///
/// Authors: Johan Bergs & Jeremy Van den Eynde
/// Original authors: Bart Braem & Michael Voorhaen
///================================================================///

require(library routers/definitions.click)
require(library routers/server.click);
require(library routers/client.click);
require(library routers/router.click);

// Address configuration
AddressInfo(router_server_network_address 192.168.1.254/24 00:50:BA:85:84:A1);
AddressInfo(multicast_server_address 192.168.1.1/24 00:50:BA:85:84:A2);

AddressInfo(router_client_network1_address 192.168.2.254/24 00:50:BA:85:84:B1);
AddressInfo(client21_address 192.168.2.1/24 00:50:BA:85:84:B2);
AddressInfo(client22_address 192.168.2.2/24 00:50:BA:85:84:B3);

AddressInfo(router_client_network2_address 192.168.3.254/24 00:50:BA:85:84:C1);
AddressInfo(client31_address 192.168.3.1/24 00:50:BA:85:84:C2);
AddressInfo(client32_address 192.168.3.2/24 00:50:BA:85:84:C3);

// Host, router and switch instantiation
multicast_server :: Server(multicast_server_address, router_server_network_address);
client21 :: Client(client21_address, router_client_network1_address);
client22 :: Client(client22_address, router_client_network1_address);
client31 :: Client(client31_address, router_client_network2_address);
client32 :: Client(client32_address, router_client_network2_address);
router :: Router(router_server_network_address, router_client_network1_address, router_client_network2_address);
server_network :: ListenEtherSwitch;
client_network1 :: ListenEtherSwitch;
client_network2 :: ListenEtherSwitch;


// Connect the hosts and routers to the network switches

multicast_server
	-> server_network
	-> multicast_server

multicast_server[1]
	-> Discard; 

client21
	-> client_network1
	-> client21

client21[1]
	-> IPPrint("client21 -- received a packet") 
	-> Discard

client22
	-> [1]client_network1[1]
	-> client22

client22[1]
	-> IPPrint("client22 --received a packet") 
	-> Discard

client31
	-> client_network2
	-> client31

client31[1]
	-> IPPrint("client31 -- received a packet") 
	-> Discard

client32
	-> [1]client_network2[1]
	-> client32

client32[1]
	-> IPPrint("client32 -- received a packet") 
	-> Discard

router
	-> [1]server_network[1]
	-> router

router[1]
	-> [2]client_network1[2]
	-> [1]router

router[2]
	-> [2]client_network2[2]
	-> [2]router

router[3]
	-> IPPrint("router -- received a packet")
	-> Discard

// In every network, create pcap dump files
server_network[2]
	-> ToDump("server_network.pcap");

client_network1[3]
	-> ToDump("client_network1.pcap");

client_network2[3]
	-> ToDump("client_network2.pcap");

// Generate traffic for the multicast server.
RatedSource("data", 1, -1, true)
	-> DynamicUDPIPEncap(multicast_server_address:ip, 1234, multicast_client_address:ip, 1234) 
	-> EtherEncap(0x0800, multicast_server_address:eth, multicast_server_address:eth) /// The MAC addresses here should be from the multicast_server to get past the HostEtherFilter. This way we can reuse the input from the network for the applications.
	-> IPPrint("multicast_server -- transmitted a UDP packet")
	-> [0]multicast_server