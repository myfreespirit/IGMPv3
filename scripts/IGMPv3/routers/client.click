// Output configuration: 
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1

require(library definitions.click)

elementclass Client {
	$address, $gateway |

	igmp_client_states::IGMPClientStates(SRC $address, DST all_routers_multicast_address);

	ip :: Strip(14)
		-> CheckIPHeader()
		-> rt :: StaticIPLookup(
					$address:ip/32 0,
					$address:ipnet 0,
					224.0.0.0/4 2,  // *
					0.0.0.0/0.0.0.0 $gateway 1)
		-> [1]output;

	// * multicast packets in the range of 224.0.0.0 to 239.255.255.255
	// but that aren't encapped with IP IGMP protocol
	// those are processed by the reporter::Reporter

	rt[2]
		-> MulticastReceiver(CLIENT_STATES igmp_client_states)
		-> [1]output

	rt[1]
		-> DropBroadcasts
		-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
		-> arpq :: ARPQuerier($address)
		-> output;

	ipgw[1]
		-> ICMPError($address, parameterproblem)
		-> output;
	
	ttl[1]
		-> ICMPError($address, timeexceeded)
		-> output; 

	frag[1]
		-> ICMPError($address, unreachable, needfrag)
		-> output;

	// Incoming Packets
	input
		-> HostEtherFilter($address)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)
		-> arp_res :: ARPResponder($address)
		-> output;

	in_cl[1]
		-> [1]arpq;
	
	in_cl[2]
		-> ip_igmp_class::IPClassifier(ip proto 2, -)[1]
		-> ip;

	ip_igmp_class[0]
		-> Strip(14)
		-> reporter::Reporter(CLIENT_STATES igmp_client_states)
        -> IPEncap(PROTO 2, SRC $address, DST all_routers_multicast_address, TTL 1, TOS 0xc0)
		-> EtherEncap(0x0800, $address:eth, $gateway:eth)
		-> output;
}
