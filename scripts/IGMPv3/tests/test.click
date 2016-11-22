igmp_router_states::IGMPRouterStates(SRC 192.168.2.1, DST 224.0.0.1);

querier::Querier(ROUTER_STATES igmp_router_states)[0]
	-> Discard;

querier[1]
	 -> EtherEncap(0x0800, 00:50:BA:85:84:B2, 00:50:BA:85:84:A1)
	 -> ToDump("test.dump")
	 -> Discard;

