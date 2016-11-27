#! /bin/bash

# display initial state for client21
echo "read client21/igmp_client_states.sockets"
echo "read client21/igmp_client_states.interfaces"
echo "read router/igmp_router_states.records"

sleep 5

# client21 is interested in group 225.0.0.1 but not from source 192.168.1.1
# FILTER_MODE iS EXCLUDE by default
echo "write client21/reporter.join_group GROUP 225.0.0.1, SRC 192.168.1.1"
echo "read client21/igmp_client_states.sockets"
echo "read client21/igmp_client_states.interfaces"
echo "read router/igmp_router_states.records"

sleep 5

# client21 decides to leave the group as there's no traffic coming in
echo "write client21/reporter.leave_group GROUP 225.0.0.1"
echo "read client21/igmp_client_states.sockets"
echo "read client21/igmp_client_states.interfaces"
echo "read router/igmp_router_states.records"

sleep 5

# client22 is interested in group 225.0.0.1, but not from source 1.1.1.1
echo "write client22/reporter.join_group GROUP 225.0.0.1, SRC 1.1.1.1"
echo "read client22/igmp_client_states.sockets"
echo "read client22/igmp_client_states.interfaces"
echo "read router/igmp_router_states.records"

# client32 is interested in group 225.0.0.1 from source 192.168.1.1 at the same time
echo "write client32/reporter.join_group GROUP 225.0.0.1, FILTER INCLUDE, SRC 192.168.1.1"
echo "read client32/igmp_client_states.sockets"
echo "read client32/igmp_client_states.interfaces"
echo "read router/igmp_router_states.records"

sleep 5

# we need to send a general query to notice that client32 would like to receive the multicast traffic
# since his filter mode didn't change
echo "write router/querier.general_query"

sleep 5

# client32 is no longer interested in source 192.168.1.1 in group 225.0.0.1
echo "write client32/reporter.join_group GROUP 225.0.0.1, FILTER EXCLUDE, SRC 192.168.1.1"
echo "read client32/igmp_client_states.sockets"
echo "read client32/igmp_client_states.interfaces"
echo "read router/igmp_router_states.records"

echo "quit"
