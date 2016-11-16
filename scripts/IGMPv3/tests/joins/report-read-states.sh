#! /bin/bash

# print initial state output
echo "read igmp_client_states.sockets"
echo "read igmp_client_states.interfaces"

sleep 1

# Join / empty source list 
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.1.1.1, FILTER EXCLUDE"

# INCLUDE multiple sources, tests union
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.2.2.2, FILTER INCLUDE, SRC 3.3.3.3"
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.2.2.2, FILTER INCLUDE, SRC 2.2.2.2"
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.2.2.2, FILTER INCLUDE, SRC 1.1.1.1"

# EXCLUDE multiple sources, tests intersection
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.3.3.3, FILTER EXCLUDE, SRC 1.1.1.1, SRC 2.2.2.2, SRC 3.3.3.3"
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.3.3.3, FILTER EXCLUDE, SRC 2.2.2.2, SRC 3.3.3.3"

# different socket, tests difference over all sockets
echo "write reporter.join_group PORT 2222, INTERFACE 0, GROUP 225.4.4.4, FILTER INCLUDE, SRC 3.3.3.3"
# different socket + INCLUDE mode, tests difference within socket and whether the state keeps EXCLUDE filter mode
echo "write reporter.join_group PORT 3333, INTERFACE 0, GROUP 225.4.4.4, FILTER EXCLUDE, SRC 2.2.2.2, SRC 3.3.3.3, SRC 4.4.4.4"
echo "write reporter.join_group PORT 3333, INTERFACE 0, GROUP 225.4.4.4, FILTER INCLUDE, SRC 4.4.4.4, SRC 5.5.5.5"

# Join group and immediately leave it
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.6.6.6, FILTER EXCLUDE, SRC 1.1.1.1"
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.6.6.6, FILTER INCLUDE"

sleep 1

# print modified state output
echo "read igmp_client_states.sockets"
echo "read igmp_client_states.interfaces"

sleep 1

echo "quit"
