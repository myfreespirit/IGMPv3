#! /bin/bash

# print initial state output
echo "read igmp_client_states.sockets"
echo "read igmp_client_states.interfaces"

sleep 1

# Join / empty source list 
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.1.1.1, FILTER EXCLUDE"

# Join on different socket port
echo "write reporter.join_group PORT 2222, INTERFACE 0, GROUP 225.1.1.1, FILTER EXCLUDE, SRC 1.1.1.1"

# Join on different interface 
#echo "write reporter.join_group PORT 1111, INTERFACE 1, GROUP 225.1.1.1, FILTER EXCLUDE, SRC 2.2.2.2"

# INCLUDE multiple sources
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.2.2.2, FILTER INCLUDE, SRC 8.8.8.8, SRC 9.9.9.9"
# modify INCLUDE sources
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.2.2.2, FILTER INCLUDE, SRC 1.1.1.1, SRC 2.2.2.2, SRC 3.3.3.3"

# EXCLUDE multiple sources
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.3.3.3, FILTER EXCLUDE, SRC 7.7.7.7, SRC 8.8.8.8, SRC 9.9.9.9"
# modify EXCLUDE sources
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.3.3.3, FILTER EXCLUDE, SRC 2.2.2.2, SRC 3.3.3.3"

# test union of INCLUDE source lists by constructing interface state
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.4.4.4, FILTER INCLUDE, SRC 1.1.1.1"
echo "write reporter.join_group PORT 2222, INTERFACE 0, GROUP 225.4.4.4, FILTER INCLUDE, SRC 2.2.2.2"
echo "write reporter.join_group PORT 3333, INTERFACE 0, GROUP 225.4.4.4, FILTER INCLUDE, SRC 3.3.3.3"

# test intersection of EXCLUDE source lists by constructing interface state
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.5.5.5, FILTER EXCLUDE, SRC 1.1.1.1, SRC 2.2.2.2, SRC 3.3.3.3, SRC 4.4.4.4"
echo "write reporter.join_group PORT 2222, INTERFACE 0, GROUP 225.5.5.5, FILTER EXCLUDE, SRC 1.1.1.1, SRC 2.2.2.2, SRC 3.3.3.3"

# test difference between intersection (EXCLUDE) and union (INCLUDE) source lists by constructing interface state
echo "write reporter.join_group PORT 1111, INTERFACE 0, GROUP 225.6.6.6, FILTER INCLUDE, SRC 1.1.1.1, SRC 2.2.2.2"
echo "write reporter.join_group PORT 2222, INTERFACE 0, GROUP 225.6.6.6, FILTER EXCLUDE, SRC 1.1.1.1, SRC 2.2.2.2, SRC 3.3.3.3, SRC 4.4.4.4"

# Ignore leaves on non members
echo "write reporter.join_group GROUP 225.7.7.7, FILTER INCLUDE, SRC 1.1.1.1"
echo "write reporter.leave_group PORT 3333, GROUP 225.7.7.7"
#echo "write reporter.leave_group INTERFACE 1, GROUP 225.7.7.7"

# From EXCLUDE back to INCLUDE
echo "write reporter.join_group PORT 1111, GROUP 225.8.8.8, FILTER INCLUDE, SRC 1.1.1.1"
echo "write reporter.join_group PORT 2222, GROUP 225.8.8.8, FILTER EXCLUDE, SRC 2.2.2.2, SRC 3.3.3.3, SRC 4.4.4.4"
echo "write reporter.leave_group PORT 2222, GROUP 225.8.8.8"

# Back to old interface state, with extra SRC address (1.1.1.1)
echo "write reporter.join_group PORT 1111, GROUP 225.9.9.9, FILTER INCLUDE, SRC 4.4.4.4"
echo "write reporter.join_group PORT 2222, GROUP 225.9.9.9, FILTER EXCLUDE, SRC 1.1.1.1, SRC 2.2.2.2, SRC 3.3.3.3, SRC 4.4.4.4"
echo "write reporter.join_group PORT 3333, GROUP 225.9.9.9, FILTER EXCLUDE, SRC 2.2.2.2, SRC 3.3.3.3, SRC 4.4.4.4"
echo "write reporter.leave_group PORT 3333, GROUP 225.9.9.9"

# Join group and immediately leave it
echo "write reporter.join_group GROUP 225.10.10.10"
echo "write reporter.leave_group GROUP 225.10.10.10"

sleep 1

# print modified state output
echo "read igmp_client_states.sockets"
echo "read igmp_client_states.interfaces"

sleep 1

echo "quit"
