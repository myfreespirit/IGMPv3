#!/bin/bash

echo "write router/igmp_router_states.qrv 1"   # assume no packet loss
echo "read router/igmp_router_states.gmi"      # prints the Group Membership Interval value

sleep 2

echo "write client21/reporter.join_group"
echo "write client32/reporter.join_group"

sleep 2

for i in {1..250}
do
   echo "read router/igmp_router_states.records"
   sleep 1
done
